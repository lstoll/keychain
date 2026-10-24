//go:build darwin

package keychain

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"io"
	"runtime"

	"lds.li/keychain/internal/corefoundation"
	"lds.li/keychain/internal/security"
)

// SecureEnclaveAlgorithm selects a hardware-backed signing algorithm.
type SecureEnclaveAlgorithm int

const (
	// SecureEnclaveP256 is ECDSA over NIST P-256. It is the default.
	SecureEnclaveP256 SecureEnclaveAlgorithm = iota
	// SecureEnclaveMLDSA65 is ML-DSA-65. It requires Go 1.27 and OS support.
	SecureEnclaveMLDSA65
	// SecureEnclaveMLDSA87 is ML-DSA-87. It requires Go 1.27 and OS support.
	SecureEnclaveMLDSA87
)

func (a SecureEnclaveAlgorithm) String() string {
	switch a {
	case SecureEnclaveP256:
		return "P-256"
	case SecureEnclaveMLDSA65:
		return "ML-DSA-65"
	case SecureEnclaveMLDSA87:
		return "ML-DSA-87"
	}
	return fmt.Sprintf("SecureEnclaveAlgorithm(%d)", int(a))
}

// ErrUnsupportedAlgorithm means the requested algorithm is unavailable in this
// build, OS, or hardware. Authentication and other operational failures are distinct.
var ErrUnsupportedAlgorithm = errors.New("unsupported Secure Enclave algorithm")

// SecureEnclaveKey is a device-bound signing key. The private key never
// leaves the Secure Enclave. Keys are not stored in either keychain and do not
// require keychain access-group entitlements. The zero value is not usable.
//
// Persistence uses the private Security.framework attribute kSecAttrTokenOID
// ("toid"), which is not a supported public API and may change across macOS releases.
type SecureEnclaveKey struct {
	sec       *security.Framework
	key       security.Key
	pub       crypto.PublicKey
	algorithm SecureEnclaveAlgorithm
	data      []byte
}

// SecureEnclaveKeyOptions configures a new key's access rules.
// Security.framework validates flag combinations and platform availability.
type SecureEnclaveKeyOptions struct {
	// Algorithm defaults to P-256. ML-DSA requires the Go 1.27 stdlib bridge and
	// runtime support in Security.framework and the Secure Enclave.
	Algorithm SecureEnclaveAlgorithm
	// AllowFallback permits P-256 when the requested ML-DSA algorithm is unavailable.
	// Check the returned key's Algorithm before choosing message/digest signing.
	AllowFallback bool
	// AccessControl defaults (when nil) to WhenUnlockedThisDeviceOnly with no
	// presence requirement. If provided, a zero Protection also defaults to
	// WhenUnlockedThisDeviceOnly. PrivateKeyUsage is always added automatically.
	// Rules are embedded in the opaque blob and cannot be changed when loading it.
	AccessControl *AccessControl
	// AuthContext supplies an LAContext for authentication.
	AuthContext *AuthContext
}

// SecureEnclaveLoadOptions configures authentication when loading a key.
type SecureEnclaveLoadOptions struct {
	// AuthContext supplies an LAContext to reuse authentication. If nil,
	// Security.framework authenticates as needed.
	AuthContext *AuthContext
}

var _ crypto.Signer = (*SecureEnclaveKey)(nil)

// CreateSecureEnclaveKey generates a key without creating a keychain item.
// With zero options, the key can be used while the device is unlocked without
// a user-presence prompt. Save DataRepresentation to load the key in another process.
// Secure Enclave hardware and a logged-in user session are required.
func CreateSecureEnclaveKey(options SecureEnclaveKeyOptions) (*SecureEnclaveKey, error) {
	return createSecureEnclaveWithFallback(options, func(algorithm SecureEnclaveAlgorithm) (*SecureEnclaveKey, error) {
		options.Algorithm = algorithm
		return createSecureEnclaveKey(options)
	})
}

func createSecureEnclaveWithFallback(options SecureEnclaveKeyOptions, create func(SecureEnclaveAlgorithm) (*SecureEnclaveKey, error)) (*SecureEnclaveKey, error) {
	switch options.Algorithm {
	case SecureEnclaveP256, SecureEnclaveMLDSA65, SecureEnclaveMLDSA87:
	default:
		return nil, fmt.Errorf("unknown Secure Enclave algorithm %v", options.Algorithm)
	}
	key, err := create(options.Algorithm)
	if err != nil && options.AllowFallback && options.Algorithm != SecureEnclaveP256 && errors.Is(err, ErrUnsupportedAlgorithm) {
		return create(SecureEnclaveP256)
	}
	return key, err
}

func secureEnclaveAccessControl(requested *AccessControl) AccessControl {
	ac := AccessControl{}
	if requested != nil {
		ac = *requested
	}
	if ac.Protection == AccessibleUnspecified {
		ac.Protection = AccessibleWhenUnlockedThisDeviceOnly
	}
	ac.Flags |= 1 << 30 // kSecAccessControlPrivateKeyUsage
	return ac
}

func createSecureEnclaveKey(options SecureEnclaveKeyOptions) (*SecureEnclaveKey, error) {
	cf, err := corefoundation.Get()
	if err != nil {
		return nil, err
	}
	sec, err := security.Get()
	if err != nil {
		return nil, err
	}
	defer runtime.KeepAlive(options.AuthContext)
	ac := secureEnclaveAccessControl(options.AccessControl)
	access, err := createAccessControl(sec, ac)
	if err != nil {
		return nil, fmt.Errorf("creating Secure Enclave access control: %w", err)
	}
	defer cf.Release(corefoundation.TypeRef(access))
	private, err := cf.MapToCFDictionary(map[corefoundation.TypeRef]corefoundation.TypeRef{
		corefoundation.TypeRef(sec.AttrIsPermanent):   corefoundation.TypeRef(cf.BooleanFalse),
		corefoundation.TypeRef(sec.AttrAccessControl): corefoundation.TypeRef(access),
	})
	if err != nil {
		return nil, err
	}
	defer cf.Release(corefoundation.TypeRef(private))
	var keyType corefoundation.StringRef
	var sizeRef corefoundation.TypeRef
	switch options.Algorithm {
	case SecureEnclaveP256:
		keyType = sec.AttrKeyTypeECSECPrimeRandom
		sizeRef = corefoundation.TypeRef(cf.NumberFromInt(256))
		if sizeRef == 0 {
			return nil, fmt.Errorf("creating key size number")
		}
		defer cf.Release(sizeRef)
	case SecureEnclaveMLDSA65, SecureEnclaveMLDSA87:
		parameterSet := 65
		if options.Algorithm == SecureEnclaveMLDSA87 {
			parameterSet = 87
		}
		if !stdlibMLDSAAvailable || !sec.SupportsMLDSA(parameterSet) {
			return nil, fmt.Errorf("%w: %v requires Go 1.27 and runtime support", ErrUnsupportedAlgorithm, options.Algorithm)
		}
		keyType = sec.AttrKeyTypeMLDSA
		sizeRef = corefoundation.TypeRef(sec.AttrKeySizeMLDSA65)
		if parameterSet == 87 {
			sizeRef = corefoundation.TypeRef(sec.AttrKeySizeMLDSA87)
		}
	}
	parameters := map[corefoundation.TypeRef]corefoundation.TypeRef{
		corefoundation.TypeRef(sec.AttrKeyType):       corefoundation.TypeRef(keyType),
		corefoundation.TypeRef(sec.AttrKeySizeInBits): sizeRef,
		corefoundation.TypeRef(sec.AttrTokenID):       corefoundation.TypeRef(sec.AttrTokenIDSecureEnclave),
		corefoundation.TypeRef(sec.PrivateKeyAttrs):   corefoundation.TypeRef(private),
	}
	if err := secureEnclaveAuthContext(parameters, sec, options.AuthContext); err != nil {
		return nil, err
	}
	attrs, err := cf.MapToCFDictionary(parameters)
	if err != nil {
		return nil, err
	}
	defer cf.Release(corefoundation.TypeRef(attrs))
	key, err := sec.CreateRandomKey(attrs)
	if err != nil {
		var nativeError *security.NativeError
		if options.Algorithm != SecureEnclaveP256 && errors.As(err, &nativeError) && nativeError.Domain == "NSOSStatusErrorDomain" && nativeError.Code == int64(security.ErrSecUnimplemented) {
			return nil, fmt.Errorf("%w: %w", ErrUnsupportedAlgorithm, normalizeNativeError(err))
		}
		return nil, fmt.Errorf("creating Secure Enclave key: %w", normalizeNativeError(err))
	}
	if options.Algorithm != SecureEnclaveP256 && !key.IsAlgorithmSupported(sec.KeyAlgorithmMLDSASignatureMessage) {
		return nil, fmt.Errorf("%w: key does not support ML-DSA message signing", ErrUnsupportedAlgorithm)
	}
	return newSecureEnclaveKey(cf, sec, key)
}

// LoadSecureEnclaveKey opens a key from its opaque DataRepresentation on the
// originating device and user account. It does not create a keychain item.
// Leave options.AuthContext nil to let Security.framework authenticate
// as needed, or provide one to reuse authentication. The original
// access rules remain in effect.
func LoadSecureEnclaveKey(data []byte, options SecureEnclaveLoadOptions) (*SecureEnclaveKey, error) {
	defer runtime.KeepAlive(options.AuthContext)
	if len(data) == 0 {
		return nil, fmt.Errorf("empty Secure Enclave key representation")
	}
	cf, err := corefoundation.Get()
	if err != nil {
		return nil, err
	}
	sec, err := security.Get()
	if err != nil {
		return nil, err
	}
	oid := cf.StringToCFString("toid")
	defer cf.Release(corefoundation.TypeRef(oid))
	blob := cf.BytesToCFData(data)
	if blob == 0 {
		return nil, fmt.Errorf("creating key representation data")
	}
	defer cf.Release(corefoundation.TypeRef(blob))
	parameters := map[corefoundation.TypeRef]corefoundation.TypeRef{
		corefoundation.TypeRef(sec.AttrTokenID): corefoundation.TypeRef(sec.AttrTokenIDSecureEnclave),
		corefoundation.TypeRef(oid):             corefoundation.TypeRef(blob),
	}
	if err := secureEnclaveAuthContext(parameters, sec, options.AuthContext); err != nil {
		return nil, err
	}
	attrs, err := cf.MapToCFDictionary(parameters)
	if err != nil {
		return nil, err
	}
	defer cf.Release(corefoundation.TypeRef(attrs))
	// The token path uses the object ID, not the keyData argument.
	key, err := sec.CreateKeyWithData(0, attrs)
	if err != nil {
		return nil, fmt.Errorf("loading Secure Enclave key: %w", normalizeNativeError(err))
	}
	return newSecureEnclaveKey(cf, sec, key)
}

func newSecureEnclaveKey(cf *corefoundation.Framework, sec *security.Framework, nativeKey security.Key) (*SecureEnclaveKey, error) {
	attrs, err := nativeKey.CopyAttributes()
	if err != nil {
		return nil, normalizeNativeError(err)
	}
	defer cf.Release(corefoundation.TypeRef(attrs))
	token, ok := cf.GetDictionaryString(attrs, sec.AttrTokenID)
	if !ok || token != cf.CFStringToString(sec.AttrTokenIDSecureEnclave) {
		return nil, fmt.Errorf("key is not a Secure Enclave key")
	}
	oid := cf.StringToCFString("toid")
	defer cf.Release(corefoundation.TypeRef(oid))
	data, ok := cf.GetDictionaryData(attrs, oid)
	if !ok || len(data) == 0 {
		return nil, fmt.Errorf("no opaque representation for Secure Enclave key")
	}
	publicKey, err := nativeKey.CopyPublicKey()
	if err != nil {
		return nil, normalizeNativeError(err)
	}
	pubData, err := publicKey.ExternalRepresentation()
	if err != nil {
		return nil, normalizeNativeError(err)
	}
	keyType, ok := cf.GetDictionaryString(attrs, sec.AttrKeyType)
	if !ok {
		return nil, fmt.Errorf("no key type for Secure Enclave key")
	}
	var pub crypto.PublicKey
	var algorithm SecureEnclaveAlgorithm
	// kSecAttrKeyTypeMLDSA is an optional private symbol, absent on older OSes.
	isMLDSA := sec.AttrKeyTypeMLDSA != 0 && keyType == cf.CFStringToString(sec.AttrKeyTypeMLDSA)
	switch {
	case keyType == cf.CFStringToString(sec.AttrKeyTypeECSECPrimeRandom):
		pub, err = ecdsa.ParseUncompressedPublicKey(elliptic.P256(), pubData)
	case isMLDSA:
		size, ok := cf.GetDictionaryInt(attrs, sec.AttrKeySizeInBits)
		if !ok {
			if text, found := cf.GetDictionaryString(attrs, sec.AttrKeySizeInBits); found {
				switch text {
				case "65":
					size = 65
					ok = true
				case "87":
					size = 87
					ok = true
				}
			}
		}
		if !ok {
			return nil, fmt.Errorf("no parameter set for Secure Enclave ML-DSA key")
		}
		switch size {
		case 65:
			algorithm = SecureEnclaveMLDSA65
		case 87:
			algorithm = SecureEnclaveMLDSA87
		default:
			return nil, fmt.Errorf("%w: ML-DSA parameter set %d", ErrUnsupportedAlgorithm, size)
		}
		pub, err = parseMLDSAPublicKey(algorithm, pubData)
	default:
		return nil, fmt.Errorf("%w: native key type %q", ErrUnsupportedAlgorithm, keyType)
	}
	if err != nil {
		return nil, fmt.Errorf("parsing Secure Enclave public key: %w", err)
	}
	key := &SecureEnclaveKey{sec: sec, key: nativeKey, pub: pub, algorithm: algorithm, data: data}
	return key, nil
}

// DataRepresentation returns a copy of the opaque blob needed to reload this
// key. It contains no plaintext private key, but should be protected against
// copying: another process with access to it may use the key on this device.
// Deleting the blob does not revoke other copies.
func (k *SecureEnclaveKey) DataRepresentation() []byte {
	if k == nil {
		return nil
	}
	return bytes.Clone(k.data)
}

// Public returns an ECDSA P-256 or immutable stdlib ML-DSA public key.
func (k *SecureEnclaveKey) Public() crypto.PublicKey {
	if k == nil || k.pub == nil {
		return nil
	}
	if pub, ok := k.pub.(*ecdsa.PublicKey); ok {
		// Return a copy, so callers cannot modify the key's own value.
		if b, err := pub.Bytes(); err == nil {
			if c, err := ecdsa.ParseUncompressedPublicKey(pub.Curve, b); err == nil {
				return c
			}
		}
		return nil
	}
	return k.pub
}

// Sign signs a SHA-256, SHA-384, or SHA-512 digest with P-256 and returns an
// ASN.1 DER ECDSA signature. Options must name the hash and the digest must
// have the corresponding length.
//
// ML-DSA instead takes the original message and nil or zero-hash options.
// mldsa.Options may supply a context of up to 255 bytes. Precomputed digests
// and external mu are rejected; the native API computes mu internally.
//
// Security.framework supplies randomness; the io.Reader argument is ignored.
func (k *SecureEnclaveKey) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if k == nil || k.pub == nil {
		return nil, fmt.Errorf("uninitialized Secure Enclave key")
	}
	defer runtime.KeepAlive(k)
	if k.algorithm == SecureEnclaveMLDSA65 || k.algorithm == SecureEnclaveMLDSA87 {
		context, err := mldsaSigningContext(opts)
		if err != nil {
			return nil, err
		}
		if !k.key.IsAlgorithmSupported(k.sec.KeyAlgorithmMLDSASignatureMessage) {
			return nil, ErrUnsupportedAlgorithm
		}
		if context != "" && !k.sec.SupportsMLDSAContext() {
			return nil, fmt.Errorf("%w: ML-DSA context signing is unavailable", ErrUnsupportedAlgorithm)
		}
		signature, err := k.key.CreateMLDSASignature(digest, []byte(context))
		if err != nil {
			return nil, fmt.Errorf("signing with Secure Enclave ML-DSA key: %w", normalizeNativeError(err))
		}
		return signature, nil
	}
	if opts == nil {
		return nil, fmt.Errorf("nil signing options")
	}
	hash := opts.HashFunc()
	var algorithm security.SecKeyAlgorithm
	switch hash {
	case crypto.SHA256:
		algorithm = k.sec.KeyAlgorithmECDSASignatureDigestX962SHA256
	case crypto.SHA384:
		algorithm = k.sec.KeyAlgorithmECDSASignatureDigestX962SHA384
	case crypto.SHA512:
		algorithm = k.sec.KeyAlgorithmECDSASignatureDigestX962SHA512
	default:
		return nil, fmt.Errorf("unsupported hash function: %v", hash)
	}
	if len(digest) != hash.Size() {
		return nil, fmt.Errorf("invalid %v digest length: got %d, want %d", hash, len(digest), hash.Size())
	}
	// kSecKeyOperationTypeSign = 0.
	if !k.key.IsAlgorithmSupported(algorithm) {
		return nil, fmt.Errorf("signing with %v is not supported by Secure Enclave keys", hash)
	}
	signature, err := k.key.CreateSignature(digest, algorithm)
	if err != nil {
		return nil, fmt.Errorf("signing with Secure Enclave key: %w", normalizeNativeError(err))
	}
	return signature, nil
}

// Algorithm reports the algorithm actually provisioned, including any fallback.
// A nil key returns the zero value, which is SecureEnclaveP256.
func (k *SecureEnclaveKey) Algorithm() SecureEnclaveAlgorithm {
	if k == nil {
		return 0
	}
	return k.algorithm
}

func secureEnclaveAuthContext(parameters map[corefoundation.TypeRef]corefoundation.TypeRef, sec *security.Framework, context *AuthContext) error {
	if context == nil {
		return nil
	}
	if context.id == 0 {
		return fmt.Errorf("uninitialized authentication context")
	}
	parameters[corefoundation.TypeRef(sec.UseAuthenticationContext)] = corefoundation.TypeRef(context.id)
	return nil
}
