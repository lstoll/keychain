//go:build darwin

package keychain

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"fmt"
	"io"
	"runtime"
	"unsafe"
)

// IdentityType specifies the type of identity.
type IdentityType int

const (
	// IdentityTypeSecIdentity represents a keychain identity.
	IdentityTypeSecIdentity IdentityType = iota
	// IdentityTypeCTK represents a CryptoTokenKit identity.
	IdentityTypeCTK
)

func (t IdentityType) String() string {
	switch t {
	case IdentityTypeSecIdentity:
		return "SecIdentity"
	case IdentityTypeCTK:
		return "CTK"
	default:
		return "Unknown"
	}
}

// Identity represents a signing identity from the keychain.
type Identity struct {
	identityType IdentityType

	// identityRef is the SecIdentityRef
	identityRef _SecIdentityRef

	// Common fields
	label string

	// Cached certificate (lazily extracted)
	certificate *x509.Certificate
	certErr     error
	certDone    bool

	// Cached key attributes (lazily extracted)
	publicKeyHash      []byte
	tokenID            string
	keySizeInBits      int
	keyFieldsExtracted bool
	keyFieldsErr       error
}

// Type returns the identity type.
func (i *Identity) Type() IdentityType {
	return i.identityType
}

// Label returns the user-facing label of this identity.
func (i *Identity) Label() string {
	return i.label
}

// Delete removes the identity from the keychain. For CTK identities, this
// shells out to sc_auth delete-ctk-identity. For SecIdentity, this uses
// SecItemDelete.
func (i *Identity) Delete() error {
	switch i.identityType {
	case IdentityTypeCTK:
		hash, err := i.PublicKeyHash()
		if err != nil {
			return fmt.Errorf("cannot delete CTK identity: %w", err)
		}
		return DeleteCTKIdentity(hash)
	case IdentityTypeSecIdentity:
		if i.identityRef == 0 {
			return fmt.Errorf("cannot delete SecIdentity: no identity ref")
		}
		query, err := mapToCFDictionary(map[_CFTypeRef]_CFTypeRef{
			_CFTypeRef(kSecClass):    _CFTypeRef(kSecClassIdentity),
			_CFTypeRef(kSecValueRef): _CFTypeRef(i.identityRef),
		})
		if err != nil {
			return err
		}
		defer _CFRelease(_CFTypeRef(query))
		return secOSStatusErr(_SecItemDelete(query))
	default:
		return fmt.Errorf("cannot delete identity: unknown type %v", i.identityType)
	}
}

// Signer returns the private key as a crypto.Signer.
func (i *Identity) Signer() (crypto.Signer, error) {
	if i.identityRef == 0 {
		return nil, fmt.Errorf("no key available")
	}

	var keyRef _SecKeyRef
	if err := secOSStatusErr(_SecIdentityCopyPrivateKey(i.identityRef, &keyRef)); err != nil {
		return nil, fmt.Errorf("copying private key: %w", err)
	}

	// Determine curve from key size
	keySize, err := i.KeySizeInBits()
	if err != nil {
		return nil, fmt.Errorf("getting key size: %w", err)
	}

	var curve elliptic.Curve
	switch keySize {
	case 256:
		curve = elliptic.P256()
	case 384:
		curve = elliptic.P384()
	case 521:
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported key size: %d bits", keySize)
	}

	// Get the public key from the private key ref
	pubKeyRef := _SecKeyCopyPublicKey(keyRef)
	if pubKeyRef == 0 {
		return nil, fmt.Errorf("failed to get public key from private key")
	}
	defer _CFRelease(_CFTypeRef(pubKeyRef))

	// Export the public key as external representation
	var cfError _CFErrorRef
	pubKeyData := _SecKeyCopyExternalRepresentation(pubKeyRef, &cfError)
	if pubKeyData == 0 {
		return nil, fmt.Errorf("failed to export public key")
	}
	defer _CFRelease(_CFTypeRef(pubKeyData))

	pubKeyBytes := bytesFromCFData(pubKeyData)

	pubKey, err := ecdsa.ParseUncompressedPublicKey(curve, pubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing public key: %w", err)
	}

	spk := &secKeyPrivateKey{
		keyRef: keyRef,
		pub:    pubKey,
	}

	runtime.AddCleanup(spk, func(keyRef _SecKeyRef) {
		_CFRelease(_CFTypeRef(keyRef))
	}, keyRef)

	return spk, nil
}

// secKeyPrivateKey implements crypto.Signer using a SecKeyRef.
type secKeyPrivateKey struct {
	keyRef _SecKeyRef
	pub    *ecdsa.PublicKey
}

func (s *secKeyPrivateKey) Public() crypto.PublicKey {
	return s.pub
}

func (s *secKeyPrivateKey) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	var algorithm _SecKeyAlgorithm
	switch opts.HashFunc() {
	case crypto.SHA256:
		algorithm = kSecKeyAlgorithmECDSASignatureDigestX962SHA256
	case crypto.SHA384:
		algorithm = kSecKeyAlgorithmECDSASignatureDigestX962SHA384
	case crypto.SHA512:
		algorithm = kSecKeyAlgorithmECDSASignatureDigestX962SHA512
	default:
		return nil, fmt.Errorf("unsupported hash function: %v", opts.HashFunc())
	}

	digestData := bytesToCFData(digest)
	defer _CFRelease(_CFTypeRef(digestData))

	var cfError _CFErrorRef
	signature := _SecKeyCreateSignature(s.keyRef, algorithm, digestData, &cfError)
	if signature == 0 {
		return nil, fmt.Errorf("SecKeyCreateSignature failed")
	}
	defer _CFRelease(_CFTypeRef(signature))

	return bytesFromCFData(signature), nil
}

// IdentityQueryType specifies which types of identities to include in a query.
type IdentityQueryType int

const (
	// IdentityQueryTypeAll queries both SecIdentity and CTK identities.
	IdentityQueryTypeAll IdentityQueryType = iota
	// IdentityQueryTypeSecIdentity queries only keychain identities (certificate + key).
	IdentityQueryTypeSecIdentity
	// IdentityQueryTypeCTK queries only CryptoTokenKit identities (Secure Enclave keys).
	IdentityQueryTypeCTK
)

// IdentityQuery specifies criteria for querying identities.
type IdentityQuery struct {
	// Label filters identities by label.
	Label string
	// PublicKeyHash filters CTK identities by public key hash.
	// This is ignored for non-CTK queries.
	PublicKeyHash []byte
	// Type specifies which types of identities to include. Defaults to All.
	Type IdentityQueryType
}

// GetIdentity returns a single identity matching the query.
// Returns an error if no identity matches or if multiple identities match.
// The returned identity can be used for signing. The caller must call Close() when done.
func GetIdentity(query IdentityQuery) (*Identity, error) {
	results, err := ListIdentities(query)
	if err != nil {
		return nil, err
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("no identity found matching query")
	}
	if len(results) > 1 {
		return nil, fmt.Errorf("multiple identities (%d) found matching query; use more specific criteria", len(results))
	}

	return results[0], nil
}

// listIdentities queries kSecClassIdentity and detects CTK identities by their token ID.
func ListIdentities(query IdentityQuery) ([]*Identity, error) {
	queryMap := map[_CFTypeRef]_CFTypeRef{
		_CFTypeRef(kSecClass):            _CFTypeRef(kSecClassIdentity),
		_CFTypeRef(kSecReturnRef):        _CFTypeRef(kCFBooleanTrue),
		_CFTypeRef(kSecReturnAttributes): _CFTypeRef(kCFBooleanTrue),
		_CFTypeRef(kSecMatchLimit):       _CFTypeRef(kSecMatchLimitAll),
	}

	if query.Label != "" {
		labelRef := stringToCFString(query.Label)
		defer _CFRelease(_CFTypeRef(labelRef))
		queryMap[_CFTypeRef(kSecAttrLabel)] = _CFTypeRef(labelRef)
	}

	// If querying only CTK, add token ID filter
	if query.Type == IdentityQueryTypeCTK {
		tokenIDRef := stringToCFString(CTKCardTokenID)
		defer _CFRelease(_CFTypeRef(tokenIDRef))
		queryMap[_CFTypeRef(kSecAttrTokenID)] = _CFTypeRef(tokenIDRef)
	}

	queryDict, err := mapToCFDictionary(queryMap)
	if err != nil {
		return nil, fmt.Errorf("creating query: %w", err)
	}
	defer _CFRelease(_CFTypeRef(queryDict))

	var res _CFTypeRef
	osstatus := _SecItemCopyMatching(queryDict, &res)
	if err := secOSStatusErr(osstatus); err != nil {
		if err.code == errSecItemNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("error copying item from query: %w", err)
	}
	defer _CFRelease(res)

	items := goSliceFromCFArray(_CFArrayRef(res))

	var ret []*Identity
	for _, item := range items {
		itemDict := mapFromCFDictionary(_CFDictionaryRef(item))

		// Extract label
		var itemLabel string
		if l, ok := getStringAttr(itemDict, kSecAttrLabel); ok {
			itemLabel = l
		}

		// Extract identity ref
		refValue, ok := itemDict[_CFTypeRef(kSecValueRef)]
		if !ok {
			continue
		}
		ref := _SecIdentityRef(refValue)
		_CFRetain(_CFTypeRef(ref))

		// Determine identity type by checking token ID
		tokenID, _ := getStringAttr(itemDict, kSecAttrTokenID)
		isCTK := tokenID == CTKCardTokenID

		// Skip based on query type filter
		if query.Type == IdentityQueryTypeSecIdentity && isCTK {
			_CFRelease(_CFTypeRef(ref))
			continue
		}
		// Note: CTK filter is already handled in the query

		identity := &Identity{
			identityRef: ref,
			label:       itemLabel,
			tokenID:     tokenID,
		}

		runtime.AddCleanup(identity, func(identityRef _SecIdentityRef) {
			_CFRelease(_CFTypeRef(identityRef))
		}, ref)

		if isCTK {
			identity.identityType = IdentityTypeCTK

			// If filtering by public key hash, we need to extract it to compare
			if query.PublicKeyHash != nil {
				hash, err := identity.PublicKeyHash()
				if err != nil || !bytes.Equal(hash, query.PublicKeyHash) {
					continue
				}
			}
		} else {
			identity.identityType = IdentityTypeSecIdentity
		}

		ret = append(ret, identity)
	}

	return ret, nil
}

// Certificate returns the X.509 certificate for this identity.
// The certificate is lazily extracted and cached.
func (i *Identity) Certificate() (*x509.Certificate, error) {
	if i.certDone {
		return i.certificate, i.certErr
	}
	i.certDone = true

	if i.identityRef == 0 {
		i.certErr = fmt.Errorf("no identity ref")
		return nil, i.certErr
	}

	// Get the certificate from the identity
	var certRef _SecCertificateRef
	if err := secOSStatusErr(_SecIdentityCopyCertificate(i.identityRef, &certRef)); err != nil {
		i.certErr = fmt.Errorf("copying certificate: %w", err)
		return nil, i.certErr
	}
	defer _CFRelease(_CFTypeRef(certRef))

	// Get DER data from certificate
	derData := _SecCertificateCopyData(certRef)
	if derData == 0 {
		i.certErr = fmt.Errorf("getting certificate data")
		return nil, i.certErr
	}
	defer _CFRelease(_CFTypeRef(derData))

	// Parse as X.509
	cert, err := x509.ParseCertificate(bytesFromCFData(derData))
	if err != nil {
		i.certErr = fmt.Errorf("parsing certificate: %w", err)
		return nil, i.certErr
	}
	i.certificate = cert

	return i.certificate, nil
}

// PublicKeyHash returns the SHA-1 hash of the public key.
// The value is lazily extracted and cached.
func (i *Identity) PublicKeyHash() ([]byte, error) {
	if err := i.ensureKeyFields(); err != nil {
		return nil, err
	}
	return i.publicKeyHash, nil
}

// KeySizeInBits returns the key size in bits.
// The value is lazily extracted and cached.
func (i *Identity) KeySizeInBits() (int, error) {
	if err := i.ensureKeyFields(); err != nil {
		return 0, err
	}
	return i.keySizeInBits, nil
}

// TokenID returns the token ID for CTK identities.
// Returns empty string for non-CTK identities.
func (i *Identity) TokenID() string {
	return i.tokenID
}

// ensureKeyFields extracts the private key and its attributes from the identity.
// It's idempotent - subsequent calls return the cached error if any.
func (i *Identity) ensureKeyFields() error {
	if i.keyFieldsExtracted {
		return i.keyFieldsErr
	}
	i.keyFieldsExtracted = true

	if i.identityRef == 0 {
		i.keyFieldsErr = fmt.Errorf("no identity ref")
		return i.keyFieldsErr
	}

	// Get the private key from the identity
	var keyRef _SecKeyRef
	if err := secOSStatusErr(_SecIdentityCopyPrivateKey(i.identityRef, &keyRef)); err != nil {
		i.keyFieldsErr = fmt.Errorf("copying private key: %w", err)
		return i.keyFieldsErr
	}
	defer _CFRelease(_CFTypeRef(keyRef))

	// Get key attributes
	attrsRef := _SecKeyCopyAttributes(keyRef)
	if attrsRef == 0 {
		i.keyFieldsErr = fmt.Errorf("getting key attributes")
		return i.keyFieldsErr
	}
	defer _CFRelease(_CFTypeRef(attrsRef))

	// Extract PublicKeyHash (kSecAttrApplicationLabel)
	if appLabelRef := _CFDictionaryGetValue(attrsRef, _CFTypeRef(kSecAttrApplicationLabel)); appLabelRef != 0 {
		if _CFGetTypeID(appLabelRef) == _CFDataGetTypeID() {
			i.publicKeyHash = bytesFromCFData(_CFDataRef(appLabelRef))
		}
	}

	// Extract KeySizeInBits
	if keySizeRef := _CFDictionaryGetValue(attrsRef, _CFTypeRef(kSecAttrKeySizeInBits)); keySizeRef != 0 {
		if _CFGetTypeID(keySizeRef) == _CFNumberGetTypeID() {
			var keySize int32
			if _CFNumberGetValue(_CFNumberRef(keySizeRef), kCFNumberIntType, unsafe.Pointer(&keySize)) {
				i.keySizeInBits = int(keySize)
			}
		}
	}

	return nil
}
