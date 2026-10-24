//go:build darwin

package keychain

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"runtime"
	"unsafe"

	"lds.li/keychain/internal/corefoundation"
	"lds.li/keychain/internal/security"
)

// CTKCardTokenID is the token ID of CTK identities created with
// sc_auth create-ctk-identity, whose keys live in the Secure Enclave and are
// accessed through CryptoTokenKit card emulation.
const CTKCardTokenID = "com.apple.ctkcard:user"

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
	identityRef security.SecIdentityRef

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

// Delete removes a SecIdentity from the keychain with SecItemDelete. CTK
// identities belong to their token and cannot be deleted here; remove
// sc_auth-created identities with `sc_auth delete-ctk-identity`.
func (i *Identity) Delete() error {
	switch i.identityType {
	case IdentityTypeCTK:
		return fmt.Errorf("CTK identities are managed by their token; use sc_auth delete-ctk-identity")
	case IdentityTypeSecIdentity:
		cf, err := corefoundation.Get()
		if err != nil {
			return err
		}
		sec, err := security.Get()
		if err != nil {
			return err
		}

		if i.identityRef == 0 {
			return fmt.Errorf("cannot delete SecIdentity: no identity ref")
		}
		query, err := cf.MapToCFDictionary(map[corefoundation.TypeRef]corefoundation.TypeRef{
			corefoundation.TypeRef(sec.Class):    corefoundation.TypeRef(sec.ClassIdentity),
			corefoundation.TypeRef(sec.ValueRef): corefoundation.TypeRef(i.identityRef),
		})
		if err != nil {
			return err
		}
		defer cf.Release(corefoundation.TypeRef(query))
		return newError(sec, sec.ItemDelete(query))
	default:
		return fmt.Errorf("cannot delete identity: unknown type %v", i.identityType)
	}
}

// Signer returns the private key as a crypto.Signer.
func (i *Identity) Signer() (crypto.Signer, error) {
	cf, err := corefoundation.Get()
	if err != nil {
		return nil, err
	}
	sec, err := security.Get()
	if err != nil {
		return nil, err
	}

	if i.identityRef == 0 {
		return nil, fmt.Errorf("no key available")
	}

	var keyRef security.SecKeyRef
	if err := newError(sec, sec.IdentityCopyPrivateKey(i.identityRef, &keyRef)); err != nil {
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
	pubKeyRef := sec.KeyCopyPublicKey(keyRef)
	if pubKeyRef == 0 {
		return nil, fmt.Errorf("failed to get public key from private key")
	}
	defer cf.Release(corefoundation.TypeRef(pubKeyRef))

	// Export the public key as external representation
	var cfError corefoundation.ErrorRef
	pubKeyData := sec.KeyCopyExternalRepresentation(pubKeyRef, &cfError)
	if pubKeyData == 0 {
		return nil, fmt.Errorf("failed to export public key")
	}
	defer cf.Release(corefoundation.TypeRef(pubKeyData))

	pubKeyBytes := cf.BytesFromCFData(pubKeyData)

	pubKey, err := ecdsa.ParseUncompressedPublicKey(curve, pubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing public key: %w", err)
	}

	spk := &secKeyPrivateKey{
		cf:     cf,
		sec:    sec,
		keyRef: keyRef,
		pub:    pubKey,
	}

	runtime.AddCleanup(spk, func(keyRef security.SecKeyRef) {
		cf.Release(corefoundation.TypeRef(keyRef))
	}, keyRef)

	return spk, nil
}

// secKeyPrivateKey implements crypto.Signer using a SecKeyRef.
type secKeyPrivateKey struct {
	cf     *corefoundation.Framework
	sec    *security.Framework
	keyRef security.SecKeyRef
	pub    *ecdsa.PublicKey
}

func (s *secKeyPrivateKey) Public() crypto.PublicKey {
	return s.pub
}

func (s *secKeyPrivateKey) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	var algorithm security.SecKeyAlgorithm
	switch opts.HashFunc() {
	case crypto.SHA256:
		algorithm = s.sec.KeyAlgorithmECDSASignatureDigestX962SHA256
	case crypto.SHA384:
		algorithm = s.sec.KeyAlgorithmECDSASignatureDigestX962SHA384
	case crypto.SHA512:
		algorithm = s.sec.KeyAlgorithmECDSASignatureDigestX962SHA512
	default:
		return nil, fmt.Errorf("unsupported hash function: %v", opts.HashFunc())
	}

	digestData := s.cf.BytesToCFData(digest)
	defer s.cf.Release(corefoundation.TypeRef(digestData))

	var cfError corefoundation.ErrorRef
	signature := s.sec.KeyCreateSignature(s.keyRef, algorithm, digestData, &cfError)
	if signature == 0 {
		return nil, fmt.Errorf("SecKeyCreateSignature failed")
	}
	defer s.cf.Release(corefoundation.TypeRef(signature))

	return s.cf.BytesFromCFData(signature), nil
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

// GetIdentity returns the single matching identity, or an error if there are
// zero or multiple matches.
func GetIdentity(query IdentityQuery) (*Identity, error) {
	results, err := ListIdentities(query)
	if err != nil {
		return nil, err
	}

	if len(results) == 0 {
		return nil, &Error{
			message: "Identity not found for query",
			code:    ErrorCodeItemNotFound,
		}
	}
	if len(results) > 1 {
		return nil, fmt.Errorf("multiple identities (%d) found matching query; use more specific criteria", len(results))
	}

	return results[0], nil
}

// ListIdentities queries kSecClassIdentity and detects CTK identities by their token ID.
func ListIdentities(query IdentityQuery) ([]*Identity, error) {
	cf, err := corefoundation.Get()
	if err != nil {
		return nil, err
	}
	sec, err := security.Get()
	if err != nil {
		return nil, err
	}

	queryMap := map[corefoundation.TypeRef]corefoundation.TypeRef{
		corefoundation.TypeRef(sec.Class):            corefoundation.TypeRef(sec.ClassIdentity),
		corefoundation.TypeRef(sec.ReturnRef):        corefoundation.TypeRef(cf.BooleanTrue),
		corefoundation.TypeRef(sec.ReturnAttributes): corefoundation.TypeRef(cf.BooleanTrue),
		corefoundation.TypeRef(sec.MatchLimit):       corefoundation.TypeRef(sec.MatchLimitAll),
	}

	if query.Label != "" {
		labelRef, err := cf.CreateString(query.Label)
		if err != nil {
			return nil, fmt.Errorf("identity label: %w", err)
		}
		defer cf.Release(corefoundation.TypeRef(labelRef))
		queryMap[corefoundation.TypeRef(sec.AttrLabel)] = corefoundation.TypeRef(labelRef)
	}

	// If querying only CTK, add token ID filter
	if query.Type == IdentityQueryTypeCTK {
		tokenIDRef := cf.StringToCFString(CTKCardTokenID)
		defer cf.Release(corefoundation.TypeRef(tokenIDRef))
		queryMap[corefoundation.TypeRef(sec.AttrTokenID)] = corefoundation.TypeRef(tokenIDRef)
	}

	queryDict, err := cf.MapToCFDictionary(queryMap)
	if err != nil {
		return nil, fmt.Errorf("creating query: %w", err)
	}
	defer cf.Release(corefoundation.TypeRef(queryDict))

	var res corefoundation.TypeRef
	osstatus := sec.ItemCopyMatching(queryDict, &res)
	if err := newError(sec, osstatus); err != nil {
		if errors.Is(err, ErrItemNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("error copying item from query: %w", err)
	}
	defer cf.Release(res)

	items := cf.GoSliceFromCFArray(corefoundation.ArrayRef(res))

	var ret []*Identity
	for _, item := range items {
		itemDict := corefoundation.DictionaryRef(item)

		// Extract label
		itemLabel, _ := cf.GetDictionaryString(itemDict, sec.AttrLabel)

		// The file keychain ignores kSecAttrLabel on identity queries.
		if query.Label != "" && itemLabel != query.Label {
			continue
		}
		refValue := cf.GetDictionaryValue(itemDict, sec.ValueRef)
		if refValue == 0 {
			continue
		}
		ref := security.SecIdentityRef(refValue)
		cf.Retain(corefoundation.TypeRef(ref))

		// Determine identity type by checking token ID
		tokenID, _ := cf.GetDictionaryString(itemDict, sec.AttrTokenID)
		isCTK := tokenID == CTKCardTokenID

		// Skip based on query type filter
		if query.Type == IdentityQueryTypeSecIdentity && isCTK {
			cf.Release(corefoundation.TypeRef(ref))
			continue
		}
		// Note: CTK filter is already handled in the query

		identity := &Identity{
			identityRef: ref,
			label:       itemLabel,
			tokenID:     tokenID,
		}

		runtime.AddCleanup(identity, func(identityRef security.SecIdentityRef) {
			cf.Release(corefoundation.TypeRef(identityRef))
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

	cf, err := corefoundation.Get()
	if err != nil {
		i.certErr = err
		return nil, i.certErr
	}
	sec, err := security.Get()
	if err != nil {
		i.certErr = err
		return nil, i.certErr
	}

	if i.identityRef == 0 {
		i.certErr = fmt.Errorf("no identity ref")
		return nil, i.certErr
	}

	// Get the certificate from the identity
	var certRef security.SecCertificateRef
	if err := newError(sec, sec.IdentityCopyCertificate(i.identityRef, &certRef)); err != nil {
		i.certErr = fmt.Errorf("copying certificate: %w", err)
		return nil, i.certErr
	}
	defer cf.Release(corefoundation.TypeRef(certRef))

	// Get DER data from certificate
	derData := sec.CertificateCopyData(certRef)
	if derData == 0 {
		i.certErr = fmt.Errorf("getting certificate data")
		return nil, i.certErr
	}
	defer cf.Release(corefoundation.TypeRef(derData))

	// Parse as X.509
	cert, err := x509.ParseCertificate(cf.BytesFromCFData(derData))
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

	cf, err := corefoundation.Get()
	if err != nil {
		i.keyFieldsErr = err
		return i.keyFieldsErr
	}
	sec, err := security.Get()
	if err != nil {
		i.keyFieldsErr = err
		return i.keyFieldsErr
	}

	if i.identityRef == 0 {
		i.keyFieldsErr = fmt.Errorf("no identity ref")
		return i.keyFieldsErr
	}

	// Get the private key from the identity
	var keyRef security.SecKeyRef
	if err := newError(sec, sec.IdentityCopyPrivateKey(i.identityRef, &keyRef)); err != nil {
		i.keyFieldsErr = fmt.Errorf("copying private key: %w", err)
		return i.keyFieldsErr
	}
	defer cf.Release(corefoundation.TypeRef(keyRef))

	// Get key attributes
	attrsRef := sec.KeyCopyAttributes(keyRef)
	if attrsRef == 0 {
		i.keyFieldsErr = fmt.Errorf("getting key attributes")
		return i.keyFieldsErr
	}
	defer cf.Release(corefoundation.TypeRef(attrsRef))

	// Extract PublicKeyHash (kSecAttrApplicationLabel)
	if appLabelRef := cf.GetDictionaryValue(attrsRef, sec.AttrApplicationLabel); appLabelRef != 0 {
		if cf.GetTypeID(appLabelRef) == cf.DataGetTypeID() {
			i.publicKeyHash = cf.BytesFromCFData(corefoundation.DataRef(appLabelRef))
		}
	}

	// Extract KeySizeInBits
	if keySizeRef := cf.GetDictionaryValue(attrsRef, sec.AttrKeySizeInBits); keySizeRef != 0 {
		if cf.GetTypeID(keySizeRef) == cf.NumberGetTypeID() {
			var keySize int32
			if cf.NumberGetValue(corefoundation.NumberRef(keySizeRef), cf.NumberIntType, unsafe.Pointer(&keySize)) {
				i.keySizeInBits = int(keySize)
			}
		}
	}

	return nil
}
