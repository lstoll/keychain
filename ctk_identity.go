//go:build darwin

package keychain

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"fmt"
	"io"
	"maps"
	"os/exec"
)

/* CTK identities created with: sc_auth create-ctk-identity -l <label> -k p-256-ne -t none */

// CTKCardTokenID is the token ID for CTK smart card identities created with
// sc_auth create-ctk-identity. These keys are stored in the Secure Enclave
// but accessed via the CryptoTokenKit card emulation layer.
const CTKCardTokenID = "com.apple.ctkcard:user"

// CTKKeyType represents the key algorithm for CTK identities.
type CTKKeyType string

const (
	// CTKKeyTypeP256 creates a P-256 (secp256r1) key in the Secure Enclave (non-extractable).
	CTKKeyTypeP256 CTKKeyType = "p-256-ne"
	// CTKKeyTypeP384 creates a P-384 (secp384r1) key in the Secure Enclave (non-extractable).
	CTKKeyTypeP384 CTKKeyType = "p-384-ne"
)

// CreateCTKIdentity creates a new CTK identity with the given label and key type.
// This shells out to sc_auth create-ctk-identity.
// Returns the created identity (without signing capability - use GetCTKIdentity for that).
// Note: Multiple identities can have the same label.
func CreateCTKIdentity(label string, keyType CTKKeyType) (Identity, error) {
	if label == "" {
		return nil, fmt.Errorf("label is required")
	}
	if keyType == "" {
		keyType = CTKKeyTypeP256
	}

	// Get existing identity hashes before creation
	beforeList, err := ListCTKIdentities()
	if err != nil {
		return nil, fmt.Errorf("listing identities before creation: %w", err)
	}
	existingHashes := make(map[string]bool)
	for _, id := range beforeList {
		if ctkId, ok := id.(*ctkIdentity); ok {
			existingHashes[hex.EncodeToString(ctkId.PublicKeyHash)] = true
		}
	}

	// Create the identity
	cmd := exec.Command("sc_auth", "create-ctk-identity", "-l", label, "-k", string(keyType), "-t", "none")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("sc_auth create-ctk-identity failed: %w: %s", err, string(output))
	}

	// Get identities after creation and find the new one
	afterList, err := ListCTKIdentities()
	if err != nil {
		return nil, fmt.Errorf("listing identities after creation: %w", err)
	}

	for _, id := range afterList {
		ctkId, ok := id.(*ctkIdentity)
		if !ok {
			continue
		}
		hashHex := hex.EncodeToString(ctkId.PublicKeyHash)
		if !existingHashes[hashHex] && ctkId.label == label {
			return ctkId, nil
		}
	}

	return nil, fmt.Errorf("created identity but could not find it in keychain")
}

// DeleteCTKIdentity deletes a CTK identity by its public key hash.
// This shells out to sc_auth delete-ctk-identity.
func DeleteCTKIdentity(publicKeyHash []byte) error {
	if publicKeyHash == nil {
		return fmt.Errorf("publicKeyHash is required")
	}

	hashHex := hex.EncodeToString(publicKeyHash)
	cmd := exec.Command("sc_auth", "delete-ctk-identity", "-h", hashHex)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("sc_auth delete-ctk-identity failed: %w: %s", err, string(output))
	}

	return nil
}

// DeleteCTKIdentityByLabel deletes a CTK identity by its label.
// Returns an error if multiple identities have the same label.
func DeleteCTKIdentityByLabel(label string) error {
	identity, err := GetCTKIdentity(label, nil)
	if err != nil {
		return fmt.Errorf("finding identity to delete: %w", err)
	}
	defer identity.Close()

	if ctkId, ok := identity.(*ctkIdentity); ok {
		return DeleteCTKIdentity(ctkId.PublicKeyHash)
	}
	return fmt.Errorf("identity is not a CTK identity")
}

// ctkIdentity represents a CryptoTokenKit identity created with sc_auth,
// typically backed by the Secure Enclave.
type ctkIdentity struct {
	// Label is the user-facing label of this identity.
	label string
	// PublicKeyHash is the SHA-1 hash of the public key (shown by sc_auth list-ctk-identities).
	PublicKeyHash []byte
	// TokenID identifies the token that stores this key.
	TokenID string
	// KeySizeInBits is the size of the key in bits.
	KeySizeInBits int

	// secKeyRef holds the SecKeyRef for the private key. Only set when
	// retrieved via GetCTKIdentity.
	secKeyRef _SecKeyRef
}

func (c *ctkIdentity) Label() string {
	return c.label
}

func (c *ctkIdentity) Delete() error {
	return DeleteCTKIdentity(c.PublicKeyHash)
}

// Close releases the underlying SecKeyRef if it was retrieved.
// This should be called when the identity is no longer needed.
func (c *ctkIdentity) Close() {
	if c.secKeyRef != 0 {
		_CFRelease(_CFTypeRef(c.secKeyRef))
		c.secKeyRef = 0
	}
}

// Signer returns the private key as a crypto.Signer. The key is backed by
// the Secure Enclave and cannot be exported. The identity must have been
// retrieved via GetCTKIdentity.
func (c *ctkIdentity) Signer() (crypto.Signer, error) {
	if c.secKeyRef == 0 {
		return nil, fmt.Errorf("no key ref available; use GetCTKIdentity to retrieve a signable identity")
	}

	// Determine the curve from key size
	var curve elliptic.Curve
	switch c.KeySizeInBits {
	case 256:
		curve = elliptic.P256()
	case 384:
		curve = elliptic.P384()
	case 521:
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported key size: %d bits", c.KeySizeInBits)
	}

	// Get the public key from the private key ref
	pubKeyRef := _SecKeyCopyPublicKey(c.secKeyRef)
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

	// Parse the public key using the standard library
	pubKey, err := ecdsa.ParseUncompressedPublicKey(curve, pubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing public key: %w", err)
	}

	return &secKeyPrivateKey{
		keyRef: c.secKeyRef,
		pub:    pubKey,
	}, nil
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
		// TODO: extract error message from cfError?
		return nil, fmt.Errorf("SecKeyCreateSignature failed")
	}
	defer _CFRelease(_CFTypeRef(signature))

	return bytesFromCFData(signature), nil
}

// populateCTKIdentityFromAttrs fills in CTKIdentity fields from a dictionary of attributes.
// It only sets fields that are not already set, allowing merging from multiple sources.
func populateCTKIdentityFromAttrs(identity *ctkIdentity, attrs map[_CFTypeRef]_CFTypeRef) {
	if identity.label == "" {
		if label, ok := getStringAttr(attrs, kSecAttrLabel); ok {
			identity.label = label
		}
	}
	if identity.TokenID == "" {
		if tokenID, ok := getStringAttr(attrs, kSecAttrTokenID); ok {
			identity.TokenID = tokenID
		}
	}
	if identity.PublicKeyHash == nil {
		if appLabel, ok := getDataAttr(attrs, kSecAttrApplicationLabel); ok {
			identity.PublicKeyHash = appLabel
		}
	}
	if identity.KeySizeInBits == 0 {
		if keySizeInBits, ok := getIntAttr(attrs, kSecAttrKeySizeInBits); ok {
			identity.KeySizeInBits = keySizeInBits
		}
	}
}

// populateFromKeyRef extracts attributes from a SecKeyRef and populates the identity.
func (c *ctkIdentity) populateFromKeyRef() error {
	if c.secKeyRef == 0 {
		return fmt.Errorf("no key ref available")
	}

	attrsRef := _SecKeyCopyAttributes(c.secKeyRef)
	if attrsRef == 0 {
		return fmt.Errorf("failed to copy key attributes")
	}
	defer _CFRelease(_CFTypeRef(attrsRef))

	attrs := mapFromCFDictionary(attrsRef)
	populateCTKIdentityFromAttrs(c, attrs)
	return nil
}

func buildKeyQuery(addlAttrs map[_CFTypeRef]_CFTypeRef, label string, publicKeyHash []byte) (_CFDictionaryRef, error) {
	query := map[_CFTypeRef]_CFTypeRef{
		_CFTypeRef(kSecClass): _CFTypeRef(kSecClassKey),
	}

	tokenIDRef := stringToCFString(CTKCardTokenID)
	query[_CFTypeRef(kSecAttrTokenID)] = _CFTypeRef(tokenIDRef)
	defer _CFRelease(_CFTypeRef(tokenIDRef))

	if label != "" {
		labelRef := stringToCFString(label)
		query[_CFTypeRef(kSecAttrLabel)] = _CFTypeRef(labelRef)
		defer _CFRelease(_CFTypeRef(labelRef))
	}

	if publicKeyHash != nil {
		hashRef := bytesToCFData(publicKeyHash)
		query[_CFTypeRef(kSecAttrApplicationLabel)] = _CFTypeRef(hashRef)
		defer _CFRelease(_CFTypeRef(hashRef))
	}

	maps.Copy(query, addlAttrs)

	return mapToCFDictionary(query)
}

// extractAttributesFromKeyRef is a helper that extracts attributes from a SecKeyRef
// without retaining it (for temporary use only in listing operations).
// Returns nil if the keyRef is invalid or attributes cannot be extracted.
func extractAttributesFromKeyRef(keyRef _SecKeyRef) map[_CFTypeRef]_CFTypeRef {
	if keyRef == 0 {
		return nil
	}
	attrsRef := _SecKeyCopyAttributes(keyRef)
	if attrsRef == 0 {
		return nil
	}
	defer _CFRelease(_CFTypeRef(attrsRef))
	return mapFromCFDictionary(attrsRef)
}

// ListCTKIdentities returns all CTK identities (created with sc_auth create-ctk-identity).
func ListCTKIdentities() ([]Identity, error) {
	q, err := buildKeyQuery(map[_CFTypeRef]_CFTypeRef{
		_CFTypeRef(kSecReturnAttributes): _CFTypeRef(kCFBooleanTrue),
		_CFTypeRef(kSecReturnRef):        _CFTypeRef(kCFBooleanTrue),
		_CFTypeRef(kSecMatchLimit):       _CFTypeRef(kSecMatchLimitAll),
	}, "", nil)
	if err != nil {
		return nil, err
	}
	defer _CFRelease(_CFTypeRef(q))

	var r _CFTypeRef
	status := _SecItemCopyMatching(q, &r)
	if err := secOSStatusErr(status); err != nil {
		// No items found is not an error for listing
		if err.code == errSecItemNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("listing CTK identities: %w", err)
	}
	defer _CFRelease(_CFTypeRef(r))

	result := goSliceFromCFArray(_CFArrayRef(r))

	identities := make([]Identity, len(result))
	for i, item := range result {
		itemDict := mapFromCFDictionary(_CFDictionaryRef(item))
		ctkId := &ctkIdentity{}
		populateCTKIdentityFromAttrs(ctkId, itemDict)

		// Supplement with attributes from the key ref directly (if available)
		if ref, ok := itemDict[_CFTypeRef(kSecValueRef)]; ok {
			if keyAttrs := extractAttributesFromKeyRef(_SecKeyRef(ref)); keyAttrs != nil {
				populateCTKIdentityFromAttrs(ctkId, keyAttrs)
			}
		}
		identities[i] = ctkId
	}

	return identities, nil
}

// GetCTKIdentity retrieves a single CTK identity by label or public key hash.
// The returned identity can be used for signing via the Signer() method.
// The caller must call Close() on the returned identity when done.
//
// If querying by label and multiple identities match, an error is returned.
// For precise matching, use the publicKeyHash parameter.
func GetCTKIdentity(label string, publicKeyHash []byte) (Identity, error) {
	if label == "" && publicKeyHash == nil {
		return nil, fmt.Errorf("either label or publicKeyHash must be provided")
	}

	// If querying by label, first check that only one matches
	if label != "" && publicKeyHash == nil {
		countQuery, err := buildKeyQuery(map[_CFTypeRef]_CFTypeRef{
			_CFTypeRef(kSecReturnAttributes): _CFTypeRef(kCFBooleanTrue),
			_CFTypeRef(kSecMatchLimit):       _CFTypeRef(kSecMatchLimitAll),
		}, label, nil)
		if err != nil {
			return nil, err
		}
		defer _CFRelease(_CFTypeRef(countQuery))

		var countResult _CFTypeRef
		status := _SecItemCopyMatching(countQuery, &countResult)
		if err := secOSStatusErr(status); err != nil {
			return nil, fmt.Errorf("getting CTK identity: %w", err)
		}
		defer _CFRelease(_CFTypeRef(countResult))

		results := goSliceFromCFArray(_CFArrayRef(countResult))
		if len(results) > 1 {
			return nil, fmt.Errorf("multiple CTK identities found with label %q; use publicKeyHash for precise matching", label)
		}
	}

	q, err := buildKeyQuery(map[_CFTypeRef]_CFTypeRef{
		_CFTypeRef(kSecReturnAttributes): _CFTypeRef(kCFBooleanTrue),
		_CFTypeRef(kSecReturnRef):        _CFTypeRef(kCFBooleanTrue),
		_CFTypeRef(kSecMatchLimit):       _CFTypeRef(kSecMatchLimitOne),
	}, label, publicKeyHash)
	if err != nil {
		return nil, err
	}
	defer _CFRelease(_CFTypeRef(q))

	var r _CFTypeRef
	status := _SecItemCopyMatching(q, &r)
	if err := secOSStatusErr(status); err != nil {
		return nil, fmt.Errorf("getting CTK identity: %w", err)
	}
	defer _CFRelease(_CFTypeRef(r))

	result := mapFromCFDictionary(_CFDictionaryRef(r))

	identity := &ctkIdentity{}
	populateCTKIdentityFromAttrs(identity, result)

	// Extract and retain the SecKeyRef
	if ref, ok := result[_CFTypeRef(kSecValueRef)]; ok {
		identity.secKeyRef = _SecKeyRef(ref)
		_CFRetain(_CFTypeRef(identity.secKeyRef))
		if err := identity.populateFromKeyRef(); err != nil {
			return nil, fmt.Errorf("populating identity from key ref: %w", err)
		}
	}

	return identity, nil
}

// GetCTKIdentityByPublicKeyHashHex is a convenience function that calls GetCTKIdentity
// with a hex-encoded public key hash (as shown by sc_auth list-ctk-identities).
func GetCTKIdentityByPublicKeyHashHex(hashHex string) (Identity, error) {
	hash, err := hex.DecodeString(hashHex)
	if err != nil {
		return nil, fmt.Errorf("invalid hex public key hash: %w", err)
	}
	return GetCTKIdentity("", hash)
}
