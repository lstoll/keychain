//go:build darwin

package keychain

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
)

type Identity interface {
	Signer() (crypto.Signer, error)
	Close()
	Label() string
	Delete() error
}

var _ Identity = (*SecIdentity)(nil)

type SecIdentity struct {
	ref    _SecIdentityRef
	label  string
	keyRef _SecKeyRef // Cached private key
}

func (s *SecIdentity) Signer() (crypto.Signer, error) {
	if s.keyRef == 0 {
		var keyRef _SecKeyRef
		if err := secOSStatusErr(_SecIdentityCopyPrivateKey(s.ref, &keyRef)); err != nil {
			return nil, fmt.Errorf("copying private key from identity: %w", err)
		}
		s.keyRef = keyRef
	}

	// Get the public key to build the signer
	pubKeyRef := _SecKeyCopyPublicKey(s.keyRef)
	if pubKeyRef == 0 {
		return nil, fmt.Errorf("failed to get public key from private key")
	}
	defer _CFRelease(_CFTypeRef(pubKeyRef))

	var cfError _CFErrorRef
	pubKeyData := _SecKeyCopyExternalRepresentation(pubKeyRef, &cfError)
	if pubKeyData == 0 {
		return nil, fmt.Errorf("failed to export public key")
	}
	defer _CFRelease(_CFTypeRef(pubKeyData))

	pubKeyBytes := bytesFromCFData(pubKeyData)

	// Determine curve? SecIdentity doesn't tell us easily without parsing key attributes.
	// But ParseUncompressedPublicKey needs the curve.
	// We can try to guess or use a generic parser if available.
	// Or check key attributes.
	attrs := extractAttributesFromKeyRef(s.keyRef)
	keySize, _ := getIntAttr(attrs, kSecAttrKeySizeInBits)
	
	var curve elliptic.Curve
	switch keySize {
	case 256:
		curve = elliptic.P256()
	case 384:
		curve = elliptic.P384()
	case 521:
		curve = elliptic.P521()
	default:
		// Fallback for RSA? But secKeyPrivateKey assumes ECDSA.
		// If it's RSA, we need a different signer.
		// For now assume ECDSA as per CTK requirements, or TODO handle RSA.
		return nil, fmt.Errorf("unsupported key size: %d", keySize)
	}

	pubKey, err := ecdsa.ParseUncompressedPublicKey(curve, pubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing public key: %w", err)
	}
	
	return &secKeyPrivateKey{
		keyRef: s.keyRef,
		pub:    pubKey,
	}, nil
}

func (s *SecIdentity) Close() {
	if s.keyRef != 0 {
		_CFRelease(_CFTypeRef(s.keyRef))
		s.keyRef = 0
	}
	if s.ref != 0 {
		_CFRelease(_CFTypeRef(s.ref))
		s.ref = 0
	}
}

func (s *SecIdentity) Label() string {
	return s.label
}

func (s *SecIdentity) Delete() error {
	// To delete an identity, we pass the ref to SecItemDelete?
	// Or we create a query with the ref.
	query, err := mapToCFDictionary(map[_CFTypeRef]_CFTypeRef{
		_CFTypeRef(kSecClass):      _CFTypeRef(kSecClassIdentity),
		_CFTypeRef(kSecValueRef):   _CFTypeRef(s.ref),
	})
	if err != nil {
		return err
	}
	defer _CFRelease(_CFTypeRef(query))
	
	return secOSStatusErr(_SecItemDelete(query))
}

func Identities() ([]Identity, error) {
	query, err := mapToCFDictionary(map[_CFTypeRef]_CFTypeRef{
		_CFTypeRef(kSecClass):      _CFTypeRef(kSecClassIdentity),
		_CFTypeRef(kSecReturnRef):  _CFTypeRef(kCFBooleanTrue),
		_CFTypeRef(kSecMatchLimit): _CFTypeRef(kSecMatchLimitAll),
		// We might want attributes too to get the Label?
		// But current implementation only asked for Ref.
		// If we want Label, we need kSecReturnAttributes too, but CopyMatching
		// returns distinct results for Ref vs Attributes vs Both (Dict).
		// Let's stick to Ref for now and maybe fetch Label on demand or leave it empty/TODO.
	})
	if err != nil {
		return nil, fmt.Errorf("creating query: %w", err)
	}

	defer _CFRelease(_CFTypeRef(query))

	var res _CFTypeRef
	osstatus := _SecItemCopyMatching(query, &res)
	if err := secOSStatusErr(osstatus); err != nil {
		if err.Code == errSecItemNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("error copying item from query: %w", err)
	}
	defer _CFRelease(res)

	n := _CFArrayGetCount(_CFArrayRef(res))
	idents := make([]_CFTypeRef, n)

	_CFArrayGetValues(_CFArrayRef(res), _CFRange{0, n}, ptrToPtr(&idents[0]))

	var ret []Identity
	for _, i := range idents {
		// We need to retain the ref because the array release will release items?
		// Wait, SecItemCopyMatching with MatchLimitAll returns a CFArray.
		// We are iterating the array.
		// The array owns the refs. When we release the array (res), the refs go away unless we retain them.
		// So yes, we should Retain.
		// The original code didn't Retain explicitly but it was using `_SecIdentityRef(i)` in the struct.
		// If `res` is released at end of function, `i` becomes invalid if not retained.
		// Original code: `defer _CFRelease(res)` then `ret = append(..., &Identity{ref: ...})`.
		// This was a BUG in the original code if `Identity` struct lived longer than the function!
		// Let's fix it by Retaining.
		
		ref := _SecIdentityRef(i)
		_CFRetain(_CFTypeRef(ref))

		ret = append(ret, &SecIdentity{
			ref: ref,
		})
	}

	return ret, nil
}
