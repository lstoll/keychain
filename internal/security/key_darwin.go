//go:build darwin

package security

import (
	"errors"
	"fmt"
	"runtime"

	cf "lds.li/keychain/internal/corefoundation"
)

const OperationSign cf.Index = 0

// NativeError describes a Security.framework OSStatus or CFError.
type NativeError struct {
	Domain      string
	Code        int64
	Description string
}

func (e *NativeError) Error() string {
	if e.Description != "" {
		return e.Description
	}
	return fmt.Sprintf("%s error %d", e.Domain, e.Code)
}

// ErrorFromCFError copies the details and consumes the +1 CFError reference.
func (f *Framework) ErrorFromCFError(ref cf.ErrorRef) error {
	if ref == 0 {
		return nil
	}
	core := f.CoreFoundation
	if core == nil {
		return errors.New("CoreFoundation unavailable")
	}
	defer core.Release(cf.TypeRef(ref))
	domainRef := core.ErrorGetDomain(ref)
	domain := core.CFStringToString(domainRef)
	code := int64(core.ErrorGetCode(ref))
	descRef := core.ErrorCopyDescription(ref)
	var desc string
	if descRef != 0 {
		desc = core.CFStringToString(descRef)
		core.Release(cf.TypeRef(descRef))
	}
	return &NativeError{Domain: domain, Code: code, Description: desc}
}

// StatusError converts a non-success Security OSStatus into a native error.
func (f *Framework) StatusError(status OSStatus) error {
	if status == ErrSecSuccess {
		return nil
	}
	core := f.CoreFoundation
	if core == nil {
		return &NativeError{Domain: "NSOSStatusErrorDomain", Code: int64(status), Description: "CoreFoundation unavailable"}
	}
	msgRef := f.CopyErrorMessageString(status, 0)
	msg := core.CFStringToString(msgRef)
	if msgRef != 0 {
		core.Release(cf.TypeRef(msgRef))
	}
	return &NativeError{Domain: "NSOSStatusErrorDomain", Code: int64(status), Description: msg}
}

type keyState struct {
	ref       SecKeyRef
	framework *Framework
	core      *cf.Framework
}
type keyRelease struct {
	ref  SecKeyRef
	core *cf.Framework
}

// Key is a copy-safe owner of one retained native SecKey reference.
// Copying Key shares its state and cleanup, so only one native release occurs.
type Key struct{ state *keyState }

func (f *Framework) AdoptKey(ref SecKeyRef) Key {
	if ref == 0 {
		return Key{}
	}
	core := f.CoreFoundation
	state := &keyState{ref: ref, framework: f, core: core}
	runtime.AddCleanup(state, func(r keyRelease) {
		if r.core != nil && r.core.Release != nil {
			r.core.Release(cf.TypeRef(r.ref))
		}
	}, keyRelease{ref: ref, core: core})
	return Key{state: state}
}

func (f *Framework) CreateRandomKey(params cf.DictionaryRef) (Key, error) {
	var cfErr cf.ErrorRef
	ref := f.KeyCreateRandomKey(params, &cfErr)
	if ref == 0 {
		if err := f.ErrorFromCFError(cfErr); err != nil {
			return Key{}, err
		}
		return Key{}, errors.New("SecKeyCreateRandomKey returned no key")
	}
	if cfErr != 0 {
		err := f.ErrorFromCFError(cfErr)
		if err != nil {
			f.CoreFoundation.Release(cf.TypeRef(ref))
			return Key{}, err
		}
	}
	return f.AdoptKey(ref), nil
}

func (f *Framework) CreateKeyWithData(data cf.DataRef, params cf.DictionaryRef) (Key, error) {
	var cfErr cf.ErrorRef
	ref := f.KeyCreateWithData(data, params, &cfErr)
	if ref == 0 {
		if err := f.ErrorFromCFError(cfErr); err != nil {
			return Key{}, err
		}
		return Key{}, errors.New("SecKeyCreateWithData returned no key")
	}
	if cfErr != 0 {
		err := f.ErrorFromCFError(cfErr)
		if err != nil {
			f.CoreFoundation.Release(cf.TypeRef(ref))
			return Key{}, err
		}
	}
	return f.AdoptKey(ref), nil
}

func (k Key) usable() (*keyState, error) {
	if k.state == nil || k.state.ref == 0 || k.state.framework == nil || k.state.core == nil {
		return nil, errors.New("invalid native key")
	}
	return k.state, nil
}

func (k Key) CopyPublicKey() (Key, error) {
	s, err := k.usable()
	if err != nil {
		return Key{}, err
	}
	ref := s.framework.KeyCopyPublicKey(s.ref)
	runtime.KeepAlive(s)
	if ref == 0 {
		return Key{}, errors.New("SecKeyCopyPublicKey returned no key")
	}
	return s.framework.AdoptKey(ref), nil
}
func (k Key) CopyAttributes() (cf.DictionaryRef, error) {
	s, err := k.usable()
	if err != nil {
		return 0, err
	}
	ref := s.framework.KeyCopyAttributes(s.ref)
	runtime.KeepAlive(s)
	if ref == 0 {
		return 0, errors.New("SecKeyCopyAttributes returned no attributes")
	}
	return ref, nil
}
func (k Key) ExternalRepresentation() ([]byte, error) {
	s, err := k.usable()
	if err != nil {
		return nil, err
	}
	var cfErr cf.ErrorRef
	ref := s.framework.KeyCopyExternalRepresentation(s.ref, &cfErr)
	runtime.KeepAlive(s)
	if ref == 0 {
		if e := s.framework.ErrorFromCFError(cfErr); e != nil {
			return nil, e
		}
		return nil, errors.New("SecKeyCopyExternalRepresentation returned no data")
	}
	defer s.core.Release(cf.TypeRef(ref))
	if cfErr != 0 {
		if e := s.framework.ErrorFromCFError(cfErr); e != nil {
			return nil, e
		}
	}
	return s.core.BytesFromCFData(ref), nil
}
func (k Key) CreateSignature(digest []byte, algorithm SecKeyAlgorithm) ([]byte, error) {
	s, err := k.usable()
	if err != nil {
		return nil, err
	}
	data := s.core.BytesToCFData(digest)
	if data == 0 {
		return nil, errors.New("creating signature digest data failed")
	}
	defer s.core.Release(cf.TypeRef(data))
	var cfErr cf.ErrorRef
	ref := s.framework.KeyCreateSignature(s.ref, algorithm, data, &cfErr)
	runtime.KeepAlive(s)
	if ref == 0 {
		if e := s.framework.ErrorFromCFError(cfErr); e != nil {
			return nil, e
		}
		return nil, errors.New("SecKeyCreateSignature returned no data")
	}
	defer s.core.Release(cf.TypeRef(ref))
	if cfErr != 0 {
		if e := s.framework.ErrorFromCFError(cfErr); e != nil {
			return nil, e
		}
	}
	return s.core.BytesFromCFData(ref), nil
}

// CreateMLDSASignature creates a message-form ML-DSA signature. A nonempty
// context requires the optional Security.framework context-signing API.
func (k Key) CreateMLDSASignature(message, context []byte) ([]byte, error) {
	if len(context) > 255 {
		return nil, errors.New("ML-DSA context exceeds 255 bytes")
	}
	s, err := k.usable()
	if err != nil {
		return nil, err
	}
	f := s.framework
	if f.KeyAlgorithmMLDSASignatureMessage == 0 {
		return nil, errors.New("ML-DSA message signature algorithm is unavailable")
	}

	var messageData cf.DataRef
	var parameters cf.DictionaryRef
	if len(context) == 0 {
		if f.KeyCreateSignature == nil {
			return nil, errors.New("signature API is unavailable in Security.framework")
		}
		messageData = s.core.BytesToCFData(message)
		if messageData == 0 {
			return nil, errors.New("creating ML-DSA message data failed")
		}
		defer s.core.Release(cf.TypeRef(messageData))
	} else {
		if !f.SupportsMLDSAContext() {
			return nil, errors.New("ML-DSA context signing is unavailable")
		}
		messageData = s.core.BytesToCFData(message)
		if messageData == 0 {
			return nil, errors.New("creating ML-DSA message data failed")
		}
		defer s.core.Release(cf.TypeRef(messageData))
		contextData := s.core.BytesToCFData(context)
		if contextData == 0 {
			return nil, errors.New("creating ML-DSA context data failed")
		}
		defer s.core.Release(cf.TypeRef(contextData))
		parameters, err = s.core.MapToCFDictionary(map[cf.TypeRef]cf.TypeRef{
			cf.TypeRef(f.KeySignatureParameterContext): cf.TypeRef(contextData),
		})
		if err != nil {
			return nil, fmt.Errorf("creating ML-DSA signature parameters: %w", err)
		}
		defer s.core.Release(cf.TypeRef(parameters))
	}

	var cfErr cf.ErrorRef
	var signature cf.DataRef
	if len(context) == 0 {
		signature = f.KeyCreateSignature(s.ref, f.KeyAlgorithmMLDSASignatureMessage, messageData, &cfErr)
	} else {
		signature = f.KeyCreateMLDSASignature(s.ref, f.KeyAlgorithmMLDSASignatureMessage, messageData, parameters, &cfErr)
	}
	runtime.KeepAlive(s)
	if signature == 0 {
		if nativeErr := f.ErrorFromCFError(cfErr); nativeErr != nil {
			return nil, nativeErr
		}
		return nil, errors.New("no ML-DSA signature returned by Security.framework")
	}
	defer s.core.Release(cf.TypeRef(signature))
	if cfErr != 0 {
		if nativeErr := f.ErrorFromCFError(cfErr); nativeErr != nil {
			return nil, nativeErr
		}
	}
	return s.core.BytesFromCFData(signature), nil
}

func (k Key) IsAlgorithmSupported(algorithm SecKeyAlgorithm) bool {
	if algorithm == 0 {
		return false
	}
	s, err := k.usable()
	if err != nil {
		return false
	}
	if s.framework.KeyIsAlgorithmSupported == nil {
		return false
	}
	supported := s.framework.KeyIsAlgorithmSupported(s.ref, OperationSign, algorithm)
	runtime.KeepAlive(s)
	return supported
}

func fileKeychainPasswordLength(length int) (uint32, error) {
	if length < 0 || uint64(length) > uint64(^uint32(0)) {
		return 0, fmt.Errorf("file keychain password exceeds UInt32 length")
	}
	return uint32(length), nil
}

// UpdateFileKeychainPassword replaces an item's secret in the file keychain.
// SecItemUpdate cannot store an empty secret there: its file keychain bridge
// passes CFDataGetBytePtr of the value to SecKeychainItemModifyContent, which is
// NULL for empty data and means "leave the secret unchanged" (SecItemUpdate in
// Security's OSX/libsecurity_keychain/lib/SecItem.cpp). Calling the underlying
// legacy function with a nonnil pointer stores the empty value.
func (f *Framework) UpdateFileKeychainPassword(itemRef SecKeychainItemRef, password []byte) error {
	length, err := fileKeychainPasswordLength(len(password))
	if err != nil {
		return err
	}
	var emptyByte byte
	data := &emptyByte
	if len(password) != 0 {
		data = &password[0]
	}
	status := f.SecKeychainItemModifyAttributesAndData(itemRef, nil, length, data)
	runtime.KeepAlive(password)
	return f.StatusError(status)
}

// DeleteFileKeychainItem deletes a file keychain item directly. SecItemDelete
// wraps this in _SafeSecKeychainItemDelete (Security's SecItem.cpp), which
// refuses with errSecInvalidOwnerEdit unless the caller's executable file name
// matches that of the password item's creator; this skips that check.
func (f *Framework) DeleteFileKeychainItem(itemRef SecKeychainItemRef) error {
	return f.StatusError(f.SecKeychainItemDelete(itemRef))
}
