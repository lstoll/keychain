//go:build darwin

package keychain

import (
	"fmt"
	"sync"

	"github.com/ebitengine/purego"
)

type (
	_SecIdentityRef    uintptr
	_SecCertificateRef uintptr
	_OSStatus          int32
	_SecKeyRef         uintptr
	_SecCodeRef        uintptr
	_SecStaticCodeRef  uintptr
	_SecKeyAlgorithm   _CFStringRef
)

const ( // https://gist.github.com/lefloh/3b4200a8eca40eb3c5596e6b6a7d83e5
	errSecSuccess       _OSStatus = 0
	errSecItemNotFound  _OSStatus = -25300
	errSecDuplicateItem _OSStatus = -25299
)

const (
	kSecCSDefaultFlags = 0
)

type securityFramework struct {
	ClassIdentity                    _CFStringRef
	ClassGenericPassword             _CFStringRef
	MatchLimitAll                    _CFStringRef
	MatchLimitOne                    _CFStringRef
	Class                            _CFStringRef
	ReturnRef                        _CFStringRef
	ReturnAttributes                 _CFStringRef
	ReturnData                       _CFStringRef
	MatchLimit                       _CFStringRef
	AttrAccount                      _CFStringRef
	AttrService                      _CFStringRef
	AttrLabel                        _CFStringRef
	AttrGeneric                      _CFStringRef
	ValueData                        _CFStringRef
	AttrTokenID                      _CFStringRef
	AttrApplicationLabel             _CFStringRef
	AttrKeySizeInBits                _CFStringRef
	ValueRef                         _CFStringRef
	CodeInfoCdHashes                 _CFStringRef
	CodeInfoDigestAlgorithms         _CFStringRef
	CodeSignatureHashSHA1            int32
	CodeSignatureHashSHA256          int32
	CodeSignatureHashSHA256Truncated int32
	CodeSignatureHashSHA384          int32
	CodeSignatureHashSHA512          int32

	KeyAlgorithmECDSASignatureDigestX962SHA256 _SecKeyAlgorithm
	KeyAlgorithmECDSASignatureDigestX962SHA384 _SecKeyAlgorithm
	KeyAlgorithmECDSASignatureDigestX962SHA512 _SecKeyAlgorithm

	ItemCopyMatching              func(query _CFDictionaryRef, res *_CFTypeRef) _OSStatus
	ItemAdd                       func(attributes _CFDictionaryRef, result *_CFTypeRef) _OSStatus
	ItemDelete                    func(query _CFDictionaryRef) _OSStatus
	CopyErrorMessageString        func(s _OSStatus, reserved uintptr) _CFStringRef
	CodeCopySelf                  func(flags uint32, code *_SecCodeRef) _OSStatus
	CodeCheckValidity             func(code _SecCodeRef, flags uint32, requirement _CFTypeRef) _OSStatus
	CodeCopySigningInformation    func(code _SecStaticCodeRef, flags uint32, information *_CFDictionaryRef) _OSStatus
	KeyCopyAttributes             func(key _SecKeyRef) _CFDictionaryRef
	KeyCopyPublicKey              func(key _SecKeyRef) _SecKeyRef
	KeyCopyExternalRepresentation func(key _SecKeyRef, error *_CFErrorRef) _CFDataRef
	KeyCreateSignature            func(key _SecKeyRef, algorithm _SecKeyAlgorithm, signedData _CFDataRef, error *_CFErrorRef) _CFDataRef
	IdentityCopyPrivateKey        func(identity _SecIdentityRef, privateKey *_SecKeyRef) _OSStatus
	IdentityCopyCertificate       func(identity _SecIdentityRef, certificate *_SecCertificateRef) _OSStatus
	CertificateCopyData           func(certificate _SecCertificateRef) _CFDataRef
}

var (
	_sec     *securityFramework
	_secOnce sync.Once
)

func getSecurity() (*securityFramework, error) {
	var _secErr error

	_secOnce.Do(func() {
		handle, err := dlopen("/System/Library/Frameworks/Security.framework/Security", purego.RTLD_LAZY|purego.RTLD_GLOBAL)
		if err != nil {
			_secErr = err
			return
		}

		s := &securityFramework{}

		// Constants
		var val uintptr
		if val, err = constsym(handle, "kSecClassIdentity"); err == nil {
			s.ClassIdentity = _CFStringRef(val)
		} else {
			_secErr = err
			return
		}
		if val, err = constsym(handle, "kSecClassGenericPassword"); err == nil {
			s.ClassGenericPassword = _CFStringRef(val)
		} else {
			_secErr = err
			return
		}
		if val, err = constsym(handle, "kSecMatchLimitAll"); err == nil {
			s.MatchLimitAll = _CFStringRef(val)
		} else {
			_secErr = err
			return
		}
		if val, err = constsym(handle, "kSecMatchLimitOne"); err == nil {
			s.MatchLimitOne = _CFStringRef(val)
		} else {
			_secErr = err
			return
		}
		if val, err = constsym(handle, "kSecClass"); err == nil {
			s.Class = _CFStringRef(val)
		} else {
			_secErr = err
			return
		}
		if val, err = constsym(handle, "kSecReturnRef"); err == nil {
			s.ReturnRef = _CFStringRef(val)
		} else {
			_secErr = err
			return
		}
		if val, err = constsym(handle, "kSecReturnAttributes"); err == nil {
			s.ReturnAttributes = _CFStringRef(val)
		} else {
			_secErr = err
			return
		}
		if val, err = constsym(handle, "kSecReturnData"); err == nil {
			s.ReturnData = _CFStringRef(val)
		} else {
			_secErr = err
			return
		}
		if val, err = constsym(handle, "kSecMatchLimit"); err == nil {
			s.MatchLimit = _CFStringRef(val)
		} else {
			_secErr = err
			return
		}
		if val, err = constsym(handle, "kSecAttrAccount"); err == nil {
			s.AttrAccount = _CFStringRef(val)
		} else {
			_secErr = err
			return
		}
		if val, err = constsym(handle, "kSecAttrService"); err == nil {
			s.AttrService = _CFStringRef(val)
		} else {
			_secErr = err
			return
		}
		if val, err = constsym(handle, "kSecAttrLabel"); err == nil {
			s.AttrLabel = _CFStringRef(val)
		} else {
			_secErr = err
			return
		}
		if val, err = constsym(handle, "kSecAttrGeneric"); err == nil {
			s.AttrGeneric = _CFStringRef(val)
		} else {
			_secErr = err
			return
		}
		if val, err = constsym(handle, "kSecValueData"); err == nil {
			s.ValueData = _CFStringRef(val)
		} else {
			_secErr = err
			return
		}
		if val, err = constsym(handle, "kSecAttrTokenID"); err == nil {
			s.AttrTokenID = _CFStringRef(val)
		} else {
			_secErr = err
			return
		}
		if val, err = constsym(handle, "kSecAttrApplicationLabel"); err == nil {
			s.AttrApplicationLabel = _CFStringRef(val)
		} else {
			_secErr = err
			return
		}
		if val, err = constsym(handle, "kSecAttrKeySizeInBits"); err == nil {
			s.AttrKeySizeInBits = _CFStringRef(val)
		} else {
			_secErr = err
			return
		}
		if val, err = constsym(handle, "kSecValueRef"); err == nil {
			s.ValueRef = _CFStringRef(val)
		} else {
			_secErr = err
			return
		}
		if val, err = constsym(handle, "kSecCodeInfoCdHashes"); err == nil {
			s.CodeInfoCdHashes = _CFStringRef(val)
		} else {
			_secErr = err
			return
		}
		if val, err = constsym(handle, "kSecCodeInfoDigestAlgorithms"); err == nil {
			s.CodeInfoDigestAlgorithms = _CFStringRef(val)
		} else {
			_secErr = err
			return
		}

		s.CodeSignatureHashSHA1 = 1
		s.CodeSignatureHashSHA256 = 2
		s.CodeSignatureHashSHA256Truncated = 3
		s.CodeSignatureHashSHA384 = 4
		s.CodeSignatureHashSHA512 = 5

		if val, err = constsym(handle, "kSecKeyAlgorithmECDSASignatureDigestX962SHA256"); err == nil {
			s.KeyAlgorithmECDSASignatureDigestX962SHA256 = _SecKeyAlgorithm(val)
		} else {
			_secErr = err
			return
		}
		if val, err = constsym(handle, "kSecKeyAlgorithmECDSASignatureDigestX962SHA384"); err == nil {
			s.KeyAlgorithmECDSASignatureDigestX962SHA384 = _SecKeyAlgorithm(val)
		} else {
			_secErr = err
			return
		}
		if val, err = constsym(handle, "kSecKeyAlgorithmECDSASignatureDigestX962SHA512"); err == nil {
			s.KeyAlgorithmECDSASignatureDigestX962SHA512 = _SecKeyAlgorithm(val)
		} else {
			_secErr = err
			return
		}

		// Functions
		if s.ItemCopyMatching, err = registerFunc[func(query _CFDictionaryRef, res *_CFTypeRef) _OSStatus](handle, "SecItemCopyMatching"); err != nil {
			_secErr = err
			return
		}
		if s.ItemAdd, err = registerFunc[func(attributes _CFDictionaryRef, result *_CFTypeRef) _OSStatus](handle, "SecItemAdd"); err != nil {
			_secErr = err
			return
		}
		if s.ItemDelete, err = registerFunc[func(query _CFDictionaryRef) _OSStatus](handle, "SecItemDelete"); err != nil {
			_secErr = err
			return
		}
		if s.CopyErrorMessageString, err = registerFunc[func(s _OSStatus, reserved uintptr) _CFStringRef](handle, "SecCopyErrorMessageString"); err != nil {
			_secErr = err
			return
		}
		if s.CodeCopySelf, err = registerFunc[func(flags uint32, code *_SecCodeRef) _OSStatus](handle, "SecCodeCopySelf"); err != nil {
			_secErr = err
			return
		}
		if s.CodeCheckValidity, err = registerFunc[func(code _SecCodeRef, flags uint32, requirement _CFTypeRef) _OSStatus](handle, "SecCodeCheckValidity"); err != nil {
			_secErr = err
			return
		}
		if s.CodeCopySigningInformation, err = registerFunc[func(code _SecStaticCodeRef, flags uint32, information *_CFDictionaryRef) _OSStatus](handle, "SecCodeCopySigningInformation"); err != nil {
			_secErr = err
			return
		}
		if s.KeyCopyAttributes, err = registerFunc[func(key _SecKeyRef) _CFDictionaryRef](handle, "SecKeyCopyAttributes"); err != nil {
			_secErr = err
			return
		}
		if s.KeyCopyPublicKey, err = registerFunc[func(key _SecKeyRef) _SecKeyRef](handle, "SecKeyCopyPublicKey"); err != nil {
			_secErr = err
			return
		}
		if s.KeyCopyExternalRepresentation, err = registerFunc[func(key _SecKeyRef, error *_CFErrorRef) _CFDataRef](handle, "SecKeyCopyExternalRepresentation"); err != nil {
			_secErr = err
			return
		}
		if s.KeyCreateSignature, err = registerFunc[func(key _SecKeyRef, algorithm _SecKeyAlgorithm, signedData _CFDataRef, error *_CFErrorRef) _CFDataRef](handle, "SecKeyCreateSignature"); err != nil {
			_secErr = err
			return
		}
		if s.IdentityCopyPrivateKey, err = registerFunc[func(identity _SecIdentityRef, privateKey *_SecKeyRef) _OSStatus](handle, "SecIdentityCopyPrivateKey"); err != nil {
			_secErr = err
			return
		}
		if s.IdentityCopyCertificate, err = registerFunc[func(identity _SecIdentityRef, certificate *_SecCertificateRef) _OSStatus](handle, "SecIdentityCopyCertificate"); err != nil {
			_secErr = err
			return
		}
		if s.CertificateCopyData, err = registerFunc[func(certificate _SecCertificateRef) _CFDataRef](handle, "SecCertificateCopyData"); err != nil {
			_secErr = err
			return
		}

		_sec = s
	})

	return _sec, _secErr
}

type errSecOSStatus struct {
	code    _OSStatus
	message string
}

func (e *errSecOSStatus) Error() string {
	return fmt.Sprintf("OSStatus error code %d: %s", e.code, e.message)
}

func (e *errSecOSStatus) Code() _OSStatus {
	return e.code
}

func (s *securityFramework) newError(code _OSStatus) error {
	if code == errSecSuccess {
		return nil
	}
	cf, err := getCoreFoundation()
	if err != nil {
		return &errSecOSStatus{code: code, message: "unknown (corefoundation load failed)"}
	}

	msgRef := s.CopyErrorMessageString(code, 0)
	msg := cf.CFStringToString(msgRef)
	cf.Release(_CFTypeRef(msgRef))

	errCode := ErrorCodeUnknown
	switch code {
	case errSecItemNotFound:
		errCode = ErrorCodeItemNotFound
	case errSecDuplicateItem:
		errCode = ErrorCodeDuplicateItem
	}

	return &Error{
		code: errCode,
		cause: &errSecOSStatus{
			code:    code,
			message: msg,
		},
	}
}
