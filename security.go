//go:build darwin

package keychain

import (
	"fmt"

	"github.com/ebitengine/purego"
)

type (
	_SecIdentityRef   uintptr
	_OSStatus         int32
	_SecKeyRef        uintptr
	_SecCodeRef       uintptr
	_SecStaticCodeRef uintptr
	_SecKeyAlgorithm  _CFStringRef
)

const ( // https://gist.github.com/lefloh/3b4200a8eca40eb3c5596e6b6a7d83e5
	errSecSuccess       _OSStatus = 0
	errSecItemNotFound  _OSStatus = -25300
	errSecDuplicateItem _OSStatus = -25299
)

const (
	kSecCSDefaultFlags = 0
)

var (
	security = dlopen("/System/Library/Frameworks/Security.framework/Security", purego.RTLD_LAZY|purego.RTLD_GLOBAL)

	kSecClassIdentity                    _CFStringRef = _CFStringRef(constsym(security, "kSecClassIdentity"))
	kSecClassGenericPassword             _CFStringRef = _CFStringRef(constsym(security, "kSecClassGenericPassword"))
	kSecClassKey                         _CFStringRef = _CFStringRef(constsym(security, "kSecClassKey"))
	kSecMatchLimitAll                    _CFStringRef = _CFStringRef(constsym(security, "kSecMatchLimitAll"))
	kSecMatchLimitOne                    _CFStringRef = _CFStringRef(constsym(security, "kSecMatchLimitOne"))
	kSecClass                            _CFStringRef = _CFStringRef(constsym(security, "kSecClass"))
	kSecReturnRef                        _CFStringRef = _CFStringRef(constsym(security, "kSecReturnRef"))
	kSecReturnAttributes                 _CFStringRef = _CFStringRef(constsym(security, "kSecReturnAttributes"))
	kSecReturnData                       _CFStringRef = _CFStringRef(constsym(security, "kSecReturnData"))
	kSecMatchLimit                       _CFStringRef = _CFStringRef(constsym(security, "kSecMatchLimit"))
	kSecAttrAccount                      _CFStringRef = _CFStringRef(constsym(security, "kSecAttrAccount"))
	kSecAttrService                      _CFStringRef = _CFStringRef(constsym(security, "kSecAttrService"))
	kSecAttrLabel                        _CFStringRef = _CFStringRef(constsym(security, "kSecAttrLabel"))
	kSecAttrGeneric                      _CFStringRef = _CFStringRef(constsym(security, "kSecAttrGeneric"))
	kSecValueData                        _CFStringRef = _CFStringRef(constsym(security, "kSecValueData"))
	kSecAttrTokenID                      _CFStringRef = _CFStringRef(constsym(security, "kSecAttrTokenID"))
	kSecAttrApplicationLabel             _CFStringRef = _CFStringRef(constsym(security, "kSecAttrApplicationLabel"))
	kSecAttrKeySizeInBits                _CFStringRef = _CFStringRef(constsym(security, "kSecAttrKeySizeInBits"))
	kSecValueRef                         _CFStringRef = _CFStringRef(constsym(security, "kSecValueRef"))
	kSecCodeInfoCdHashes                 _CFStringRef = _CFStringRef(constsym(security, "kSecCodeInfoCdHashes"))
	kSecCodeInfoDigestAlgorithms         _CFStringRef = _CFStringRef(constsym(security, "kSecCodeInfoDigestAlgorithms"))
	kSecCodeSignatureHashSHA1            int32        = 1
	kSecCodeSignatureHashSHA256          int32        = 2
	kSecCodeSignatureHashSHA256Truncated int32        = 3
	kSecCodeSignatureHashSHA384          int32        = 4
	kSecCodeSignatureHashSHA512          int32        = 5

	kSecKeyAlgorithmECDSASignatureDigestX962SHA256 _SecKeyAlgorithm = _SecKeyAlgorithm(constsym(security, "kSecKeyAlgorithmECDSASignatureDigestX962SHA256"))
	kSecKeyAlgorithmECDSASignatureDigestX962SHA384 _SecKeyAlgorithm = _SecKeyAlgorithm(constsym(security, "kSecKeyAlgorithmECDSASignatureDigestX962SHA384"))
	kSecKeyAlgorithmECDSASignatureDigestX962SHA512 _SecKeyAlgorithm = _SecKeyAlgorithm(constsym(security, "kSecKeyAlgorithmECDSASignatureDigestX962SHA512"))
)

var (
	_SecItemCopyMatching       = registerFunc[func(query _CFDictionaryRef, res *_CFTypeRef) _OSStatus](security, "SecItemCopyMatching")
	_SecItemAdd                = registerFunc[func(attributes _CFDictionaryRef, result *_CFTypeRef) _OSStatus](security, "SecItemAdd")
	_SecItemDelete             = registerFunc[func(query _CFDictionaryRef) _OSStatus](security, "SecItemDelete")
	_SecCopyErrorMessageString = registerFunc[func(s _OSStatus, reserved uintptr) _CFStringRef](security, "SecCopyErrorMessageString")

	_SecCodeCopySelf               = registerFunc[func(flags uint32, code *_SecCodeRef) _OSStatus](security, "SecCodeCopySelf")
	_SecCodeCheckValidity          = registerFunc[func(code _SecCodeRef, flags uint32, requirement _CFTypeRef) _OSStatus](security, "SecCodeCheckValidity")
	_SecCodeCopySigningInformation = registerFunc[func(code _SecStaticCodeRef, flags uint32, information *_CFDictionaryRef) _OSStatus](security, "SecCodeCopySigningInformation")

	_SecKeyCopyAttributes             = registerFunc[func(key _SecKeyRef) _CFDictionaryRef](security, "SecKeyCopyAttributes")
	_SecKeyCopyPublicKey              = registerFunc[func(key _SecKeyRef) _SecKeyRef](security, "SecKeyCopyPublicKey")
	_SecKeyCopyExternalRepresentation = registerFunc[func(key _SecKeyRef, error *_CFErrorRef) _CFDataRef](security, "SecKeyCopyExternalRepresentation")
	_SecKeyCreateSignature            = registerFunc[func(key _SecKeyRef, algorithm _SecKeyAlgorithm, signedData _CFDataRef, error *_CFErrorRef) _CFDataRef](security, "SecKeyCreateSignature")

	_SecIdentityCopyPrivateKey = registerFunc[func(identity _SecIdentityRef, privateKey *_SecKeyRef) _OSStatus](security, "SecIdentityCopyPrivateKey")
)

type errSecOSStatus struct {
	Code    _OSStatus
	Message string
}

func (e *errSecOSStatus) Error() string {
	return fmt.Sprintf("OSStatus error code %d: %s", e.Code, e.Message)
}

func secOSStatusErr(s _OSStatus) *errSecOSStatus {
	if s == errSecSuccess {
		return nil
	}
	return &errSecOSStatus{
		Code:    s,
		Message: cfStringtoString(_SecCopyErrorMessageString(s, 0)),
	}
}

// ErrorCode for compatibility with o2ext
type ErrorCode _OSStatus

const (
	KeychainErrorCodeSuccess       ErrorCode = ErrorCode(errSecSuccess)
	KeychainErrorCodeItemNotFound  ErrorCode = ErrorCode(errSecItemNotFound)
	KeychainErrorCodeDuplicateItem ErrorCode = ErrorCode(errSecDuplicateItem)
)
