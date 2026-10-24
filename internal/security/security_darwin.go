//go:build darwin

package security

import (
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
	cf "lds.li/keychain/internal/corefoundation"
)

type (
	SecKeychainItemRef  uintptr
	SecIdentityRef      uintptr
	SecCertificateRef   uintptr
	SecTrustRef         uintptr
	SecPolicyRef        uintptr
	OSStatus            int32
	SecKeyRef           uintptr
	SecCodeRef          uintptr
	SecStaticCodeRef    uintptr
	SecAccessControlRef uintptr
	SecKeyAlgorithm     cf.StringRef
)

const ( // https://gist.github.com/lefloh/3b4200a8eca40eb3c5596e6b6a7d83e5
	ErrSecSuccess               OSStatus = 0
	ErrSecUnimplemented         OSStatus = -4
	ErrSecParam                 OSStatus = -50
	ErrSecUserCanceled          OSStatus = -128
	ErrSecAuthFailed            OSStatus = -25293
	ErrSecDuplicateItem         OSStatus = -25299
	ErrSecItemNotFound          OSStatus = -25300
	ErrSecInteractionNotAllowed OSStatus = -25308
	ErrSecMissingEntitlement    OSStatus = -34018
)

const (
	SecCSDefaultFlags       = 0
	SecCSSigningInformation = 1 << 1
)

type Framework struct {
	CoreFoundation *cf.Framework

	SecKeychainItemModifyAttributesAndData func(item SecKeychainItemRef, attributes unsafe.Pointer, length uint32, data *byte) OSStatus
	SecKeychainItemDelete                  func(item SecKeychainItemRef) OSStatus

	AttrAccessibleAfterFirstUnlockThisDeviceOnly cf.StringRef
	AttrAccessibleWhenPasscodeSetThisDeviceOnly  cf.StringRef
	AttrKeyType                                  cf.StringRef
	AttrKeyClass                                 cf.StringRef
	AttrKeyClassPrivate                          cf.StringRef
	AttrKeyTypeECSECPrimeRandom                  cf.StringRef
	AttrTokenIDSecureEnclave                     cf.StringRef
	AttrIsPermanent                              cf.StringRef
	PrivateKeyAttrs                              cf.StringRef
	AttrAccessibleWhenUnlockedThisDeviceOnly     cf.StringRef

	ClassIdentity                    cf.StringRef
	ClassCertificate                 cf.StringRef
	ClassKey                         cf.StringRef
	ClassGenericPassword             cf.StringRef
	MatchLimitAll                    cf.StringRef
	MatchLimitOne                    cf.StringRef
	Class                            cf.StringRef
	ReturnRef                        cf.StringRef
	ReturnAttributes                 cf.StringRef
	ReturnData                       cf.StringRef
	MatchLimit                       cf.StringRef
	AttrAccount                      cf.StringRef
	AttrService                      cf.StringRef
	AttrLabel                        cf.StringRef
	AttrGeneric                      cf.StringRef
	ValueData                        cf.StringRef
	AttrTokenID                      cf.StringRef
	AttrApplicationLabel             cf.StringRef
	AttrKeySizeInBits                cf.StringRef
	ValueRef                         cf.StringRef
	AttrSynchronizable               cf.StringRef
	AttrSynchronizableAny            cf.StringRef
	AttrAccessible                   cf.StringRef
	AttrAccessibleWhenUnlocked       cf.StringRef
	AttrAccessibleAfterFirstUnlock   cf.StringRef
	UseDataProtectionKeychain        cf.StringRef
	AttrAccessGroup                  cf.StringRef
	AttrAccessControl                cf.StringRef
	UseAuthenticationContext         cf.StringRef
	CodeInfoTeamIdentifier           cf.StringRef
	CodeInfoCdHashes                 cf.StringRef
	CodeInfoDigestAlgorithms         cf.StringRef
	CodeSignatureHashSHA1            int32
	CodeSignatureHashSHA256          int32
	CodeSignatureHashSHA256Truncated int32
	CodeSignatureHashSHA384          int32
	CodeSignatureHashSHA512          int32

	KeyAlgorithmECDSASignatureDigestX962SHA256 SecKeyAlgorithm
	KeyAlgorithmECDSASignatureDigestX962SHA384 SecKeyAlgorithm
	KeyAlgorithmECDSASignatureDigestX962SHA512 SecKeyAlgorithm

	AttrKeyTypeMLDSA                  cf.StringRef
	AttrKeySizeMLDSA65                cf.StringRef
	AttrKeySizeMLDSA87                cf.StringRef
	KeyAlgorithmMLDSASignatureMessage SecKeyAlgorithm
	KeySignatureParameterContext      cf.StringRef
	KeyCreateMLDSASignature           MLDSASignatureFunc

	KeyCreateRandomKey      func(parameters cf.DictionaryRef, errOut *cf.ErrorRef) SecKeyRef
	KeyCreateWithData       func(data cf.DataRef, parameters cf.DictionaryRef, errOut *cf.ErrorRef) SecKeyRef
	KeyIsAlgorithmSupported func(key SecKeyRef, operation cf.Index, algorithm SecKeyAlgorithm) bool

	ItemCopyMatching               func(query cf.DictionaryRef, res *cf.TypeRef) OSStatus
	ItemAdd                        func(attributes cf.DictionaryRef, result *cf.TypeRef) OSStatus
	ItemUpdate                     func(query cf.DictionaryRef, attributes cf.DictionaryRef) OSStatus
	ItemDelete                     func(query cf.DictionaryRef) OSStatus
	AccessControlCreateWithFlags   func(allocator cf.AllocatorRef, protection cf.TypeRef, flags uint64, err *cf.ErrorRef) SecAccessControlRef
	CopyErrorMessageString         func(s OSStatus, reserved uintptr) cf.StringRef
	CodeCopySelf                   func(flags uint32, code *SecCodeRef) OSStatus
	CodeCheckValidity              func(code SecCodeRef, flags uint32, requirement cf.TypeRef) OSStatus
	CodeCopySigningInformation     func(code SecStaticCodeRef, flags uint32, information *cf.DictionaryRef) OSStatus
	KeyCopyAttributes              func(key SecKeyRef) cf.DictionaryRef
	KeyCopyPublicKey               func(key SecKeyRef) SecKeyRef
	KeyCopyExternalRepresentation  func(key SecKeyRef, errOut *cf.ErrorRef) cf.DataRef
	KeyCreateSignature             func(key SecKeyRef, algorithm SecKeyAlgorithm, signedData cf.DataRef, errOut *cf.ErrorRef) cf.DataRef
	IdentityCopyPrivateKey         func(identity SecIdentityRef, privateKey *SecKeyRef) OSStatus
	IdentityCopyCertificate        func(identity SecIdentityRef, certificate *SecCertificateRef) OSStatus
	CertificateCopyData            func(certificate SecCertificateRef) cf.DataRef
	CertificateCreateWithData      func(allocator cf.AllocatorRef, data cf.DataRef) SecCertificateRef
	PolicyCreateBasicX509          func() SecPolicyRef
	PolicyCreateSSL                func(server uint8, hostname cf.StringRef) SecPolicyRef
	TrustCreateWithCertificates    func(certificates cf.ArrayRef, policies cf.ArrayRef, trust *SecTrustRef) OSStatus
	TrustSetNetworkFetchAllowed    func(trust SecTrustRef, allowed uint8) OSStatus
	TrustSetAnchorCertificates     func(trust SecTrustRef, anchorCertificates cf.ArrayRef) OSStatus
	TrustSetAnchorCertificatesOnly func(trust SecTrustRef, anchorOnly uint8) OSStatus
	TrustEvaluateWithError         func(trust SecTrustRef, errOut *cf.ErrorRef) bool
	TrustCopyCertificateChain      func(trust SecTrustRef) cf.ArrayRef
}

var (
	framework     *Framework
	frameworkErr  error
	frameworkOnce sync.Once
)

func Get() (*Framework, error) {
	frameworkOnce.Do(func() {
		handle, err := dlopen("/System/Library/Frameworks/Security.framework/Security", purego.RTLD_LAZY|purego.RTLD_GLOBAL)
		if err != nil {
			frameworkErr = err
			return
		}

		core, err := cf.Get()
		if err != nil {
			frameworkErr = err
			return
		}
		s := &Framework{CoreFoundation: core}

		// Constants
		var val uintptr
		if val, err = constsym(handle, "kSecClassIdentity"); err == nil {
			s.ClassIdentity = cf.StringRef(val)
		} else {
			frameworkErr = err
			return
		}
		if val, err = constsym(handle, "kSecClassGenericPassword"); err == nil {
			s.ClassGenericPassword = cf.StringRef(val)
		} else {
			frameworkErr = err
			return
		}
		if val, err = constsym(handle, "kSecMatchLimitAll"); err == nil {
			s.MatchLimitAll = cf.StringRef(val)
		} else {
			frameworkErr = err
			return
		}
		if val, err = constsym(handle, "kSecMatchLimitOne"); err == nil {
			s.MatchLimitOne = cf.StringRef(val)
		} else {
			frameworkErr = err
			return
		}
		if val, err = constsym(handle, "kSecClass"); err == nil {
			s.Class = cf.StringRef(val)
		} else {
			frameworkErr = err
			return
		}
		if val, err = constsym(handle, "kSecReturnRef"); err == nil {
			s.ReturnRef = cf.StringRef(val)
		} else {
			frameworkErr = err
			return
		}
		if val, err = constsym(handle, "kSecReturnAttributes"); err == nil {
			s.ReturnAttributes = cf.StringRef(val)
		} else {
			frameworkErr = err
			return
		}
		if val, err = constsym(handle, "kSecReturnData"); err == nil {
			s.ReturnData = cf.StringRef(val)
		} else {
			frameworkErr = err
			return
		}
		if val, err = constsym(handle, "kSecMatchLimit"); err == nil {
			s.MatchLimit = cf.StringRef(val)
		} else {
			frameworkErr = err
			return
		}
		if val, err = constsym(handle, "kSecAttrAccount"); err == nil {
			s.AttrAccount = cf.StringRef(val)
		} else {
			frameworkErr = err
			return
		}
		if val, err = constsym(handle, "kSecAttrService"); err == nil {
			s.AttrService = cf.StringRef(val)
		} else {
			frameworkErr = err
			return
		}
		if val, err = constsym(handle, "kSecAttrLabel"); err == nil {
			s.AttrLabel = cf.StringRef(val)
		} else {
			frameworkErr = err
			return
		}
		if val, err = constsym(handle, "kSecAttrGeneric"); err == nil {
			s.AttrGeneric = cf.StringRef(val)
		} else {
			frameworkErr = err
			return
		}
		if val, err = constsym(handle, "kSecValueData"); err == nil {
			s.ValueData = cf.StringRef(val)
		} else {
			frameworkErr = err
			return
		}
		if val, err = constsym(handle, "kSecAttrTokenID"); err == nil {
			s.AttrTokenID = cf.StringRef(val)
		} else {
			frameworkErr = err
			return
		}
		if val, err = constsym(handle, "kSecAttrApplicationLabel"); err == nil {
			s.AttrApplicationLabel = cf.StringRef(val)
		} else {
			frameworkErr = err
			return
		}
		if val, err = constsym(handle, "kSecAttrKeySizeInBits"); err == nil {
			s.AttrKeySizeInBits = cf.StringRef(val)
		} else {
			frameworkErr = err
			return
		}
		if val, err = constsym(handle, "kSecValueRef"); err == nil {
			s.ValueRef = cf.StringRef(val)
		} else {
			frameworkErr = err
			return
		}
		if val, err = constsym(handle, "kSecCodeInfoCdHashes"); err == nil {
			s.CodeInfoCdHashes = cf.StringRef(val)
		} else {
			frameworkErr = err
			return
		}
		if val, err = constsym(handle, "kSecCodeInfoDigestAlgorithms"); err == nil {
			s.CodeInfoDigestAlgorithms = cf.StringRef(val)
		} else {
			frameworkErr = err
			return
		}
		for _, item := range []struct {
			name string
			dest *cf.StringRef
		}{
			{"kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly", &s.AttrAccessibleAfterFirstUnlockThisDeviceOnly},
			{"kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly", &s.AttrAccessibleWhenPasscodeSetThisDeviceOnly},
			{"kSecClassCertificate", &s.ClassCertificate},
			{"kSecClassKey", &s.ClassKey},
			{"kSecAttrKeyType", &s.AttrKeyType},
			{"kSecAttrKeyClass", &s.AttrKeyClass},
			{"kSecAttrKeyClassPrivate", &s.AttrKeyClassPrivate},
			{"kSecAttrKeyTypeECSECPrimeRandom", &s.AttrKeyTypeECSECPrimeRandom},
			{"kSecAttrTokenIDSecureEnclave", &s.AttrTokenIDSecureEnclave},
			{"kSecAttrIsPermanent", &s.AttrIsPermanent},
			{"kSecPrivateKeyAttrs", &s.PrivateKeyAttrs},
			{"kSecAttrAccessibleWhenUnlockedThisDeviceOnly", &s.AttrAccessibleWhenUnlockedThisDeviceOnly},
			{"kSecAttrSynchronizable", &s.AttrSynchronizable},
			{"kSecAttrSynchronizableAny", &s.AttrSynchronizableAny},
			{"kSecAttrAccessible", &s.AttrAccessible},
			{"kSecAttrAccessibleWhenUnlocked", &s.AttrAccessibleWhenUnlocked},
			{"kSecAttrAccessibleAfterFirstUnlock", &s.AttrAccessibleAfterFirstUnlock},
			{"kSecUseDataProtectionKeychain", &s.UseDataProtectionKeychain},
			{"kSecAttrAccessGroup", &s.AttrAccessGroup},
			{"kSecAttrAccessControl", &s.AttrAccessControl},
			{"kSecUseAuthenticationContext", &s.UseAuthenticationContext},
			{"kSecCodeInfoTeamIdentifier", &s.CodeInfoTeamIdentifier},
		} {
			if *item.dest, err = loadCFString(handle, item.name); err != nil {
				frameworkErr = err
				return
			}
		}

		s.CodeSignatureHashSHA1 = 1
		s.CodeSignatureHashSHA256 = 2
		s.CodeSignatureHashSHA256Truncated = 3
		s.CodeSignatureHashSHA384 = 4
		s.CodeSignatureHashSHA512 = 5

		if val, err = constsym(handle, "kSecKeyAlgorithmECDSASignatureDigestX962SHA256"); err == nil {
			s.KeyAlgorithmECDSASignatureDigestX962SHA256 = SecKeyAlgorithm(val)
		} else {
			frameworkErr = err
			return
		}
		if val, err = constsym(handle, "kSecKeyAlgorithmECDSASignatureDigestX962SHA384"); err == nil {
			s.KeyAlgorithmECDSASignatureDigestX962SHA384 = SecKeyAlgorithm(val)
		} else {
			frameworkErr = err
			return
		}
		if val, err = constsym(handle, "kSecKeyAlgorithmECDSASignatureDigestX962SHA512"); err == nil {
			s.KeyAlgorithmECDSASignatureDigestX962SHA512 = SecKeyAlgorithm(val)
		} else {
			frameworkErr = err
			return
		}

		// Functions
		if s.SecKeychainItemModifyAttributesAndData, err = registerFunc[func(item SecKeychainItemRef, attributes unsafe.Pointer, length uint32, data *byte) OSStatus](handle, "SecKeychainItemModifyAttributesAndData"); err != nil {
			frameworkErr = err
			return
		}
		if s.SecKeychainItemDelete, err = registerFunc[func(item SecKeychainItemRef) OSStatus](handle, "SecKeychainItemDelete"); err != nil {
			frameworkErr = err
			return
		}
		if s.KeyCreateRandomKey, err = registerFunc[func(cf.DictionaryRef, *cf.ErrorRef) SecKeyRef](handle, "SecKeyCreateRandomKey"); err != nil {
			frameworkErr = err
			return
		}
		if s.KeyCreateWithData, err = registerFunc[func(cf.DataRef, cf.DictionaryRef, *cf.ErrorRef) SecKeyRef](handle, "SecKeyCreateWithData"); err != nil {
			frameworkErr = err
			return
		}
		if s.KeyIsAlgorithmSupported, err = registerFunc[func(SecKeyRef, cf.Index, SecKeyAlgorithm) bool](handle, "SecKeyIsAlgorithmSupported"); err != nil {
			frameworkErr = err
			return
		}
		if s.ItemCopyMatching, err = registerFunc[func(query cf.DictionaryRef, res *cf.TypeRef) OSStatus](handle, "SecItemCopyMatching"); err != nil {
			frameworkErr = err
			return
		}
		if s.ItemAdd, err = registerFunc[func(attributes cf.DictionaryRef, result *cf.TypeRef) OSStatus](handle, "SecItemAdd"); err != nil {
			frameworkErr = err
			return
		}
		if s.ItemUpdate, err = registerFunc[func(query cf.DictionaryRef, attributes cf.DictionaryRef) OSStatus](handle, "SecItemUpdate"); err != nil {
			frameworkErr = err
			return
		}
		if s.ItemDelete, err = registerFunc[func(query cf.DictionaryRef) OSStatus](handle, "SecItemDelete"); err != nil {
			frameworkErr = err
			return
		}
		if s.AccessControlCreateWithFlags, err = registerFunc[func(allocator cf.AllocatorRef, protection cf.TypeRef, flags uint64, err *cf.ErrorRef) SecAccessControlRef](handle, "SecAccessControlCreateWithFlags"); err != nil {
			frameworkErr = err
			return
		}
		if s.CopyErrorMessageString, err = registerFunc[func(s OSStatus, reserved uintptr) cf.StringRef](handle, "SecCopyErrorMessageString"); err != nil {
			frameworkErr = err
			return
		}
		if s.CodeCopySelf, err = registerFunc[func(flags uint32, code *SecCodeRef) OSStatus](handle, "SecCodeCopySelf"); err != nil {
			frameworkErr = err
			return
		}
		if s.CodeCheckValidity, err = registerFunc[func(code SecCodeRef, flags uint32, requirement cf.TypeRef) OSStatus](handle, "SecCodeCheckValidity"); err != nil {
			frameworkErr = err
			return
		}
		if s.CodeCopySigningInformation, err = registerFunc[func(code SecStaticCodeRef, flags uint32, information *cf.DictionaryRef) OSStatus](handle, "SecCodeCopySigningInformation"); err != nil {
			frameworkErr = err
			return
		}
		if s.KeyCopyAttributes, err = registerFunc[func(key SecKeyRef) cf.DictionaryRef](handle, "SecKeyCopyAttributes"); err != nil {
			frameworkErr = err
			return
		}
		if s.KeyCopyPublicKey, err = registerFunc[func(key SecKeyRef) SecKeyRef](handle, "SecKeyCopyPublicKey"); err != nil {
			frameworkErr = err
			return
		}
		if s.KeyCopyExternalRepresentation, err = registerFunc[func(key SecKeyRef, errOut *cf.ErrorRef) cf.DataRef](handle, "SecKeyCopyExternalRepresentation"); err != nil {
			frameworkErr = err
			return
		}
		if s.KeyCreateSignature, err = registerFunc[func(key SecKeyRef, algorithm SecKeyAlgorithm, signedData cf.DataRef, errOut *cf.ErrorRef) cf.DataRef](handle, "SecKeyCreateSignature"); err != nil {
			frameworkErr = err
			return
		}
		if s.IdentityCopyPrivateKey, err = registerFunc[func(identity SecIdentityRef, privateKey *SecKeyRef) OSStatus](handle, "SecIdentityCopyPrivateKey"); err != nil {
			frameworkErr = err
			return
		}
		if s.IdentityCopyCertificate, err = registerFunc[func(identity SecIdentityRef, certificate *SecCertificateRef) OSStatus](handle, "SecIdentityCopyCertificate"); err != nil {
			frameworkErr = err
			return
		}
		if s.CertificateCopyData, err = registerFunc[func(certificate SecCertificateRef) cf.DataRef](handle, "SecCertificateCopyData"); err != nil {
			frameworkErr = err
			return
		}
		if s.CertificateCreateWithData, err = registerFunc[func(allocator cf.AllocatorRef, data cf.DataRef) SecCertificateRef](handle, "SecCertificateCreateWithData"); err != nil {
			frameworkErr = err
			return
		}
		if s.PolicyCreateBasicX509, err = registerFunc[func() SecPolicyRef](handle, "SecPolicyCreateBasicX509"); err != nil {
			frameworkErr = err
			return
		}
		if s.PolicyCreateSSL, err = registerFunc[func(server uint8, hostname cf.StringRef) SecPolicyRef](handle, "SecPolicyCreateSSL"); err != nil {
			frameworkErr = err
			return
		}
		if s.TrustCreateWithCertificates, err = registerFunc[func(certificates cf.ArrayRef, policies cf.ArrayRef, trust *SecTrustRef) OSStatus](handle, "SecTrustCreateWithCertificates"); err != nil {
			frameworkErr = err
			return
		}
		if s.TrustSetNetworkFetchAllowed, err = registerFunc[func(trust SecTrustRef, allowed uint8) OSStatus](handle, "SecTrustSetNetworkFetchAllowed"); err != nil {
			frameworkErr = err
			return
		}
		if s.TrustSetAnchorCertificates, err = registerFunc[func(trust SecTrustRef, anchorCertificates cf.ArrayRef) OSStatus](handle, "SecTrustSetAnchorCertificates"); err != nil {
			frameworkErr = err
			return
		}
		if s.TrustSetAnchorCertificatesOnly, err = registerFunc[func(trust SecTrustRef, anchorOnly uint8) OSStatus](handle, "SecTrustSetAnchorCertificatesOnly"); err != nil {
			frameworkErr = err
			return
		}
		if s.TrustEvaluateWithError, err = registerFunc[func(trust SecTrustRef, errOut *cf.ErrorRef) bool](handle, "SecTrustEvaluateWithError"); err != nil {
			frameworkErr = err
			return
		}
		if s.TrustCopyCertificateChain, err = registerFunc[func(trust SecTrustRef) cf.ArrayRef](handle, "SecTrustCopyCertificateChain"); err != nil {
			frameworkErr = err
			return
		}

		loadOptionalMLDSASymbols(
			s,
			func(name string) (uintptr, error) { return constsym(handle, name) },
			func() (uintptr, error) { return purego.Dlsym(handle, "SecKeyCreateMLDSASignature") },
			func(symbol uintptr) (MLDSASignatureFunc, error) {
				var fn MLDSASignatureFunc
				purego.RegisterFunc(&fn, symbol)
				return fn, nil
			},
		)

		framework = s
	})

	return framework, frameworkErr
}

func loadCFString(handle uintptr, name string) (cf.StringRef, error) {
	val, err := constsym(handle, name)
	if err != nil {
		return 0, err
	}
	return cf.StringRef(val), nil
}

type MLDSASignatureFunc func(key SecKeyRef, algorithm SecKeyAlgorithm, signedData cf.DataRef, parameters cf.DictionaryRef, errOut *cf.ErrorRef) cf.DataRef

// loadOptionalMLDSASymbols deliberately ignores missing symbols so older OS
// releases retain all their non-ML-DSA functionality.
func loadOptionalMLDSASymbols(
	s *Framework,
	lookupConstant func(name string) (uintptr, error),
	lookupFunction func() (uintptr, error),
	registerFunction func(symbol uintptr) (MLDSASignatureFunc, error),
) {
	constants := []struct {
		name string
		dest *cf.TypeRef
	}{
		{"kSecAttrKeyTypeMLDSA", (*cf.TypeRef)(&s.AttrKeyTypeMLDSA)},
		{"kSecAttrKeySizeMLDSA65", (*cf.TypeRef)(&s.AttrKeySizeMLDSA65)},
		{"kSecAttrKeySizeMLDSA87", (*cf.TypeRef)(&s.AttrKeySizeMLDSA87)},
		{"kSecKeyAlgorithmMLDSASignatureMessage", (*cf.TypeRef)(&s.KeyAlgorithmMLDSASignatureMessage)},
		{"kSecKeySignatureParameterContext", (*cf.TypeRef)(&s.KeySignatureParameterContext)},
	}
	for _, item := range constants {
		if value, err := lookupConstant(item.name); err == nil {
			*item.dest = cf.TypeRef(value)
		}
	}
	if symbol, err := lookupFunction(); err == nil {
		if fn, err := registerFunction(symbol); err == nil {
			s.KeyCreateMLDSASignature = fn
		}
	}
}

// SupportsMLDSA reports whether the requested parameter set has all required
// Security.framework symbols available on the current operating system.
func (f *Framework) SupportsMLDSA(parameterSet int) bool {
	if f == nil || f.AttrKeyTypeMLDSA == 0 || f.KeyAlgorithmMLDSASignatureMessage == 0 {
		return false
	}
	switch parameterSet {
	case 65:
		return f.AttrKeySizeMLDSA65 != 0
	case 87:
		return f.AttrKeySizeMLDSA87 != 0
	default:
		return false
	}
}

// SupportsMLDSAContext reports whether Security.framework supports the context
// parameter for ML-DSA message signatures.
func (f *Framework) SupportsMLDSAContext() bool {
	return f != nil && f.KeySignatureParameterContext != 0 && f.KeyCreateMLDSASignature != nil
}
