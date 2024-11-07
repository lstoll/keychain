//go:build darwin

package keychain

import (
	"fmt"

	"github.com/ebitengine/purego"
)

type (
	_SecIdentityRef uintptr
	_OSStatus       int32
)

const ( // https://gist.github.com/lefloh/3b4200a8eca40eb3c5596e6b6a7d83e5
	errSecSuccess      _OSStatus = 0
	errSecItemNotFound _OSStatus = -25300
)

var (
	security = dlopen("/System/Library/Frameworks/Security.framework/Security", purego.RTLD_LAZY|purego.RTLD_GLOBAL)

	kSecClassIdentity = dlsym(security, "kSecClassIdentity")
	kSecMatchLimitAll = dlsym(security, "kSecMatchLimitAll")
	kSecClass         = dlsym(security, "kSecClass")
	kSecReturnRef     = dlsym(security, "kSecReturnRef")
	kSecMatchLimit    = dlsym(security, "kSecMatchLimit")
)

var (
	_SecItemCopyMatching       = registerFunc[func(query _CFDictionaryRef, res *_CFTypeRef) _OSStatus](security, "SecItemCopyMatching")
	_SecCopyErrorMessageString = registerFunc[func(s _OSStatus, reserved uintptr) _CFStringRef](security, "SecCopyErrorMessageString")
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
