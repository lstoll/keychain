//go:build darwin

package keychain

import (
	"github.com/ebitengine/purego"
)

type (
	_SecIdentityRef uintptr
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
	_SecItemCopyMatching = registerFunc[func(query _CFDictionaryRef, res *_CFTypeRef) uintptr](security, "SecItemCopyMatching")
)
