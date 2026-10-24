//go:build darwin

package keychain

import (
	"fmt"

	"lds.li/keychain/internal/corefoundation"
	"lds.li/keychain/internal/security"
)

// Accessible is a Keychain protection class (kSecAttrAccessible).
//
// ThisDeviceOnly classes cannot be used with a synchronizable PasswordStore.
type Accessible int

const (
	// AccessibleUnspecified leaves kSecAttrAccessible unset.
	AccessibleUnspecified Accessible = iota
	// AccessibleWhenUnlocked is kSecAttrAccessibleWhenUnlocked.
	AccessibleWhenUnlocked
	// AccessibleAfterFirstUnlock is kSecAttrAccessibleAfterFirstUnlock.
	AccessibleAfterFirstUnlock
	// AccessibleWhenUnlockedThisDeviceOnly prevents migration to another device.
	AccessibleWhenUnlockedThisDeviceOnly
	// AccessibleAfterFirstUnlockThisDeviceOnly permits use after the first unlock.
	AccessibleAfterFirstUnlockThisDeviceOnly
	// AccessibleWhenPasscodeSetThisDeviceOnly requires a device passcode.
	AccessibleWhenPasscodeSetThisDeviceOnly
)

// AccessControlFlag is a SecAccessControlCreateFlags value.
type AccessControlFlag uint64

const (
	// AccessControlUserPresence requires Touch ID or the device passcode.
	AccessControlUserPresence AccessControlFlag = 1 << 0
	// AccessControlBiometryAny requires any enrolled biometric identity.
	AccessControlBiometryAny AccessControlFlag = 1 << 1
	// AccessControlBiometryCurrentSet invalidates access when biometric enrollment changes.
	// Do not use it for synchronizable items.
	AccessControlBiometryCurrentSet AccessControlFlag = 1 << 3
	// AccessControlDevicePasscode requires the device passcode.
	AccessControlDevicePasscode AccessControlFlag = 1 << 4
	// AccessControlOr permits any of the specified authentication constraints.
	AccessControlOr AccessControlFlag = 1 << 14
	// AccessControlAnd requires all specified authentication constraints.
	AccessControlAnd AccessControlFlag = 1 << 15
)

// AccessControl sets protection and authentication rules for new items.
// ThisDeviceOnly protection and nonzero Flags cannot be used with a
// synchronizable PasswordStore.
//
// https://developer.apple.com/documentation/security/secaccesscontrolcreatewithflags
type AccessControl struct {
	Protection Accessible
	Flags      AccessControlFlag
}

func (a Accessible) thisDeviceOnly() bool {
	switch a {
	case AccessibleWhenUnlockedThisDeviceOnly, AccessibleAfterFirstUnlockThisDeviceOnly, AccessibleWhenPasscodeSetThisDeviceOnly:
		return true
	}
	return false
}

func accessibleRef(s *security.Framework, a Accessible) (corefoundation.StringRef, error) {
	switch a {
	case AccessibleUnspecified:
		return 0, nil
	case AccessibleWhenUnlocked:
		return s.AttrAccessibleWhenUnlocked, nil
	case AccessibleAfterFirstUnlock:
		return s.AttrAccessibleAfterFirstUnlock, nil
	case AccessibleWhenUnlockedThisDeviceOnly:
		return s.AttrAccessibleWhenUnlockedThisDeviceOnly, nil
	case AccessibleAfterFirstUnlockThisDeviceOnly:
		return s.AttrAccessibleAfterFirstUnlockThisDeviceOnly, nil
	case AccessibleWhenPasscodeSetThisDeviceOnly:
		return s.AttrAccessibleWhenPasscodeSetThisDeviceOnly, nil
	default:
		return 0, fmt.Errorf("unknown keychain accessible class %d", a)
	}
}

func createAccessControl(s *security.Framework, ac AccessControl) (security.SecAccessControlRef, error) {
	prot, err := accessibleRef(s, ac.Protection)
	if err != nil {
		return 0, err
	}
	if prot == 0 {
		return 0, fmt.Errorf("AccessControl.Protection is required")
	}
	var cfErr corefoundation.ErrorRef
	sac := s.AccessControlCreateWithFlags(corefoundation.AllocatorDefault, corefoundation.TypeRef(prot), uint64(ac.Flags), &cfErr)
	if sac == 0 {
		if cfErr != 0 {
			return 0, normalizeNativeError(s.ErrorFromCFError(cfErr))
		}
		return 0, fmt.Errorf("SecAccessControlCreateWithFlags failed")
	}
	if cfErr != 0 {
		_ = s.ErrorFromCFError(cfErr)
	}
	return sac, nil
}

func putBool(attrs map[corefoundation.TypeRef]corefoundation.TypeRef, key corefoundation.StringRef, v bool, cf *corefoundation.Framework) {
	if v {
		attrs[corefoundation.TypeRef(key)] = corefoundation.TypeRef(cf.BooleanTrue)
	} else {
		attrs[corefoundation.TypeRef(key)] = corefoundation.TypeRef(cf.BooleanFalse)
	}
}
