//go:build darwin

package keychain

import "fmt"

// Bool returns a pointer to b for optional Keychain boolean attributes.
func Bool(b bool) *bool {
	return &b
}

// Accessible is a Keychain protection class (kSecAttrAccessible).
//
// Do not use ThisDeviceOnly classes with Synchronizable items; they cannot sync.
type Accessible int

const (
	// AccessibleUnspecified leaves kSecAttrAccessible unset.
	AccessibleUnspecified Accessible = iota
	// AccessibleWhenUnlocked is kSecAttrAccessibleWhenUnlocked.
	AccessibleWhenUnlocked
	// AccessibleAfterFirstUnlock is kSecAttrAccessibleAfterFirstUnlock.
	AccessibleAfterFirstUnlock
)

// AccessControlFlag is a SecAccessControlCreateFlags value.
type AccessControlFlag uint64

const (
	// AccessControlUserPresence requires Touch ID or the device passcode.
	// Do not use biometryCurrentSet: fingerprint sets are per-device and break after iCloud sync.
	AccessControlUserPresence AccessControlFlag = 1 << 0
)

// AccessControl is stored as kSecAttrAccessControl. Do not also set Accessible
// on the same add; the protection class belongs here.
//
// https://developer.apple.com/documentation/security/secaccesscontrolcreatewithflags
type AccessControl struct {
	Protection Accessible
	Flags      AccessControlFlag
}

func (s *securityFramework) accessibleRef(a Accessible) (_CFStringRef, error) {
	switch a {
	case AccessibleUnspecified:
		return 0, nil
	case AccessibleWhenUnlocked:
		return s.AttrAccessibleWhenUnlocked, nil
	case AccessibleAfterFirstUnlock:
		return s.AttrAccessibleAfterFirstUnlock, nil
	default:
		return 0, fmt.Errorf("unknown keychain accessible class %d", a)
	}
}

func (s *securityFramework) createAccessControl(cf *coreFoundation, ac AccessControl) (_SecAccessControlRef, error) {
	prot, err := s.accessibleRef(ac.Protection)
	if err != nil {
		return 0, err
	}
	if prot == 0 {
		return 0, fmt.Errorf("AccessControl.Protection is required")
	}
	var cfErr _CFErrorRef
	sac := s.AccessControlCreateWithFlags(kCFAllocatorDefault, _CFTypeRef(prot), uint64(ac.Flags), &cfErr)
	if sac == 0 {
		msg := "SecAccessControlCreateWithFlags failed"
		if cfErr != 0 {
			desc := cf.ErrorCopyDescription(cfErr)
			msg = cf.CFStringToString(desc)
			cf.Release(_CFTypeRef(desc))
			cf.Release(_CFTypeRef(cfErr))
		}
		return 0, fmt.Errorf("%s", msg)
	}
	return sac, nil
}

func putOptionalBool(attrs map[_CFTypeRef]_CFTypeRef, key _CFStringRef, v *bool, cf *coreFoundation) {
	if v == nil {
		return
	}
	if *v {
		attrs[_CFTypeRef(key)] = _CFTypeRef(cf.BooleanTrue)
	} else {
		attrs[_CFTypeRef(key)] = _CFTypeRef(cf.BooleanFalse)
	}
}
