//go:build darwin

package keychain

import "testing"

func TestSecOSStatusErr(t *testing.T) {
	if err := secOSStatusErr(errSecSuccess); err != nil {
		t.Errorf("wanted nil err, got: %v", err)
	}

	err := secOSStatusErr(errSecItemNotFound)
	if err == nil {
		t.Error("wanted err, got nil")
	}
	if err.Error() != "OSStatus error code -25300: The specified item could not be found in the keychain." {
		t.Errorf("unexpected message: %s", err.Error())
	}

	err = secOSStatusErr(_OSStatus(128000)) // hopefully not defined
	if err == nil {
		t.Error("wanted err, got nil")
	}
	if err.Error() != "OSStatus error code 128000: OSStatus 128000" {
		t.Errorf("unexpected message: %s", err.Error())
	}
}
