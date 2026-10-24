//go:build darwin

package keychain

import (
	"errors"
	"testing"

	"lds.li/keychain/internal/security"
)

func TestSecOSStatusErr(t *testing.T) {
	sec, err := security.Get()
	if err != nil {
		t.Fatal(err)
	}

	if err := newError(sec, security.ErrSecSuccess); err != nil {
		t.Errorf("wanted nil err, got: %v", err)
	}

	err = newError(sec, security.ErrSecItemNotFound)
	if !errors.Is(err, ErrItemNotFound) {
		t.Fatalf("wanted ErrItemNotFound, got: %v", err)
	}
	if err.Error() != "The specified item could not be found in the keychain." {
		t.Errorf("unexpected message: %s", err.Error())
	}

	err = newError(sec, security.OSStatus(128000)) // hopefully not defined
	var e *Error
	if !errors.As(err, &e) || e.Code() != ErrorCodeUnknown || e.Status() != 128000 {
		t.Fatalf("unexpected error: %#v", err)
	}
	if err.Error() != "NSOSStatusErrorDomain 128000: OSStatus 128000" {
		t.Errorf("unexpected message: %s", err.Error())
	}
}
