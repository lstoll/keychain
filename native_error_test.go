//go:build darwin

package keychain

import (
	"errors"
	"fmt"
	"testing"

	"lds.li/keychain/internal/security"
)

func TestNormalizeNativeError(t *testing.T) {
	for _, tc := range []struct {
		status   security.OSStatus
		sentinel error
	}{
		{security.ErrSecItemNotFound, ErrItemNotFound},
		{security.ErrSecDuplicateItem, ErrDuplicateItem},
		{security.ErrSecParam, ErrParam},
	} {
		native := &security.NativeError{Domain: "NSOSStatusErrorDomain", Code: int64(tc.status), Description: "d"}
		err := fmt.Errorf("w: %w", normalizeNativeError(native))
		if !errors.Is(err, tc.sentinel) {
			t.Errorf("%d: want %v, got %v", tc.status, tc.sentinel, err)
		}
		var e *Error
		if !errors.As(err, &e) || e.Status() != int64(tc.status) || e.Domain() != "NSOSStatusErrorDomain" {
			t.Errorf("%d: bad fields: %#v", tc.status, e)
		}
	}

	ne := &security.NativeError{Domain: "NSOSStatusErrorDomain", Code: 128000, Description: "weird"}
	err := normalizeNativeError(ne)
	var e *Error
	if !errors.As(err, &e) || e.Code() != ErrorCodeUnknown || e.Status() != 128000 || !errors.Is(err, ne) {
		t.Fatalf("unknown: %#v", err)
	}
	for _, s := range allSentinels {
		if errors.Is(err, s) {
			t.Errorf("unknown matched %v", s)
		}
	}
	// A code outside OSStatus's range must not wrap into a known status.
	wide := &security.NativeError{Domain: "NSOSStatusErrorDomain", Code: int64(security.ErrSecItemNotFound) + 1<<32}
	if err := normalizeNativeError(wide); errors.Is(err, ErrItemNotFound) {
		t.Errorf("out-of-range code matched ErrItemNotFound: %v", err)
	}
	if normalizeNativeError(nil) != nil {
		t.Error("nil not preserved")
	}
}
