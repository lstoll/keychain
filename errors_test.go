package keychain

import (
	"errors"
	"fmt"
	"testing"
)

var allSentinels = map[ErrorCode]*Error{
	ErrorCodeItemNotFound:          ErrItemNotFound,
	ErrorCodeDuplicateItem:         ErrDuplicateItem,
	ErrorCodeMissingEntitlement:    ErrMissingEntitlement,
	ErrorCodeAuthFailed:            ErrAuthFailed,
	ErrorCodeUserCanceled:          ErrUserCanceled,
	ErrorCodeInteractionNotAllowed: ErrInteractionNotAllowed,
	ErrorCodeParam:                 ErrParam,
}

func TestErrorIs(t *testing.T) {
	for code, sentinel := range allSentinels {
		err := fmt.Errorf("wrapped: %w", &Error{code: code, message: "msg", domain: "d", status: 5})
		if !errors.Is(err, sentinel) {
			t.Errorf("%v: want match", code)
		}
		for other, os := range allSentinels {
			if other != code && errors.Is(err, os) {
				t.Errorf("%v matched %v", code, other)
			}
		}
	}
}

func TestErrorIsUnknown(t *testing.T) {
	unknown := &Error{code: ErrorCodeUnknown, domain: "d", status: 1}
	for _, s := range allSentinels {
		if errors.Is(unknown, s) {
			t.Errorf("unknown matched %v", s.Code())
		}
	}
	if errors.Is(unknown, &Error{}) {
		t.Error("unknown matched empty Error")
	}
	if errors.Is(fmt.Errorf("w: %w", unknown), unknown) != true {
		t.Error("identity match should still work")
	}
	// A non-sentinel target never matches by code.
	if errors.Is(&Error{code: ErrorCodeParam}, &Error{code: ErrorCodeParam, message: "x"}) {
		t.Error("non-sentinel target matched")
	}
}

func TestErrorAccessors(t *testing.T) {
	e := &Error{code: ErrorCodeUnknown, message: "boom", domain: "NSOSStatusErrorDomain", status: -25291}
	if e.Domain() != "NSOSStatusErrorDomain" || e.Status() != -25291 {
		t.Errorf("accessors: %q %d", e.Domain(), e.Status())
	}
	if got, want := e.Error(), "NSOSStatusErrorDomain -25291: boom"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
	if got, want := ErrItemNotFound.Error(), "keychain: item not found"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
	if got := (&Error{code: ErrorCodeParam, message: "native"}).Error(); got != "native" {
		t.Errorf("Error() = %q", got)
	}
	if ErrItemNotFound.Domain() != "" || ErrItemNotFound.Status() != 0 {
		t.Error("sentinel has native info")
	}
}

func TestErrorCodeString(t *testing.T) {
	for code, want := range map[ErrorCode]string{
		ErrorCodeUnknown:               "unknown",
		ErrorCodeItemNotFound:          "item not found",
		ErrorCodeDuplicateItem:         "duplicate item",
		ErrorCodeMissingEntitlement:    "missing entitlement",
		ErrorCodeAuthFailed:            "authentication failed",
		ErrorCodeUserCanceled:          "user canceled",
		ErrorCodeInteractionNotAllowed: "interaction not allowed",
		ErrorCodeParam:                 "invalid parameter",
		ErrorCode(999):                 "unknown",
	} {
		if got := code.String(); got != want {
			t.Errorf("%d: %q, want %q", code, got, want)
		}
	}
}
