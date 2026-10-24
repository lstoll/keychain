//go:build darwin

package keychain

import (
	"errors"
	"math"

	"lds.li/keychain/internal/security"
)

// normalizeNativeError maps a security.NativeError to an *Error, keeping it as
// the cause. Other errors are returned unchanged.
func normalizeNativeError(err error) error {
	var e *security.NativeError
	if !errors.As(err, &e) {
		return err
	}
	code := ErrorCodeUnknown
	// OSStatus is 32-bit; a wider code can't match one, and would wrap if converted.
	if e.Domain == "NSOSStatusErrorDomain" && e.Code >= math.MinInt32 && e.Code <= math.MaxInt32 {
		switch security.OSStatus(e.Code) {
		case security.ErrSecItemNotFound:
			code = ErrorCodeItemNotFound
		case security.ErrSecDuplicateItem:
			code = ErrorCodeDuplicateItem
		case security.ErrSecMissingEntitlement:
			code = ErrorCodeMissingEntitlement
		case security.ErrSecAuthFailed:
			code = ErrorCodeAuthFailed
		case security.ErrSecUserCanceled:
			code = ErrorCodeUserCanceled
		case security.ErrSecInteractionNotAllowed:
			code = ErrorCodeInteractionNotAllowed
		case security.ErrSecParam:
			code = ErrorCodeParam
		}
	}
	return &Error{code: code, message: e.Description, domain: e.Domain, status: e.Code, cause: err}
}

// newError maps an OSStatus from a Security.framework call to an *Error, or nil
// for errSecSuccess.
func newError(sec *security.Framework, status security.OSStatus) error {
	return normalizeNativeError(sec.StatusError(status))
}
