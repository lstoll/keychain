package keychain

import "fmt"

// ErrorCode classifies an Error. Use errors.Is with the Err* sentinels to
// test for a specific code.
type ErrorCode int

const (
	// ErrorCodeUnknown is an error with no specific mapping; see Error.Domain and Error.Status.
	ErrorCodeUnknown ErrorCode = iota
	// ErrorCodeItemNotFound means the item does not exist.
	ErrorCodeItemNotFound
	// ErrorCodeDuplicateItem means the item already exists.
	ErrorCodeDuplicateItem
	// ErrorCodeMissingEntitlement means the process lacks a required entitlement.
	ErrorCodeMissingEntitlement
	// ErrorCodeAuthFailed means authentication failed.
	ErrorCodeAuthFailed
	// ErrorCodeUserCanceled means the user canceled the operation.
	ErrorCodeUserCanceled
	// ErrorCodeInteractionNotAllowed means user interaction was required but not allowed.
	ErrorCodeInteractionNotAllowed
	// ErrorCodeParam means an invalid parameter was passed.
	ErrorCodeParam
)

// String returns a short description of the code.
func (c ErrorCode) String() string {
	switch c {
	case ErrorCodeItemNotFound:
		return "item not found"
	case ErrorCodeDuplicateItem:
		return "duplicate item"
	case ErrorCodeMissingEntitlement:
		return "missing entitlement"
	case ErrorCodeAuthFailed:
		return "authentication failed"
	case ErrorCodeUserCanceled:
		return "user canceled"
	case ErrorCodeInteractionNotAllowed:
		return "interaction not allowed"
	case ErrorCodeParam:
		return "invalid parameter"
	default:
		return "unknown"
	}
}

// Sentinels for use with errors.Is. They match any *Error with the same code.
var (
	ErrItemNotFound          = &Error{code: ErrorCodeItemNotFound}
	ErrDuplicateItem         = &Error{code: ErrorCodeDuplicateItem}
	ErrMissingEntitlement    = &Error{code: ErrorCodeMissingEntitlement}
	ErrAuthFailed            = &Error{code: ErrorCodeAuthFailed}
	ErrUserCanceled          = &Error{code: ErrorCodeUserCanceled}
	ErrInteractionNotAllowed = &Error{code: ErrorCodeInteractionNotAllowed}
	ErrParam                 = &Error{code: ErrorCodeParam}
)

// Error is the error type returned for Keychain, Security and
// LocalAuthentication failures.
type Error struct {
	message string
	code    ErrorCode
	cause   error
	domain  string
	status  int64
}

// Error implements error.
func (e *Error) Error() string {
	if e.code == ErrorCodeUnknown && e.status != 0 {
		s := fmt.Sprintf("%s %d", e.domain, e.status)
		if e.message != "" {
			s += ": " + e.message
		}
		return s
	}
	if e.message != "" {
		return e.message
	}
	if e.cause != nil {
		return e.cause.Error()
	}
	return "keychain: " + e.code.String()
}

// Code returns the error classification.
func (e *Error) Code() ErrorCode {
	return e.code
}

// Domain returns the native error domain, such as "NSOSStatusErrorDomain" or
// "com.apple.LocalAuthentication". It is empty if there is none.
func (e *Error) Domain() string { return e.domain }

// Status returns the raw native code (OSStatus, CFError or LAError code), or 0.
func (e *Error) Status() int64 { return e.status }

// Unwrap returns the underlying cause, if any.
func (e *Error) Unwrap() error {
	return e.cause
}

// Is reports whether target is a sentinel (such as ErrItemNotFound) with the
// same, known code.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	if !ok || t.message != "" || t.cause != nil || t.domain != "" || t.status != 0 {
		return false
	}
	return t.code != ErrorCodeUnknown && t.code == e.code
}
