package keychain

import "fmt"

type ErrorCode int

const (
	ErrorCodeUnknown ErrorCode = iota
	ErrorCodeItemNotFound
	ErrorCodeDuplicateItem
)

type Error struct {
	message string
	code    ErrorCode
	cause   error
}

func (e *Error) Error() string {
	if e.message != "" {
		return e.message
	} else if e.cause != nil {
		return e.cause.Error()
	}
	return fmt.Sprintf("error code %d", e.code)
}

func (e *Error) Code() ErrorCode {
	return e.code
}

func (e *Error) Unwrap() error {
	return e.cause
}
