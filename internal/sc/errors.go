package sc

import (
	"errors"
)

// Failure supplies stable operator-safe machine classification without
// exposing raw profile URIs, file paths or transport credential URLs.
type Failure struct {
	Code    string
	Message string
}

func (e *Failure) Error() string       { return e.Message }
func Fault(code, message string) error { return &Failure{Code: code, Message: message} }
func ErrorCode(err error) string {
	if err == nil {
		return ""
	}
	var failure *Failure
	if errors.As(err, &failure) {
		return failure.Code
	}
	return "operation_failed"
}
