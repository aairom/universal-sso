package sso

import (
	"fmt"
	"net/http"
)

// SSOErrorCode enumerates standard machine-readable SSO error codes.
type SSOErrorCode string

const (
	ErrCodeInvalidConfig     SSOErrorCode = "INVALID_CONFIG"
	ErrCodeProviderNotFound  SSOErrorCode = "PROVIDER_NOT_FOUND"
	ErrCodeStateMismatch     SSOErrorCode = "STATE_MISMATCH"
	ErrCodeStateExpired      SSOErrorCode = "STATE_EXPIRED"
	ErrCodeInvalidToken      SSOErrorCode = "INVALID_TOKEN"
	ErrCodeTokenExpired      SSOErrorCode = "TOKEN_EXPIRED"
	ErrCodeSignatureInvalid  SSOErrorCode = "SIGNATURE_INVALID"
	ErrCodeIdPRejected       SSOErrorCode = "IDP_REJECTED"
	ErrCodeNetworkFailure    SSOErrorCode = "NETWORK_FAILURE"
	ErrCodeUnsupportedMethod SSOErrorCode = "UNSUPPORTED_METHOD"
	ErrCodeUnauthorized      SSOErrorCode = "UNAUTHORIZED"
	ErrCodeInternal          SSOErrorCode = "INTERNAL_ERROR"
)

// SSOError defines a structured error with HTTP status, code, message, and wrapped cause.
type SSOError struct {
	Code       SSOErrorCode `json:"code"`
	Message    string       `json:"message"`
	HTTPStatus int          `json:"http_status"`
	Err        error        `json:"-"`
}

func (e *SSOError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("[%s] %s: %v", e.Code, e.Message, e.Err)
	}
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

func (e *SSOError) Unwrap() error {
	return e.Err
}

// NewError creates a new SSOError.
func NewError(code SSOErrorCode, message string, httpStatus int, cause error) *SSOError {
	return &SSOError{
		Code:       code,
		Message:    message,
		HTTPStatus: httpStatus,
		Err:        cause,
	}
}

// Common error constructors.
func ErrInvalidConfig(msg string, err error) *SSOError {
	return NewError(ErrCodeInvalidConfig, msg, http.StatusInternalServerError, err)
}

func ErrNotFound(msg string) *SSOError {
	return NewError(ErrCodeProviderNotFound, msg, http.StatusNotFound, nil)
}

func ErrStateInvalid(msg string) *SSOError {
	return NewError(ErrCodeStateMismatch, msg, http.StatusBadRequest, nil)
}

func ErrTokenValidation(msg string, err error) *SSOError {
	return NewError(ErrCodeInvalidToken, msg, http.StatusUnauthorized, err)
}

func ErrUnauthorizedAccess(msg string) *SSOError {
	return NewError(ErrCodeUnauthorized, msg, http.StatusUnauthorized, nil)
}
