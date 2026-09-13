// Copyright 2025 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package clientauth

import (
	"net/http"

	"github.com/thunder-id/thunderid/internal/oauth/oauth2/constants"
)

// authError represents an authentication error.
type authError struct {
	ErrorCode        string
	ErrorDescription string
	StatusCode       int
}

// newAuthError creates a new authentication error.
func newAuthError(errorCode, errorDescription string, statusCode int) *authError {
	return &authError{
		ErrorCode:        errorCode,
		ErrorDescription: errorDescription,
		StatusCode:       statusCode,
	}
}

// Common authentication errors
var (
	errInvalidAuthorizationHeader = newAuthError(
		constants.ErrorInvalidClient,
		"Invalid client credentials",
		http.StatusUnauthorized,
	)
	errInvalidClientCredentials = newAuthError(
		constants.ErrorInvalidClient,
		"Invalid client credentials",
		http.StatusUnauthorized,
	)
	errMultipleAuthMethods = newAuthError(
		constants.ErrorInvalidRequest,
		"Multiple client authentication methods were provided",
		http.StatusBadRequest,
	)
	errMissingClientID = newAuthError(
		constants.ErrorInvalidRequest,
		"Missing client_id parameter",
		http.StatusBadRequest,
	)
	errUnauthorizedAuthMethod = newAuthError(
		constants.ErrorUnauthorizedClient,
		"Client is not allowed to use the specified authentication method",
		http.StatusBadRequest,
	)
	// errClientNotAuthorizedForOU is returned when a request names an organization unit the client
	// may not be used in. The client authenticated successfully, so this is unauthorized_client
	// rather than invalid_client, which would be indistinguishable from a bad secret.
	errClientNotAuthorizedForOU = newAuthError(
		constants.ErrorUnauthorizedClient,
		"The client is not authorized for the requested organization unit",
		http.StatusBadRequest,
	)
	errClientIDMismatch = newAuthError(
		constants.ErrorInvalidRequest,
		"client_id in request body does not match client_id from authentication credentials",
		http.StatusBadRequest,
	)
	errInvalidClientAssertion = newAuthError(
		constants.ErrorInvalidClient,
		"Invalid client assertion",
		http.StatusUnauthorized,
	)
	errClientAuthRequired = newAuthError(
		constants.ErrorInvalidClient,
		"Client authentication is required",
		http.StatusUnauthorized,
	)
)
