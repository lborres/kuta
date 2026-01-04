package core

import "errors"

// Authentication Related Errors
var (
	// User errors
	ErrUserExists         = errors.New("user already exists")       // 409 Conflict
	ErrUserNotFound       = errors.New("user not found")            // 404 Not Found
	ErrInvalidCredentials = errors.New("invalid email or password") // 401 Unauthorized
)

// Session errors
var (
	ErrMissingAuthHeader = errors.New("missing authorization header") // 401
	ErrInvalidToken      = errors.New("invalid session token")        // 401
	ErrSessionNotFound   = errors.New("session not found")            // 401
	ErrSessionExpired    = errors.New("session expired")              // 401
	ErrCacheNotFound     = errors.New("session not found in cache")
)

// Validation errors (client input)
var (
	ErrInvalidAuthHeader = errors.New("invalid authorization format, expected 'Bearer <token>'") // 401
	ErrEmailRequired     = errors.New("email is required")                                       // 400
	ErrPasswordRequired  = errors.New("password is required")                                    // 400
	ErrPasswordTooShort  = errors.New("password is too short")                                   // 400
	ErrPasswordTooLong   = errors.New("password is too long")                                    // 400
	ErrInvalidEmail      = errors.New("invalid email format")                                    // 400
)

// Config errors (server-side configuration)
var (
	ErrDBAdapterRequired   = errors.New("database adapter is required") // 500
	ErrHTTPAdapterRequired = errors.New("adapter is required")          // 500
	ErrSecretRequired      = errors.New("secret is required")           // 500
	ErrSecretTooShort      = errors.New("secret too short")             // 500
)

var (
	ErrNotImplemented = errors.New("not implemented") // 501
)
