package core

import "errors"

// Authentication errors
var (
	// User errors

	ErrUserExists         = errors.New("user already exists")
	ErrUserNotFound       = errors.New("user not found")
	ErrInvalidCredentials = errors.New("invalid email or password")

	// Session errors

	ErrInvalidToken    = errors.New("invalid session token")
	ErrSessionNotFound = errors.New("session not found")
	ErrSessionExpired  = errors.New("session expired")
	ErrUnauthorized    = errors.New("unauthorized")
	ErrCacheNotFound   = errors.New("session not found in cache")

	// Validation errors

	ErrEmailRequired    = errors.New("email is required")
	ErrPasswordRequired = errors.New("password is required")
	ErrPasswordTooShort = errors.New("password is too short")
	ErrPasswordTooLong  = errors.New("password is too long")
	ErrInvalidEmail     = errors.New("invalid email format")

	// Config errors

	ErrAdapterRequired = errors.New("database adapter is required")
	ErrSecretRequired  = errors.New("secret is required")
	ErrSecretTooShort  = errors.New("secret must be at least 32 characters")
)
