package core

import (
	"time"
)

// Session represents an active login session
type Session struct {
	ID        string    `json:"id"`
	UserID    string    `json:"userId"`
	TokenHash string    `json:"-"` // Never expose in JSON (security!)
	IPAddress string    `json:"ipAddress"`
	UserAgent string    `json:"userAgent"`
	ExpiresAt time.Time `json:"expiresAt"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// SessionData combines user and session info
// The model returned to clients
type SessionData struct {
	User    *User    `json:"user"`
	Session *Session `json:"session"`
}

// CookieCacheConfig defines behavior for client-side session caching in cookies
type CookieCacheConfig struct {
	Enabled   bool
	MaxAge    time.Duration
	UpdateAge time.Duration
}

// SessionConfig defines session lifetime and refresh behavior
type SessionConfig struct {
	ExpiresIn    time.Duration
	UpdateAge    time.Duration
	CookieConfig *CookieConfig
	CookieCache  *CookieCacheConfig
}

func DefaultSessionConfig() *SessionConfig {
	return &SessionConfig{
		ExpiresIn: 7 * 24 * time.Hour,
		UpdateAge: 24 * time.Hour,
	}
}

type CreateSessionResult struct {
	Session *Session `json:"session"`
	Token   string   `json:"token"`
}

// AuthProvider provides authentication operations for HTTP adapters
type AuthProvider interface {
	SignUp(input SignUpInput, ipAddress, userAgent string) (*SignUpResult, error)
	SignIn(input SignInInput, ipAddress, userAgent string) (*SignInResult, error)
	SignOut(token string) error
	GetSession(token string) (*SessionData, error)
	Refresh(token string) (*RefreshResult, error)
}

type SignUpInput struct {
	Email    string
	Password string
	Name     string
	Image    *string
}

type SignUpResult struct {
	User    *User    `json:"user"`
	Session *Session `json:"session"`
	Token   string   `json:"token"` // The raw token (not the hash)
}

type SignInInput struct {
	Email    string
	Password string
}

type SignInResult struct {
	User    *User    `json:"user"`
	Session *Session `json:"session"`
	Token   string   `json:"token"` // The raw token (not the hash)
}

type RefreshResult struct {
	Session *Session `json:"session"`
	Token   string   `json:"token"` // The raw token (not the hash)
}
