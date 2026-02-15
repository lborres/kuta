package core

import "time"

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
