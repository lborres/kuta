package core

import "time"

// User represents a user account in the system\
//
// This is the "identity" - who someone is
type User struct {
	ID            string    `json:"id"`
	Email         string    `json:"email"`
	EmailVerified bool      `json:"emailVerified"`
	Name          string    `json:"name"`
	Image         *string   `json:"image,omitempty"`
	CreatedAt     time.Time `json:"createdAt"`
	UpdatedAt     time.Time `json:"updatedAt"`
}

// Account represents an authentication method
//
// This is the "credential" - how someone proves who they are
type Account struct {
	ID           string     `json:"id"`
	UserID       string     `json:"userId"`
	ProviderID   string     `json:"providerId"` // "credential", "google", "github"
	AccountID    string     `json:"accountId"`
	Password     *string    `json:"-"` // Never expose in JSON
	AccessToken  *string    `json:"-"` // Never expose in JSON
	RefreshToken *string    `json:"-"` // Never expose in JSON
	ExpiresAt    *time.Time `json:"expiresAt,omitempty"`
	CreatedAt    time.Time  `json:"createdAt"`
	UpdatedAt    time.Time  `json:"updatedAt"`
}

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
