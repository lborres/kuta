package core

import "time"

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
