package admin

import (
	"time"

	"github.com/lborres/kuta/core"
)

// AdminUserStorage extends user storage with admin-specific operations
type AdminUserStorage interface {
	// Extend user with role/ban fields
	GetUserWithRole(id string) (*UserWithRole, error)
	GetUserWithRoleByEmail(email string) (*UserWithRole, error)

	// Role management
	SetUserRole(userID string, role string) error

	// Ban management
	BanUser(userID string, reason string, expiresAt *time.Time) error
	UnbanUser(userID string) error
	IsBanned(userID string) (bool, *time.Time, error) // Returns banned status and expiry

	// User listing
	ListUsers(opts ListUsersInput) (*ListUsersResult, error)
	CountUsers(opts ListUsersInput) (int, error)

	// Admin user creation (with role)
	CreateUserWithRole(user *UserWithRole, password string) error

	// Update user with arbitrary fields
	UpdateUserFields(userID string, fields map[string]any) error
}

// AdminSessionStorage extends session storage with admin-specific operations
type AdminSessionStorage interface {
	// Create session with impersonation info
	CreateImpersonationSession(session *SessionWithImpersonation) (string, error)

	// Get session with impersonation info
	GetSessionWithImpersonation(tokenHash string) (*SessionWithImpersonation, error)
}

// AdminStorageProvider combines all admin storage requirements
type AdminStorageProvider interface {
	core.StorageProvider
	AdminUserStorage
	AdminSessionStorage
}
