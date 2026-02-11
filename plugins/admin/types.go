package admin

import (
	"time"

	"github.com/lborres/kuta/core"
)

// UserWithRole extends the base User with admin-specific fields
type UserWithRole struct {
	core.User
	Role       string     `json:"role"`
	Banned     bool       `json:"banned"`
	BanReason  *string    `json:"banReason,omitempty"`
	BanExpires *time.Time `json:"banExpires,omitempty"`
}

// SessionWithImpersonation extends Session with impersonation info
type SessionWithImpersonation struct {
	core.Session
	ImpersonatedBy *string `json:"impersonatedBy,omitempty"`
}

// Config options for the admin plugin
type Config struct {
	// DefaultRole is assigned to new users (default: "user")
	DefaultRole string

	// AdminRoles are roles that have admin privileges (default: ["admin"])
	AdminRoles []string

	// AdminUserIDs is a list of user IDs that always have admin access
	// This bypasses role checks
	AdminUserIDs []string

	// DefaultBanReason is used when no reason is provided
	DefaultBanReason string

	// DefaultBanDuration is used when no duration is provided (0 = permanent)
	DefaultBanDuration time.Duration

	// ImpersonationDuration is how long an impersonation session lasts (default: 1 hour)
	ImpersonationDuration time.Duration

	// BannedUserMessage is shown when a banned user tries to sign in
	BannedUserMessage string

	// Roles defines custom roles and their permissions
	Roles map[string]*Role
}

// DefaultConfig returns the default admin configuration
func DefaultConfig() Config {
	return Config{
		DefaultRole:           "user",
		AdminRoles:            []string{"admin"},
		DefaultBanReason:      "No reason provided",
		ImpersonationDuration: time.Hour,
		BannedUserMessage:     "You have been banned from this application. Please contact support if you believe this is an error.",
		Roles:                 DefaultRoles(),
	}
}

// Role represents a set of permissions
type Role struct {
	name        string
	permissions map[string][]string
}

// NewRole creates a new role with the given name and permissions
func NewRole(name string, permissions map[string][]string) *Role {
	return &Role{
		name:        name,
		permissions: permissions,
	}
}

// HasPermission checks if the role has a specific permission
func (r *Role) HasPermission(resource, action string) bool {
	if r.permissions == nil {
		return false
	}
	actions, ok := r.permissions[resource]
	if !ok {
		return false
	}
	for _, a := range actions {
		if a == action || a == "*" {
			return true
		}
	}
	return false
}

// Authorize checks if the role has all required permissions
func (r *Role) Authorize(permissions map[string][]string) bool {
	for resource, actions := range permissions {
		for _, action := range actions {
			if !r.HasPermission(resource, action) {
				return false
			}
		}
	}
	return true
}

// DefaultRoles returns the default role configuration
func DefaultRoles() map[string]*Role {
	return map[string]*Role{
		"admin": NewRole("admin", map[string][]string{
			"user":    {"create", "list", "get", "update", "delete", "set-role", "ban", "set-password"},
			"session": {"list", "revoke", "delete"},
		}),
		"user": NewRole("user", map[string][]string{
			"user":    {},
			"session": {},
		}),
	}
}

// Permissions defines what actions can be performed on resources
type Permissions map[string][]string

// SetRoleInput is the input for setting a user's role
type SetRoleInput struct {
	UserID string   `json:"userId"`
	Role   string   `json:"role"`
	Roles  []string `json:"roles,omitempty"` // For multiple roles
}

// BanUserInput is the input for banning a user
type BanUserInput struct {
	UserID     string         `json:"userId"`
	Reason     string         `json:"reason,omitempty"`
	ExpiresIn  *time.Duration `json:"expiresIn,omitempty"` // Duration until ban expires
	BanExpires *time.Time     `json:"banExpires,omitempty"`
}

// CreateUserInput is the input for admin user creation
type CreateUserInput struct {
	Email    string         `json:"email"`
	Password string         `json:"password"`
	Name     string         `json:"name"`
	Role     string         `json:"role,omitempty"`
	Data     map[string]any `json:"data,omitempty"` // Extra fields
}

// UpdateUserInput is the input for admin user updates
type UpdateUserInput struct {
	UserID string         `json:"userId"`
	Data   map[string]any `json:"data"`
}

// ListUsersInput is the input for listing users
type ListUsersInput struct {
	Limit          int    `json:"limit,omitempty"`
	Offset         int    `json:"offset,omitempty"`
	SortBy         string `json:"sortBy,omitempty"`
	SortDirection  string `json:"sortDirection,omitempty"` // "asc" or "desc"
	SearchValue    string `json:"searchValue,omitempty"`
	SearchField    string `json:"searchField,omitempty"` // "email" or "name"
	FilterField    string `json:"filterField,omitempty"`
	FilterValue    string `json:"filterValue,omitempty"`
	FilterOperator string `json:"filterOperator,omitempty"` // "eq", "ne", "contains"
}

// ListUsersResult is the result of listing users
type ListUsersResult struct {
	Users  []*UserWithRole `json:"users"`
	Total  int             `json:"total"`
	Limit  int             `json:"limit,omitempty"`
	Offset int             `json:"offset,omitempty"`
}

// ImpersonateResult is the result of impersonating a user
type ImpersonateResult struct {
	Session *SessionWithImpersonation `json:"session"`
	User    *UserWithRole             `json:"user"`
	Token   string                    `json:"token"`
}
