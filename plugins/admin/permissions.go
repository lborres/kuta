package admin

// PermissionChecker handles permission verification for admin operations
type PermissionChecker struct {
	config *Config
}

// NewPermissionChecker creates a new permission checker
func NewPermissionChecker(config *Config) *PermissionChecker {
	return &PermissionChecker{config: config}
}

// HasPermission checks if a user has the required permissions
func (p *PermissionChecker) HasPermission(userID, role string, permissions Permissions) bool {
	// Check if user is in admin user IDs list (bypass role check)
	for _, adminID := range p.config.AdminUserIDs {
		if adminID == userID {
			return true
		}
	}

	// If no role specified, use default role
	if role == "" {
		role = p.config.DefaultRole
	}

	// Get role from config
	r, ok := p.config.Roles[role]
	if !ok {
		return false
	}

	// Check if role has all required permissions
	return r.Authorize(permissions)
}

// IsAdminRole checks if the given role is an admin role
func (p *PermissionChecker) IsAdminRole(role string) bool {
	for _, adminRole := range p.config.AdminRoles {
		if adminRole == role {
			return true
		}
	}
	return false
}

// CanPerform is a convenience method that checks a single permission
func (p *PermissionChecker) CanPerform(userID, role, resource, action string) bool {
	return p.HasPermission(userID, role, Permissions{
		resource: {action},
	})
}
