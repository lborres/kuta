package admin

import "errors"

// Admin plugin errors
var (
	// Permission errors
	ErrNotAuthorized              = errors.New("not authorized")
	ErrNotAllowedToSetRole        = errors.New("you are not allowed to change user roles")
	ErrNotAllowedToCreateUser     = errors.New("you are not allowed to create users")
	ErrNotAllowedToListUsers      = errors.New("you are not allowed to list users")
	ErrNotAllowedToGetUser        = errors.New("you are not allowed to get user")
	ErrNotAllowedToUpdateUser     = errors.New("you are not allowed to update users")
	ErrNotAllowedToDeleteUser     = errors.New("you are not allowed to delete users")
	ErrNotAllowedToBanUser        = errors.New("you are not allowed to ban users")
	ErrNotAllowedToSetPassword    = errors.New("you are not allowed to set user passwords")
	ErrNotAllowedToListSessions   = errors.New("you are not allowed to list user sessions")
	ErrNotAllowedToRevokeSessions = errors.New("you are not allowed to revoke user sessions")
	ErrNotAllowedToImpersonate    = errors.New("you are not allowed to impersonate users")

	// Ban errors
	ErrUserBanned       = errors.New("user is banned")
	ErrCannotBanSelf    = errors.New("you cannot ban yourself")
	ErrCannotDeleteSelf = errors.New("you cannot delete yourself")

	// Role errors
	ErrInvalidRole      = errors.New("invalid role")
	ErrRoleDoesNotExist = errors.New("role does not exist")

	// Impersonation errors
	ErrNotImpersonating     = errors.New("you are not impersonating anyone")
	ErrImpersonationFailed  = errors.New("impersonation failed")
	ErrAdminSessionNotFound = errors.New("admin session not found")

	// General errors
	ErrNoDataToUpdate = errors.New("no data to update")
)
