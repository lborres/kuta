package admin

import (
	"time"

	"github.com/lborres/kuta/core"
	"github.com/lborres/kuta/pkg/crypto"
)

// Service provides admin functionality
type Service struct {
	config      Config
	storage     AdminStorageProvider
	permissions *PermissionChecker
	passwords   crypto.PasswordHandler
	sessions    core.AuthProvider
	nanoid      *crypto.NanoIDGenerator
}

// NewService creates a new admin service
func NewService(
	config Config,
	storage AdminStorageProvider,
	passwords crypto.PasswordHandler,
	sessions core.AuthProvider,
) *Service {
	// Apply defaults
	if config.DefaultRole == "" {
		config.DefaultRole = "user"
	}
	if len(config.AdminRoles) == 0 {
		config.AdminRoles = []string{"admin"}
	}
	if config.ImpersonationDuration == 0 {
		config.ImpersonationDuration = time.Hour
	}
	if config.BannedUserMessage == "" {
		config.BannedUserMessage = "You have been banned from this application."
	}
	if config.Roles == nil {
		config.Roles = DefaultRoles()
	}

	nanoid, _ := crypto.NewNanoID()

	return &Service{
		config:      config,
		storage:     storage,
		permissions: NewPermissionChecker(&config),
		passwords:   passwords,
		sessions:    sessions,
		nanoid:      nanoid,
	}
}

// SetRole sets a user's role (requires "user:set-role" permission)
func (s *Service) SetRole(actorID, actorRole string, input SetRoleInput) (*UserWithRole, error) {
	if !s.permissions.CanPerform(actorID, actorRole, "user", "set-role") {
		return nil, ErrNotAllowedToSetRole
	}

	// Validate role exists
	role := input.Role
	if len(input.Roles) > 0 {
		role = input.Roles[0] // For now, single role support
	}
	if _, ok := s.config.Roles[role]; !ok {
		return nil, ErrRoleDoesNotExist
	}

	if err := s.storage.SetUserRole(input.UserID, role); err != nil {
		return nil, err
	}

	return s.storage.GetUserWithRole(input.UserID)
}

// GetUser gets a user by ID (requires "user:get" permission)
func (s *Service) GetUser(actorID, actorRole, targetUserID string) (*UserWithRole, error) {
	if !s.permissions.CanPerform(actorID, actorRole, "user", "get") {
		return nil, ErrNotAllowedToGetUser
	}

	return s.storage.GetUserWithRole(targetUserID)
}

// CreateUser creates a new user (requires "user:create" permission)
func (s *Service) CreateUser(actorID, actorRole string, input CreateUserInput) (*UserWithRole, error) {
	if !s.permissions.CanPerform(actorID, actorRole, "user", "create") {
		return nil, ErrNotAllowedToCreateUser
	}

	// Check if user already exists
	existing, _ := s.storage.GetUserByEmail(input.Email)
	if existing != nil {
		return nil, core.ErrUserExists
	}

	// Validate role if provided
	role := input.Role
	if role == "" {
		role = s.config.DefaultRole
	}
	if _, ok := s.config.Roles[role]; !ok {
		return nil, ErrRoleDoesNotExist
	}

	// Generate user ID
	userID, err := s.nanoid.Generate()
	if err != nil {
		return nil, err
	}

	// Create user
	user := &UserWithRole{
		User: core.User{
			ID:    userID,
			Email: input.Email,
			Name:  input.Name,
		},
		Role:   role,
		Banned: false,
	}

	if err := s.storage.CreateUserWithRole(user, input.Password); err != nil {
		return nil, err
	}

	return user, nil
}

// UpdateUser updates a user's fields (requires "user:update" permission)
func (s *Service) UpdateUser(actorID, actorRole string, input UpdateUserInput) (*UserWithRole, error) {
	if !s.permissions.CanPerform(actorID, actorRole, "user", "update") {
		return nil, ErrNotAllowedToUpdateUser
	}

	if len(input.Data) == 0 {
		return nil, ErrNoDataToUpdate
	}

	if err := s.storage.UpdateUserFields(input.UserID, input.Data); err != nil {
		return nil, err
	}

	return s.storage.GetUserWithRole(input.UserID)
}

// ListUsers lists users with pagination (requires "user:list" permission)
func (s *Service) ListUsers(actorID, actorRole string, input ListUsersInput) (*ListUsersResult, error) {
	if !s.permissions.CanPerform(actorID, actorRole, "user", "list") {
		return nil, ErrNotAllowedToListUsers
	}

	return s.storage.ListUsers(input)
}

// DeleteUser deletes a user (requires "user:delete" permission)
func (s *Service) DeleteUser(actorID, actorRole, targetUserID string) error {
	if !s.permissions.CanPerform(actorID, actorRole, "user", "delete") {
		return ErrNotAllowedToDeleteUser
	}

	// Cannot delete self
	if actorID == targetUserID {
		return ErrCannotDeleteSelf
	}

	// Verify user exists
	_, err := s.storage.GetUserWithRole(targetUserID)
	if err != nil {
		return err
	}

	return s.storage.DeleteUser(targetUserID)
}

// BanUser bans a user (requires "user:ban" permission)
func (s *Service) BanUser(actorID, actorRole string, input BanUserInput) (*UserWithRole, error) {
	if !s.permissions.CanPerform(actorID, actorRole, "user", "ban") {
		return nil, ErrNotAllowedToBanUser
	}

	// Cannot ban self
	if actorID == input.UserID {
		return nil, ErrCannotBanSelf
	}

	// Verify user exists
	_, err := s.storage.GetUserWithRole(input.UserID)
	if err != nil {
		return nil, err
	}

	// Calculate ban expiry
	var expiresAt *time.Time
	if input.BanExpires != nil {
		expiresAt = input.BanExpires
	} else if input.ExpiresIn != nil {
		t := time.Now().Add(*input.ExpiresIn)
		expiresAt = &t
	} else if s.config.DefaultBanDuration > 0 {
		t := time.Now().Add(s.config.DefaultBanDuration)
		expiresAt = &t
	}

	// Set ban reason
	reason := input.Reason
	if reason == "" {
		reason = s.config.DefaultBanReason
	}

	if err := s.storage.BanUser(input.UserID, reason, expiresAt); err != nil {
		return nil, err
	}

	// Revoke all user sessions
	_, _ = s.storage.DeleteUserSessions(input.UserID)

	return s.storage.GetUserWithRole(input.UserID)
}

// UnbanUser unbans a user (requires "user:ban" permission)
func (s *Service) UnbanUser(actorID, actorRole, targetUserID string) (*UserWithRole, error) {
	if !s.permissions.CanPerform(actorID, actorRole, "user", "ban") {
		return nil, ErrNotAllowedToBanUser
	}

	if err := s.storage.UnbanUser(targetUserID); err != nil {
		return nil, err
	}

	return s.storage.GetUserWithRole(targetUserID)
}

// SetUserPassword sets a user's password (requires "user:set-password" permission)
func (s *Service) SetUserPassword(actorID, actorRole, targetUserID, newPassword string) error {
	if !s.permissions.CanPerform(actorID, actorRole, "user", "set-password") {
		return ErrNotAllowedToSetPassword
	}

	// Hash the new password
	hashedPassword, err := s.passwords.Hash(newPassword)
	if err != nil {
		return err
	}

	// Update the account's password
	accounts, err := s.storage.GetAccountByUserAndProvider(targetUserID, "credential")
	if err != nil {
		return err
	}

	if len(accounts) == 0 {
		return core.ErrUserNotFound
	}

	accounts[0].Password = &hashedPassword
	return s.storage.UpdateAccount(accounts[0])
}

// ListUserSessions lists a user's sessions (requires "session:list" permission)
func (s *Service) ListUserSessions(actorID, actorRole, targetUserID string) ([]*core.Session, error) {
	if !s.permissions.CanPerform(actorID, actorRole, "session", "list") {
		return nil, ErrNotAllowedToListSessions
	}

	return s.storage.GetUserSessions(targetUserID)
}

// RevokeSession revokes a specific session (requires "session:revoke" permission)
func (s *Service) RevokeSession(actorID, actorRole, sessionID string) error {
	if !s.permissions.CanPerform(actorID, actorRole, "session", "revoke") {
		return ErrNotAllowedToRevokeSessions
	}

	return s.storage.DeleteSessionByID(sessionID)
}

// RevokeUserSessions revokes all sessions for a user (requires "session:revoke" permission)
func (s *Service) RevokeUserSessions(actorID, actorRole, targetUserID string) (int, error) {
	if !s.permissions.CanPerform(actorID, actorRole, "session", "revoke") {
		return 0, ErrNotAllowedToRevokeSessions
	}

	return s.storage.DeleteUserSessions(targetUserID)
}

// CheckBanStatus checks if a user is banned (and clears expired bans)
// This is called during sign-in to prevent banned users from authenticating
func (s *Service) CheckBanStatus(userID string) error {
	banned, expiresAt, err := s.storage.IsBanned(userID)
	if err != nil {
		return err
	}

	if !banned {
		return nil
	}

	// Check if ban has expired
	if expiresAt != nil && time.Now().After(*expiresAt) {
		// Clear the expired ban
		_ = s.storage.UnbanUser(userID)
		return nil
	}

	return ErrUserBanned
}

// Config returns the service configuration (for handlers)
func (s *Service) Config() Config {
	return s.config
}

// Permissions returns the permission checker (for handlers)
func (s *Service) Permissions() *PermissionChecker {
	return s.permissions
}
