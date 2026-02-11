package admin

import (
	"testing"
	"time"

	"github.com/lborres/kuta/core"
)

// FakeAdminStorage implements AdminStorageProvider for testing
type FakeAdminStorage struct {
	users    map[string]*UserWithRole
	accounts map[string]*core.Account
	sessions map[string]*core.Session
}

func NewFakeAdminStorage() *FakeAdminStorage {
	return &FakeAdminStorage{
		users:    make(map[string]*UserWithRole),
		accounts: make(map[string]*core.Account),
		sessions: make(map[string]*core.Session),
	}
}

// UserStorage implementation
func (f *FakeAdminStorage) CreateUser(u *core.User) error {
	f.users[u.ID] = &UserWithRole{User: *u, Role: "user"}
	return nil
}

func (f *FakeAdminStorage) GetUserByID(id string) (*core.User, error) {
	if u, ok := f.users[id]; ok {
		return &u.User, nil
	}
	return nil, core.ErrUserNotFound
}

func (f *FakeAdminStorage) GetUserByEmail(email string) (*core.User, error) {
	for _, u := range f.users {
		if u.Email == email {
			return &u.User, nil
		}
	}
	return nil, core.ErrUserNotFound
}

func (f *FakeAdminStorage) UpdateUser(u *core.User) error {
	if existing, ok := f.users[u.ID]; ok {
		existing.User = *u
		return nil
	}
	return core.ErrUserNotFound
}

func (f *FakeAdminStorage) DeleteUser(id string) error {
	if _, ok := f.users[id]; ok {
		delete(f.users, id)
		return nil
	}
	return core.ErrUserNotFound
}

// AccountStorage implementation
func (f *FakeAdminStorage) CreateAccount(a *core.Account) error {
	f.accounts[a.ID] = a
	return nil
}

func (f *FakeAdminStorage) GetAccountByID(id string) (*core.Account, error) {
	if a, ok := f.accounts[id]; ok {
		return a, nil
	}
	return nil, core.ErrUserNotFound
}

func (f *FakeAdminStorage) GetAccountByUserAndProvider(userID, providerID string) ([]*core.Account, error) {
	var result []*core.Account
	for _, a := range f.accounts {
		if a.UserID == userID && a.ProviderID == providerID {
			result = append(result, a)
		}
	}
	return result, nil
}

func (f *FakeAdminStorage) UpdateAccount(a *core.Account) error {
	if _, ok := f.accounts[a.ID]; ok {
		f.accounts[a.ID] = a
		return nil
	}
	return core.ErrUserNotFound
}

func (f *FakeAdminStorage) DeleteAccount(id string) error {
	delete(f.accounts, id)
	return nil
}

// SessionStorage implementation
func (f *FakeAdminStorage) CreateSession(session *core.Session) error {
	f.sessions[session.ID] = session
	return nil
}

func (f *FakeAdminStorage) GetSessionByHash(tokenHash string) (*core.Session, error) {
	for _, s := range f.sessions {
		if s.TokenHash == tokenHash {
			return s, nil
		}
	}
	return nil, core.ErrSessionNotFound
}

func (f *FakeAdminStorage) GetSessionByID(id string) (*core.Session, error) {
	if s, ok := f.sessions[id]; ok {
		return s, nil
	}
	return nil, core.ErrSessionNotFound
}

func (f *FakeAdminStorage) GetUserSessions(userID string) ([]*core.Session, error) {
	var result []*core.Session
	for _, s := range f.sessions {
		if s.UserID == userID {
			result = append(result, s)
		}
	}
	return result, nil
}

func (f *FakeAdminStorage) UpdateSession(session *core.Session) error {
	if _, ok := f.sessions[session.ID]; ok {
		f.sessions[session.ID] = session
		return nil
	}
	return core.ErrSessionNotFound
}

func (f *FakeAdminStorage) DeleteSessionByID(id string) error {
	delete(f.sessions, id)
	return nil
}

func (f *FakeAdminStorage) DeleteSessionByHash(tokenHash string) error {
	for id, s := range f.sessions {
		if s.TokenHash == tokenHash {
			delete(f.sessions, id)
			return nil
		}
	}
	return nil
}

func (f *FakeAdminStorage) DeleteUserSessions(userID string) (int, error) {
	count := 0
	for id, s := range f.sessions {
		if s.UserID == userID {
			delete(f.sessions, id)
			count++
		}
	}
	return count, nil
}

func (f *FakeAdminStorage) DeleteExpiredSessions() (int, error) {
	count := 0
	now := time.Now()
	for id, s := range f.sessions {
		if s.ExpiresAt.Before(now) {
			delete(f.sessions, id)
			count++
		}
	}
	return count, nil
}

// AdminUserStorage implementation
func (f *FakeAdminStorage) GetUserWithRole(id string) (*UserWithRole, error) {
	if u, ok := f.users[id]; ok {
		return u, nil
	}
	return nil, core.ErrUserNotFound
}

func (f *FakeAdminStorage) GetUserWithRoleByEmail(email string) (*UserWithRole, error) {
	for _, u := range f.users {
		if u.Email == email {
			return u, nil
		}
	}
	return nil, core.ErrUserNotFound
}

func (f *FakeAdminStorage) SetUserRole(userID string, role string) error {
	if u, ok := f.users[userID]; ok {
		u.Role = role
		return nil
	}
	return core.ErrUserNotFound
}

func (f *FakeAdminStorage) BanUser(userID string, reason string, expiresAt *time.Time) error {
	if u, ok := f.users[userID]; ok {
		u.Banned = true
		u.BanReason = &reason
		u.BanExpires = expiresAt
		return nil
	}
	return core.ErrUserNotFound
}

func (f *FakeAdminStorage) UnbanUser(userID string) error {
	if u, ok := f.users[userID]; ok {
		u.Banned = false
		u.BanReason = nil
		u.BanExpires = nil
		return nil
	}
	return core.ErrUserNotFound
}

func (f *FakeAdminStorage) IsBanned(userID string) (bool, *time.Time, error) {
	if u, ok := f.users[userID]; ok {
		return u.Banned, u.BanExpires, nil
	}
	return false, nil, core.ErrUserNotFound
}

func (f *FakeAdminStorage) ListUsers(opts ListUsersInput) (*ListUsersResult, error) {
	var users []*UserWithRole
	for _, u := range f.users {
		users = append(users, u)
	}

	// Apply basic pagination
	start := opts.Offset
	end := len(users)
	if opts.Limit > 0 && start+opts.Limit < end {
		end = start + opts.Limit
	}
	if start > len(users) {
		start = len(users)
	}

	return &ListUsersResult{
		Users:  users[start:end],
		Total:  len(f.users),
		Limit:  opts.Limit,
		Offset: opts.Offset,
	}, nil
}

func (f *FakeAdminStorage) CountUsers(opts ListUsersInput) (int, error) {
	return len(f.users), nil
}

func (f *FakeAdminStorage) CreateUserWithRole(user *UserWithRole, password string) error {
	f.users[user.ID] = user

	// Create credential account
	hashedPassword := password // In real impl, this would be hashed
	account := &core.Account{
		ID:         user.ID + "-account",
		UserID:     user.ID,
		ProviderID: "credential",
		AccountID:  user.Email,
		Password:   &hashedPassword,
	}
	f.accounts[account.ID] = account

	return nil
}

func (f *FakeAdminStorage) UpdateUserFields(userID string, fields map[string]any) error {
	u, ok := f.users[userID]
	if !ok {
		return core.ErrUserNotFound
	}

	for key, value := range fields {
		switch key {
		case "name":
			if v, ok := value.(string); ok {
				u.Name = v
			}
		case "email":
			if v, ok := value.(string); ok {
				u.Email = v
			}
		case "role":
			if v, ok := value.(string); ok {
				u.Role = v
			}
		}
	}
	return nil
}

// AdminSessionStorage implementation
func (f *FakeAdminStorage) CreateImpersonationSession(session *SessionWithImpersonation) (string, error) {
	f.sessions[session.ID] = &session.Session
	return "fake-token", nil
}

func (f *FakeAdminStorage) GetSessionWithImpersonation(tokenHash string) (*SessionWithImpersonation, error) {
	for _, s := range f.sessions {
		if s.TokenHash == tokenHash {
			return &SessionWithImpersonation{Session: *s}, nil
		}
	}
	return nil, core.ErrSessionNotFound
}

// FakePasswordHandler for testing
type FakePasswordHandler struct{}

func (f *FakePasswordHandler) Hash(password string) (string, error) {
	return "hashed-" + password, nil
}

func (f *FakePasswordHandler) Verify(password, hash string) (bool, error) {
	return hash == "hashed-"+password, nil
}

// Tests

func TestService_SetRole(t *testing.T) {
	tests := []struct {
		name      string
		actorID   string
		actorRole string
		input     SetRoleInput
		setup     func(*FakeAdminStorage)
		wantErr   error
	}{
		{
			name:      "admin can set role",
			actorID:   "admin-1",
			actorRole: "admin",
			input:     SetRoleInput{UserID: "user-1", Role: "admin"},
			setup: func(s *FakeAdminStorage) {
				s.users["user-1"] = &UserWithRole{
					User: core.User{ID: "user-1", Email: "user@example.com"},
					Role: "user",
				}
			},
			wantErr: nil,
		},
		{
			name:      "user cannot set role",
			actorID:   "user-1",
			actorRole: "user",
			input:     SetRoleInput{UserID: "user-2", Role: "admin"},
			wantErr:   ErrNotAllowedToSetRole,
		},
		{
			name:      "cannot set non-existent role",
			actorID:   "admin-1",
			actorRole: "admin",
			input:     SetRoleInput{UserID: "user-1", Role: "super-admin"},
			setup: func(s *FakeAdminStorage) {
				s.users["user-1"] = &UserWithRole{
					User: core.User{ID: "user-1", Email: "user@example.com"},
					Role: "user",
				}
			},
			wantErr: ErrRoleDoesNotExist,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			storage := NewFakeAdminStorage()
			if tt.setup != nil {
				tt.setup(storage)
			}

			svc := NewService(DefaultConfig(), storage, &FakePasswordHandler{}, nil)
			_, err := svc.SetRole(tt.actorID, tt.actorRole, tt.input)

			if tt.wantErr != nil {
				if err != tt.wantErr {
					t.Errorf("SetRole() error = %v, wantErr %v", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Errorf("SetRole() unexpected error = %v", err)
			}
		})
	}
}

func TestService_BanUser(t *testing.T) {
	tests := []struct {
		name      string
		actorID   string
		actorRole string
		input     BanUserInput
		setup     func(*FakeAdminStorage)
		wantErr   error
	}{
		{
			name:      "admin can ban user",
			actorID:   "admin-1",
			actorRole: "admin",
			input:     BanUserInput{UserID: "user-1", Reason: "Spam"},
			setup: func(s *FakeAdminStorage) {
				s.users["user-1"] = &UserWithRole{
					User: core.User{ID: "user-1", Email: "user@example.com"},
					Role: "user",
				}
			},
			wantErr: nil,
		},
		{
			name:      "user cannot ban",
			actorID:   "user-1",
			actorRole: "user",
			input:     BanUserInput{UserID: "user-2"},
			wantErr:   ErrNotAllowedToBanUser,
		},
		{
			name:      "cannot ban self",
			actorID:   "admin-1",
			actorRole: "admin",
			input:     BanUserInput{UserID: "admin-1"},
			setup: func(s *FakeAdminStorage) {
				s.users["admin-1"] = &UserWithRole{
					User: core.User{ID: "admin-1", Email: "admin@example.com"},
					Role: "admin",
				}
			},
			wantErr: ErrCannotBanSelf,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			storage := NewFakeAdminStorage()
			if tt.setup != nil {
				tt.setup(storage)
			}

			svc := NewService(DefaultConfig(), storage, &FakePasswordHandler{}, nil)
			_, err := svc.BanUser(tt.actorID, tt.actorRole, tt.input)

			if tt.wantErr != nil {
				if err != tt.wantErr {
					t.Errorf("BanUser() error = %v, wantErr %v", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Errorf("BanUser() unexpected error = %v", err)
			}
		})
	}
}

func TestService_CreateUser(t *testing.T) {
	tests := []struct {
		name      string
		actorID   string
		actorRole string
		input     CreateUserInput
		wantErr   error
	}{
		{
			name:      "admin can create user",
			actorID:   "admin-1",
			actorRole: "admin",
			input:     CreateUserInput{Email: "new@example.com", Password: "Password123!", Name: "New User"},
			wantErr:   nil,
		},
		{
			name:      "user cannot create user",
			actorID:   "user-1",
			actorRole: "user",
			input:     CreateUserInput{Email: "new@example.com", Password: "Password123!", Name: "New User"},
			wantErr:   ErrNotAllowedToCreateUser,
		},
		{
			name:      "admin can create user with specific role",
			actorID:   "admin-1",
			actorRole: "admin",
			input:     CreateUserInput{Email: "admin@example.com", Password: "Password123!", Name: "New Admin", Role: "admin"},
			wantErr:   nil,
		},
		{
			name:      "cannot create with invalid role",
			actorID:   "admin-1",
			actorRole: "admin",
			input:     CreateUserInput{Email: "admin@example.com", Password: "Password123!", Name: "New User", Role: "superadmin"},
			wantErr:   ErrRoleDoesNotExist,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			storage := NewFakeAdminStorage()
			svc := NewService(DefaultConfig(), storage, &FakePasswordHandler{}, nil)

			user, err := svc.CreateUser(tt.actorID, tt.actorRole, tt.input)

			if tt.wantErr != nil {
				if err != tt.wantErr {
					t.Errorf("CreateUser() error = %v, wantErr %v", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Errorf("CreateUser() unexpected error = %v", err)
				return
			}

			if user.Email != tt.input.Email {
				t.Errorf("CreateUser() email = %v, want %v", user.Email, tt.input.Email)
			}
		})
	}
}

func TestService_DeleteUser(t *testing.T) {
	tests := []struct {
		name         string
		actorID      string
		actorRole    string
		targetUserID string
		setup        func(*FakeAdminStorage)
		wantErr      error
	}{
		{
			name:         "admin can delete user",
			actorID:      "admin-1",
			actorRole:    "admin",
			targetUserID: "user-1",
			setup: func(s *FakeAdminStorage) {
				s.users["user-1"] = &UserWithRole{
					User: core.User{ID: "user-1", Email: "user@example.com"},
					Role: "user",
				}
			},
			wantErr: nil,
		},
		{
			name:         "user cannot delete user",
			actorID:      "user-1",
			actorRole:    "user",
			targetUserID: "user-2",
			wantErr:      ErrNotAllowedToDeleteUser,
		},
		{
			name:         "cannot delete self",
			actorID:      "admin-1",
			actorRole:    "admin",
			targetUserID: "admin-1",
			setup: func(s *FakeAdminStorage) {
				s.users["admin-1"] = &UserWithRole{
					User: core.User{ID: "admin-1", Email: "admin@example.com"},
					Role: "admin",
				}
			},
			wantErr: ErrCannotDeleteSelf,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			storage := NewFakeAdminStorage()
			if tt.setup != nil {
				tt.setup(storage)
			}

			svc := NewService(DefaultConfig(), storage, &FakePasswordHandler{}, nil)
			err := svc.DeleteUser(tt.actorID, tt.actorRole, tt.targetUserID)

			if tt.wantErr != nil {
				if err != tt.wantErr {
					t.Errorf("DeleteUser() error = %v, wantErr %v", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Errorf("DeleteUser() unexpected error = %v", err)
			}
		})
	}
}

func TestRole_HasPermission(t *testing.T) {
	tests := []struct {
		name       string
		role       *Role
		resource   string
		action     string
		wantResult bool
	}{
		{
			name:       "admin has user:create permission",
			role:       DefaultRoles()["admin"],
			resource:   "user",
			action:     "create",
			wantResult: true,
		},
		{
			name:       "admin has user:ban permission",
			role:       DefaultRoles()["admin"],
			resource:   "user",
			action:     "ban",
			wantResult: true,
		},
		{
			name:       "user does not have user:create permission",
			role:       DefaultRoles()["user"],
			resource:   "user",
			action:     "create",
			wantResult: false,
		},
		{
			name:       "admin has session:list permission",
			role:       DefaultRoles()["admin"],
			resource:   "session",
			action:     "list",
			wantResult: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.role.HasPermission(tt.resource, tt.action)
			if result != tt.wantResult {
				t.Errorf("HasPermission() = %v, want %v", result, tt.wantResult)
			}
		})
	}
}

func TestPermissionChecker_HasPermission(t *testing.T) {
	tests := []struct {
		name        string
		config      Config
		userID      string
		role        string
		permissions Permissions
		wantResult  bool
	}{
		{
			name:   "admin user ID bypasses role check",
			config: Config{AdminUserIDs: []string{"special-user"}, DefaultRole: "user", Roles: DefaultRoles()},
			userID: "special-user",
			role:   "user",
			permissions: Permissions{
				"user": {"delete"},
			},
			wantResult: true,
		},
		{
			name:   "admin role has permission",
			config: Config{DefaultRole: "user", Roles: DefaultRoles()},
			userID: "admin-1",
			role:   "admin",
			permissions: Permissions{
				"user": {"create"},
			},
			wantResult: true,
		},
		{
			name:   "user role lacks permission",
			config: Config{DefaultRole: "user", Roles: DefaultRoles()},
			userID: "user-1",
			role:   "user",
			permissions: Permissions{
				"user": {"create"},
			},
			wantResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker := NewPermissionChecker(&tt.config)
			result := checker.HasPermission(tt.userID, tt.role, tt.permissions)
			if result != tt.wantResult {
				t.Errorf("HasPermission() = %v, want %v", result, tt.wantResult)
			}
		})
	}
}

func TestService_CheckBanStatus(t *testing.T) {
	tests := []struct {
		name    string
		userID  string
		setup   func(*FakeAdminStorage)
		wantErr error
	}{
		{
			name:   "not banned user passes",
			userID: "user-1",
			setup: func(s *FakeAdminStorage) {
				s.users["user-1"] = &UserWithRole{
					User:   core.User{ID: "user-1", Email: "user@example.com"},
					Role:   "user",
					Banned: false,
				}
			},
			wantErr: nil,
		},
		{
			name:   "banned user fails",
			userID: "user-1",
			setup: func(s *FakeAdminStorage) {
				s.users["user-1"] = &UserWithRole{
					User:   core.User{ID: "user-1", Email: "user@example.com"},
					Role:   "user",
					Banned: true,
				}
			},
			wantErr: ErrUserBanned,
		},
		{
			name:   "expired ban passes",
			userID: "user-1",
			setup: func(s *FakeAdminStorage) {
				pastTime := time.Now().Add(-time.Hour)
				s.users["user-1"] = &UserWithRole{
					User:       core.User{ID: "user-1", Email: "user@example.com"},
					Role:       "user",
					Banned:     true,
					BanExpires: &pastTime,
				}
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			storage := NewFakeAdminStorage()
			if tt.setup != nil {
				tt.setup(storage)
			}

			svc := NewService(DefaultConfig(), storage, &FakePasswordHandler{}, nil)
			err := svc.CheckBanStatus(tt.userID)

			if tt.wantErr != nil {
				if err != tt.wantErr {
					t.Errorf("CheckBanStatus() error = %v, wantErr %v", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Errorf("CheckBanStatus() unexpected error = %v", err)
			}
		})
	}
}
