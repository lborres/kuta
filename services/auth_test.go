package services

import (
	"testing"
	"time"

	"github.com/lborres/kuta/core"
	"github.com/lborres/kuta/pkg/crypto"
)

// Requirement: SignUp creates a new user account and returns a result with user and session.
func TestAuthService_SignUp(t *testing.T) {
	tests := []struct {
		name      string
		email     string
		password  string
		setup     func(*FakeStorageProvider) // optional setup before SignUp
		wantErr   bool
		wantUser  bool
		wantToken bool
	}{
		{
			name:      "creates user and session for valid input",
			email:     "alice@example.com",
			password:  "SecurePass123!",
			wantErr:   false,
			wantUser:  true,
			wantToken: true,
		},
		{
			name:     "returns error for empty email",
			email:    "",
			password: "SecurePass123!",
			wantErr:  true,
		},
		{
			name:     "returns error for empty password",
			email:    "alice@example.com",
			password: "",
			wantErr:  true,
		},
		{
			name:     "returns error for duplicate email",
			email:    "alice@example.com",
			password: "SecurePass123!",
			setup: func(storage *FakeStorageProvider) {
				// Create a user with this email first
				_ = storage.CreateUser(&core.User{
					ID:    "existing-user",
					Email: "alice@example.com",
				})
			},
			wantErr: true,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			// Arrange
			storage := NewFakeStorageProvider()
			if test.setup != nil {
				test.setup(storage)
			}
			sm := NewSessionManager(core.SessionConfig{MaxAge: 24 * time.Hour}, storage, nil)
			passwords := crypto.NewArgon2()
			service := NewAuthService(storage, sm, passwords)

			// Act
			result, err := service.SignUp(core.SignUpInput{
				Email:    test.email,
				Password: test.password,
			}, "127.0.0.1", "test-agent")

			// Assert
			if (err != nil) != test.wantErr {
				t.Fatalf("SignUp() error = %v, wantErr %v", err, test.wantErr)
			}
			if test.wantUser && result != nil && result.User == nil {
				t.Error("SignUp() should return user")
			}
			if test.wantToken && result != nil && result.Token == "" {
				t.Error("SignUp() should return token")
			}
		})
	}
}

// Requirement: SignIn authenticates a user by email and password, creates a session, and returns user + token.
func TestAuthService_SignIn(t *testing.T) {
	tests := []struct {
		name      string
		email     string
		password  string
		setup     func(*FakeStorageProvider, crypto.PasswordHandler) // setup user + account before SignIn
		wantErr   bool
		wantUser  bool
		wantToken bool
	}{
		{
			name:     "signs in user with valid credentials",
			email:    "alice@example.com",
			password: "SecurePass123!",
			setup: func(storage *FakeStorageProvider, passwords crypto.PasswordHandler) {
				// Create user
				user := &core.User{
					ID:    "user-alice",
					Email: "alice@example.com",
				}
				_ = storage.CreateUser(user)
				// Create account with hashed password
				hashedPassword, _ := passwords.Hash("SecurePass123!")
				account := &core.Account{
					ID:         "account-alice",
					UserID:     "user-alice",
					ProviderID: "credential",
					AccountID:  "alice@example.com",
					Password:   &hashedPassword,
				}
				_ = storage.CreateAccount(account)
			},
			wantErr:   false,
			wantUser:  true,
			wantToken: true,
		},
		{
			name:     "returns error for empty email",
			email:    "",
			password: "SecurePass123!",
			wantErr:  true,
		},
		{
			name:     "returns error for empty password",
			email:    "alice@example.com",
			password: "",
			wantErr:  true,
		},
		{
			name:     "returns error for user not found",
			email:    "nonexistent@example.com",
			password: "SecurePass123!",
			wantErr:  true,
		},
		{
			name:     "returns error for wrong password",
			email:    "alice@example.com",
			password: "WrongPassword123!",
			setup: func(storage *FakeStorageProvider, passwords crypto.PasswordHandler) {
				// Create user
				user := &core.User{
					ID:    "user-alice",
					Email: "alice@example.com",
				}
				_ = storage.CreateUser(user)
				// Create account with correct hashed password
				hashedPassword, _ := passwords.Hash("CorrectPassword123!")
				account := &core.Account{
					ID:         "account-alice",
					UserID:     "user-alice",
					ProviderID: "credential",
					AccountID:  "alice@example.com",
					Password:   &hashedPassword,
				}
				_ = storage.CreateAccount(account)
			},
			wantErr: true,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			// Arrange
			storage := NewFakeStorageProvider()
			passwords := crypto.NewArgon2()
			sm := NewSessionManager(core.SessionConfig{MaxAge: 24 * time.Hour}, storage, nil)
			service := NewAuthService(storage, sm, passwords)
			if test.setup != nil {
				test.setup(storage, passwords)
			}

			// Act
			result, err := service.SignIn(core.SignInInput{
				Email:    test.email,
				Password: test.password,
			}, "127.0.0.1", "test-agent")

			// Assert
			if (err != nil) != test.wantErr {
				t.Fatalf("SignIn() error = %v, wantErr %v", err, test.wantErr)
			}
			if test.wantUser && result != nil && result.User == nil {
				t.Error("SignIn() should return user")
			}
			if test.wantToken && result != nil && result.Token == "" {
				t.Error("SignIn() should return token")
			}
			if test.wantUser && result != nil && result.User.Email != test.email {
				t.Errorf("SignIn() returned wrong email: got %q, want %q", result.User.Email, test.email)
			}
		})
	}
}

// Requirement: SignOut destroys a session and prevents further use of the token.
func TestAuthService_SignOut(t *testing.T) {
	tests := []struct {
		name      string
		setupAuth func(*FakeStorageProvider, crypto.PasswordHandler) string // returns token
		token     string
		wantErr   bool
	}{
		{
			name: "successfully signs out user",
			setupAuth: func(storage *FakeStorageProvider, passwords crypto.PasswordHandler) string {
				user := &core.User{ID: "user-alice", Email: "alice@example.com"}
				_ = storage.CreateUser(user)
				hashedPassword, _ := passwords.Hash("SecurePass123!")
				account := &core.Account{
					ID:         "account-alice",
					UserID:     "user-alice",
					ProviderID: "credential",
					AccountID:  "alice@example.com",
					Password:   &hashedPassword,
				}
				_ = storage.CreateAccount(account)

				sm := NewSessionManager(core.SessionConfig{MaxAge: 24 * time.Hour}, storage, nil)
				service := NewAuthService(storage, sm, passwords)
				result, _ := service.SignIn(core.SignInInput{
					Email:    "alice@example.com",
					Password: "SecurePass123!",
				}, "127.0.0.1", "test-agent")
				return result.Token
			},
			wantErr: false,
		},
		{
			name:    "returns error for empty token",
			token:   "",
			wantErr: true,
		},
		{
			name:    "returns error for invalid token",
			token:   "invalid_token_xyz",
			wantErr: true,
		},
		{
			name: "prevents token use after signout",
			setupAuth: func(storage *FakeStorageProvider, passwords crypto.PasswordHandler) string {
				user := &core.User{ID: "user-bob", Email: "bob@example.com"}
				_ = storage.CreateUser(user)
				hashedPassword, _ := passwords.Hash("SecurePass123!")
				account := &core.Account{
					ID:         "account-bob",
					UserID:     "user-bob",
					ProviderID: "credential",
					AccountID:  "bob@example.com",
					Password:   &hashedPassword,
				}
				_ = storage.CreateAccount(account)

				sm := NewSessionManager(core.SessionConfig{MaxAge: 24 * time.Hour}, storage, nil)
				service := NewAuthService(storage, sm, passwords)
				result, _ := service.SignIn(core.SignInInput{
					Email:    "bob@example.com",
					Password: "SecurePass123!",
				}, "127.0.0.1", "test-agent")
				return result.Token
			},
			wantErr: false,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			// Arrange
			storage := NewFakeStorageProvider()
			passwords := crypto.NewArgon2()
			sm := NewSessionManager(core.SessionConfig{MaxAge: 24 * time.Hour}, storage, nil)
			service := NewAuthService(storage, sm, passwords)

			token := test.token
			if test.setupAuth != nil {
				token = test.setupAuth(storage, passwords)
			}

			// Act
			err := service.SignOut(token)

			// Assert
			if (err != nil) != test.wantErr {
				t.Fatalf("SignOut() error = %v, wantErr %v", err, test.wantErr)
			}

			// If signout succeeded, verify token can't be used
			if !test.wantErr && test.name == "prevents token use after signout" {
				_, err := service.GetSession(token)
				if err == nil {
					t.Error("GetSession() should fail after SignOut()")
				}
			}
		})
	}
}

// Requirement: GetSession retrieves session data by token, validates expiry, and returns user info.
func TestAuthService_GetSession(t *testing.T) {
	tests := []struct {
		name        string
		setupAuth   func(*FakeStorageProvider, crypto.PasswordHandler) string // returns token
		token       string
		withExpired bool // create expired session
		wantErr     bool
		wantSession bool
	}{
		{
			name: "returns session data for valid token",
			setupAuth: func(storage *FakeStorageProvider, passwords crypto.PasswordHandler) string {
				user := &core.User{ID: "user-alice", Email: "alice@example.com"}
				_ = storage.CreateUser(user)
				hashedPassword, _ := passwords.Hash("SecurePass123!")
				account := &core.Account{
					ID:         "account-alice",
					UserID:     "user-alice",
					ProviderID: "credential",
					AccountID:  "alice@example.com",
					Password:   &hashedPassword,
				}
				_ = storage.CreateAccount(account)

				sm := NewSessionManager(core.SessionConfig{MaxAge: 24 * time.Hour}, storage, nil)
				service := NewAuthService(storage, sm, passwords)
				result, _ := service.SignIn(core.SignInInput{
					Email:    "alice@example.com",
					Password: "SecurePass123!",
				}, "127.0.0.1", "test-agent")
				return result.Token
			},
			wantErr:     false,
			wantSession: true,
		},
		{
			name:        "returns error for empty token",
			token:       "",
			wantErr:     true,
			wantSession: false,
		},
		{
			name:        "returns error for invalid token",
			token:       "invalid_token_xyz",
			wantErr:     true,
			wantSession: false,
		},
		{
			name: "returns error for expired session",
			setupAuth: func(storage *FakeStorageProvider, passwords crypto.PasswordHandler) string {
				user := &core.User{ID: "user-charlie", Email: "charlie@example.com"}
				_ = storage.CreateUser(user)
				hashedPassword, _ := passwords.Hash("SecurePass123!")
				account := &core.Account{
					ID:         "account-charlie",
					UserID:     "user-charlie",
					ProviderID: "credential",
					AccountID:  "charlie@example.com",
					Password:   &hashedPassword,
				}
				_ = storage.CreateAccount(account)

				// Create with expired session config
				sm := NewSessionManager(core.SessionConfig{MaxAge: -1 * time.Hour}, storage, nil)
				service := NewAuthService(storage, sm, passwords)
				result, _ := service.SignIn(core.SignInInput{
					Email:    "charlie@example.com",
					Password: "SecurePass123!",
				}, "127.0.0.1", "test-agent")
				return result.Token
			},
			wantErr:     true,
			wantSession: false,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			// Arrange
			storage := NewFakeStorageProvider()
			passwords := crypto.NewArgon2()
			sm := NewSessionManager(core.SessionConfig{MaxAge: 24 * time.Hour}, storage, nil)
			service := NewAuthService(storage, sm, passwords)

			token := test.token
			if test.setupAuth != nil {
				token = test.setupAuth(storage, passwords)
			}

			// Act
			sessionData, err := service.GetSession(token)

			// Assert
			if (err != nil) != test.wantErr {
				t.Fatalf("GetSession() error = %v, wantErr %v", err, test.wantErr)
			}
			if test.wantSession && sessionData == nil {
				t.Error("GetSession() should return session data")
			}
			if !test.wantSession && sessionData != nil {
				t.Error("GetSession() should return error")
			}
			if test.wantSession && sessionData != nil {
				if sessionData.Session == nil {
					t.Error("SessionData.Session is nil")
				}
				if sessionData.User == nil {
					t.Error("SessionData.User is nil")
				}
			}
		})
	}
}
