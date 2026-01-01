package services

import (
	"fmt"
	"time"

	"github.com/lborres/kuta/core"
	"github.com/lborres/kuta/pkg/crypto"
)

type AuthService struct {
	db             core.StorageAdapter
	passwordHasher crypto.PasswordHandler
	sessionManager SessionManager
}

// Ensure AuthService implements AuthHandler
var _ core.AuthHandler = (*AuthService)(nil)

func NewAuthService(db *core.StorageAdapter, passwordHasher *crypto.PasswordHandler, sessionManager *SessionManager) *AuthService {
	return &AuthService{
		db:             *db,
		passwordHasher: *passwordHasher,
		sessionManager: *sessionManager,
	}
}

// SignUp registers a new user with email and password
func (s *AuthService) SignUp(input core.SignUpInput, ipAddress, userAgent string) (*core.SignUpResult, error) {
	// Step 1: Check if user already exists
	existingUser, err := s.db.GetUserByEmail(input.Email)
	if err != nil && err != core.ErrUserNotFound {
		return nil, fmt.Errorf("failed to check existing user: %w", err)
	}
	if existingUser != nil {
		return nil, core.ErrUserExists
	}

	// Step 2: Hash the password
	hashedPassword, err := s.passwordHasher.Hash(input.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Step 3: Create the user
	user := &core.User{
		Email:         input.Email,
		EmailVerified: false, // You can change this based on your requirements
		Name:          input.Name,
		Image:         input.Image,
	}

	err = s.db.CreateUser(user)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Step 4: Create a credential account for this user
	account := &core.Account{
		UserID:     user.ID,
		ProviderID: "credential", // This is email/password authentication
		AccountID:  user.ID,      // For credential provider, account ID = user ID
		Password:   &hashedPassword,
	}

	err = s.db.CreateAccount(account)
	if err != nil {
		return nil, fmt.Errorf("failed to create account: %w", err)
	}

	// Step 5: Create a session for the new user
	sessionResult, err := s.sessionManager.Create(user.ID, ipAddress, userAgent)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	return &core.SignUpResult{
		User:    user,
		Session: sessionResult.Session,
		Token:   sessionResult.Token,
	}, nil
}

// SignIn authenticates a user with email and password
func (s *AuthService) SignIn(input core.SignInInput, ipAddress, userAgent string) (*core.SignInResult, error) {
	// Step 1: Find the user by email
	user, err := s.db.GetUserByEmail(input.Email)
	if err != nil {
		if err == core.ErrUserNotFound {
			return nil, core.ErrInvalidCredentials
		}
		return nil, fmt.Errorf("failed to find user: %w", err)
	}

	// Step 2: Get the credential account for this user
	accounts, err := s.db.GetAccountByUserAndProvider(user.ID, "credential")
	if err != nil {
		return nil, fmt.Errorf("failed to get account: %w", err)
	}
	if len(accounts) == 0 {
		return nil, core.ErrInvalidCredentials
	}

	account := accounts[0]
	if account.Password == nil {
		return nil, core.ErrInvalidCredentials
	}

	// Step 3: Verify the password
	valid, err := s.passwordHasher.Verify(input.Password, *account.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to verify password: %w", err)
	}
	if !valid {
		return nil, core.ErrInvalidCredentials
	}

	// Step 4: Create a new session
	sessionResult, err := s.sessionManager.Create(user.ID, ipAddress, userAgent)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	return &core.SignInResult{
		User:    user,
		Session: sessionResult.Session,
		Token:   sessionResult.Token,
	}, nil
}

// SignOut invalidates the current session
func (s *AuthService) SignOut(tokenHash string) error {
	err := s.db.DeleteSessionByHash(tokenHash)
	if err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}
	return nil
}

// GetSession retrieves session data by token
func (s *AuthService) GetSession(token string) (*core.SessionData, error) {
	// Hash the token to look it up
	tokenHash := crypto.HashToken(token)

	// Get session from storage
	session, err := s.db.GetSessionByHash(tokenHash)
	if err != nil {
		if err == core.ErrSessionNotFound {
			return nil, core.ErrInvalidToken
		}
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	// Check if session is expired
	if session.ExpiresAt.Before(time.Now()) {
		return nil, core.ErrSessionExpired
	}

	// Get the user
	user, err := s.db.GetUserByID(session.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return &core.SessionData{
		User:    user,
		Session: session,
	}, nil
}
