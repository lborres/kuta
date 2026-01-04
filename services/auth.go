package services

import (
	"time"

	"github.com/lborres/kuta/core"
	"github.com/lborres/kuta/pkg/crypto"
)

// AuthService handles user authentication (signup, signin, signout).
type AuthService struct {
	storage   core.StorageProvider
	sessions  *SessionManager
	passwords crypto.PasswordHandler
	nanoid    *crypto.NanoIDGenerator
}

// NewAuthService creates a new authentication service.
func NewAuthService(
	storage core.StorageProvider,
	sessions *SessionManager,
	passwords crypto.PasswordHandler,
) *AuthService {
	nanoid, _ := crypto.NewNanoID()
	return &AuthService{
		storage:   storage,
		sessions:  sessions,
		passwords: passwords,
		nanoid:    nanoid,
	}
}

// SignUp creates a new user and session.
func (as *AuthService) SignUp(input core.SignUpInput, ipAddress, userAgent string) (*core.SignUpResult, error) {
	// Validate email
	if input.Email == "" {
		return nil, core.ErrEmailRequired
	}

	// Validate password
	if input.Password == "" {
		return nil, core.ErrPasswordRequired
	}

	// Check if user already exists
	_, err := as.storage.GetUserByEmail(input.Email)
	if err == nil {
		// User exists
		return nil, core.ErrUserExists
	}
	if err != core.ErrUserNotFound {
		// Some other error occurred
		return nil, err
	}

	// Hash password
	hashedPassword, err := as.passwords.Hash(input.Password)
	if err != nil {
		return nil, err
	}

	// Generate user ID
	userID, err := as.nanoid.Generate()
	if err != nil {
		return nil, err
	}

	// Create user
	now := time.Now()
	user := &core.User{
		ID:        userID,
		Email:     input.Email,
		Name:      input.Name,
		Image:     input.Image,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := as.storage.CreateUser(user); err != nil {
		return nil, err
	}

	// Create account with hashed password
	accountID, err := as.nanoid.Generate()
	if err != nil {
		return nil, err
	}

	account := &core.Account{
		ID:         accountID,
		UserID:     userID,
		ProviderID: "credential", // Default credential provider
		AccountID:  input.Email,  // Store email as account identifier
		Password:   &hashedPassword,
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	if err := as.storage.CreateAccount(account); err != nil {
		// Cleanup: delete the user if account creation fails
		_ = as.storage.DeleteUser(userID)
		return nil, err
	}

	// Create session
	sessionResult, err := as.sessions.Create(userID, ipAddress, userAgent)
	if err != nil {
		// Cleanup: delete user and account if session creation fails
		_ = as.storage.DeleteUser(userID)
		_ = as.storage.DeleteAccount(accountID)
		return nil, err
	}

	return &core.SignUpResult{
		User:    user,
		Session: sessionResult.Session,
		Token:   sessionResult.Token,
	}, nil
}

// SignIn authenticates a user and creates a session.
func (as *AuthService) SignIn(input core.SignInInput, ipAddress, userAgent string) (*core.SignInResult, error) {
	// Validate email
	if input.Email == "" {
		return nil, core.ErrEmailRequired
	}

	// Validate password
	if input.Password == "" {
		return nil, core.ErrPasswordRequired
	}

	// Get user by email
	user, err := as.storage.GetUserByEmail(input.Email)
	if err != nil {
		if err == core.ErrUserNotFound {
			return nil, core.ErrUserNotFound
		}
		return nil, err
	}

	// Get account(s) for this user with credential provider
	accounts, err := as.storage.GetAccountByUserAndProvider(user.ID, "credential")
	if err != nil {
		return nil, err
	}
	if len(accounts) == 0 {
		return nil, core.ErrInvalidCredentials
	}

	// Find account with password and verify
	var account *core.Account
	for _, acc := range accounts {
		if acc.Password != nil {
			account = acc
			break
		}
	}
	if account == nil {
		return nil, core.ErrInvalidCredentials
	}

	// Verify password
	match, err := as.passwords.Verify(input.Password, *account.Password)
	if err != nil {
		return nil, err
	}
	if !match {
		return nil, core.ErrInvalidCredentials
	}

	// Create session
	sessionResult, err := as.sessions.Create(user.ID, ipAddress, userAgent)
	if err != nil {
		return nil, err
	}

	return &core.SignInResult{
		User:    user,
		Session: sessionResult.Session,
		Token:   sessionResult.Token,
	}, nil
}

// SignOut destroys a session.
func (as *AuthService) SignOut(token string) error {
	return as.sessions.Destroy(token)
}

// GetSession retrieves session data by token.
func (as *AuthService) GetSession(token string) (*core.SessionData, error) {
	// Validate input
	if token == "" {
		return nil, core.ErrInvalidToken
	}

	// Verify session by token
	session, err := as.sessions.Verify(token)
	if err != nil {
		return nil, err
	}

	// Get user
	user, err := as.storage.GetUserByID(session.UserID)
	if err != nil {
		return nil, err
	}

	return &core.SessionData{
		Session: session,
		User:    user,
	}, nil
}
