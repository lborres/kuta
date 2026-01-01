package core

import (
	"fmt"
	"time"

	"github.com/lborres/kuta/pkg/crypto"
)

// SignUpInput contains the data needed to register a new user
type SignUpInput struct {
	Email    string
	Password string
	Name     string
	Image    *string
}

// SignUpResult contains the newly created user and their first session
type SignUpResult struct {
	User    *User    `json:"user"`
	Session *Session `json:"session"`
	Token   string   `json:"token"` // The raw token (not the hash)
}

// SignUp registers a new user with email and password
func (k *Kuta) SignUp(input SignUpInput, ipAddress, userAgent string) (*SignUpResult, error) {
	// Step 1: Check if user already exists
	existingUser, err := k.Database.GetUserByEmail(input.Email)
	if err != nil && err != ErrUserNotFound {
		return nil, fmt.Errorf("failed to check existing user: %w", err)
	}
	if existingUser != nil {
		return nil, ErrUserExists
	}

	// Step 2: Hash the password
	hashedPassword, err := k.PasswordHasher.Hash(input.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Step 3: Create the user
	user := &User{
		Email:         input.Email,
		EmailVerified: false, // You can change this based on your requirements
		Name:          input.Name,
		Image:         input.Image,
	}

	err = k.Database.CreateUser(user)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Step 4: Create a credential account for this user
	account := &Account{
		UserID:     user.ID,
		ProviderID: "credential", // This is email/password authentication
		AccountID:  user.ID,      // For credential provider, account ID = user ID
		Password:   &hashedPassword,
	}

	err = k.Database.CreateAccount(account)
	if err != nil {
		return nil, fmt.Errorf("failed to create account: %w", err)
	}

	// Step 5: Create a session for the new user
	sessionResult, err := k.SessionManager.Create(user.ID, ipAddress, userAgent)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	return &SignUpResult{
		User:    user,
		Session: sessionResult.Session,
		Token:   sessionResult.Token,
	}, nil
}

// SignInInput contains the credentials for authentication
type SignInInput struct {
	Email    string
	Password string
}

// SignInResult contains the authenticated user and their session
type SignInResult struct {
	User    *User    `json:"user"`
	Session *Session `json:"session"`
	Token   string   `json:"token"` // The raw token (not the hash)
}

// SignIn authenticates a user with email and password
func (k *Kuta) SignIn(input SignInInput, ipAddress, userAgent string) (*SignInResult, error) {
	// Step 1: Find the user by email
	user, err := k.Database.GetUserByEmail(input.Email)
	if err != nil {
		if err == ErrUserNotFound {
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("failed to find user: %w", err)
	}

	// Step 2: Get the credential account for this user
	accounts, err := k.Database.GetAccountByUserAndProvider(user.ID, "credential")
	if err != nil {
		return nil, fmt.Errorf("failed to get account: %w", err)
	}
	if len(accounts) == 0 {
		return nil, ErrInvalidCredentials
	}

	account := accounts[0]
	if account.Password == nil {
		return nil, ErrInvalidCredentials
	}

	// Step 3: Verify the password
	valid, err := k.PasswordHasher.Verify(input.Password, *account.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to verify password: %w", err)
	}
	if !valid {
		return nil, ErrInvalidCredentials
	}

	// Step 4: Create a new session
	sessionResult, err := k.SessionManager.Create(user.ID, ipAddress, userAgent)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	return &SignInResult{
		User:    user,
		Session: sessionResult.Session,
		Token:   sessionResult.Token,
	}, nil
}

// SignOut invalidates the current session
func (k *Kuta) SignOut(tokenHash string) error {
	err := k.Database.DeleteSessionByHash(tokenHash)
	if err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}
	return nil
}

// GetSession retrieves session data by token
func (k *Kuta) GetSession(token string) (*SessionData, error) {
	// Hash the token to look it up
	tokenHash := crypto.HashToken(token)

	// Get session from storage
	session, err := k.Database.GetSessionByHash(tokenHash)
	if err != nil {
		if err == ErrSessionNotFound {
			return nil, ErrInvalidToken
		}
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	// Check if session is expired
	if session.ExpiresAt.Before(time.Now()) {
		return nil, ErrSessionExpired
	}

	// Get the user
	user, err := k.Database.GetUserByID(session.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return &SessionData{
		User:    user,
		Session: session,
	}, nil
}
