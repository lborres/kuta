package services

import (
	"regexp"
	"strings"
	"time"

	"github.com/lborres/kuta/core"
	"github.com/lborres/kuta/pkg/crypto"
)

const (
	minPasswordLength = 8
	maxPasswordLength = 128
	maxEmailLength    = 254 // RFC 5321 standard
	maxNameLength     = 255 // Reasonable limit for user names
)

// Simple email validation regex
var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

// validateEmail checks if the email format is valid
func validateEmail(email string) error {
	if email == "" {
		return core.ErrEmailRequired
	}
	if len(email) > maxEmailLength {
		return core.ErrInvalidEmail
	}
	// Reject emails containing HTML special characters
	if strings.ContainsAny(email, "<>'\"") {
		return core.ErrInvalidEmail
	}
	if !emailRegex.MatchString(email) {
		return core.ErrInvalidEmail
	}
	return nil
}

// validatePassword checks if the password meets length and complexity requirements
func validatePassword(password string) error {
	if password == "" {
		return core.ErrPasswordRequired
	}
	if len(password) < minPasswordLength {
		return core.ErrPasswordTooShort
	}
	if len(password) > maxPasswordLength {
		return core.ErrPasswordTooLong
	}

	// Check for at least one uppercase letter
	hasUpper := false
	for _, char := range password {
		if char >= 'A' && char <= 'Z' {
			hasUpper = true
			break
		}
	}
	if !hasUpper {
		return core.ErrPasswordComplexity
	}

	// Check for at least one special character
	specialChars := "!@#$%^&*()_+-=[]{}|;:',.<>?/~`\""
	hasSpecial := false
	for _, char := range password {
		for _, special := range specialChars {
			if char == special {
				hasSpecial = true
				break
			}
		}
		if hasSpecial {
			break
		}
	}
	if !hasSpecial {
		return core.ErrPasswordComplexity
	}

	return nil
}

// validateName checks if the name meets length requirements
func validateName(name string) error {
	if len(name) > maxNameLength {
		return core.ErrNameTooLong
	}
	return nil
}

// sanitizeInput removes HTML tags and dangerous characters from user input
func sanitizeInput(input string) string {
	// Strip HTML tags using regex
	htmlTagRegex := regexp.MustCompile(`<[^>]*>`)
	sanitized := htmlTagRegex.ReplaceAllString(input, "")

	// Remove common XSS patterns
	sanitized = strings.ReplaceAll(sanitized, "javascript:", "")
	sanitized = strings.ReplaceAll(sanitized, "onerror=", "")
	sanitized = strings.ReplaceAll(sanitized, "onload=", "")

	return strings.TrimSpace(sanitized)
}

// SessionManager handles both session management and authentication operations.
// It combines session lifecycle (create, verify, destroy) with authentication
// flows (signup, signin, signout) since all these operations are related to
// session management.
type SessionManager struct {
	config    core.SessionConfig
	storage   core.StorageProvider
	cache     core.Cache // optional, can be nil if caching is disabled
	nanoid    *crypto.NanoIDGenerator
	passwords crypto.PasswordHandler
}

func NewSessionManager(config core.SessionConfig, storage core.StorageProvider, cache core.Cache, passwords crypto.PasswordHandler) *SessionManager {
	nanoid, _ := crypto.NewNanoID()
	return &SessionManager{
		config:    config,
		storage:   storage,
		cache:     cache,
		nanoid:    nanoid,
		passwords: passwords,
	}
}

func (sm *SessionManager) Create(userID, ip, userAgent string) (*core.CreateSessionResult, error) {
	// Generate cryptographic material
	pair, err := crypto.GenerateHashedToken()
	if err != nil {
		return nil, err
	}

	sessionID, err := sm.nanoid.Generate()
	if err != nil {
		return nil, err
	}

	// Create session with timestamps and expiry
	now := time.Now()
	session := &core.Session{
		ID:        sessionID,
		UserID:    userID,
		TokenHash: pair.Hash,
		IPAddress: ip,
		UserAgent: userAgent,
		CreatedAt: now,
		UpdatedAt: now,
		ExpiresAt: now.Add(sm.config.ExpiresIn),
	}

	// Persist session
	if err := sm.storage.CreateSession(session); err != nil {
		return nil, err
	}

	// Cache session if caching is enabled (cache is non-nil)
	if sm.cache != nil {
		// We don't fail the request if caching fails
		_ = sm.cache.Set(pair.Hash, session)
	}

	return &core.CreateSessionResult{Session: session, Token: pair.Token}, nil
}

func (sm *SessionManager) Verify(token string) (*core.Session, error) {
	// Validate input
	if token == "" {
		return nil, core.ErrInvalidToken
	}

	tokenHash := crypto.HashToken(token)

	// Try cache first if caching is enabled
	if sm.cache != nil {
		if session, err := sm.cache.Get(tokenHash); err == nil {
			// Cache hit - validate expiry
			if time.Now().After(session.ExpiresAt) {
				// Remove expired session from cache
				_ = sm.cache.Delete(tokenHash)
				return nil, core.ErrSessionExpired
			}
			return session, nil
		}
		// Cache miss - fall through to storage
	}

	// Get from storage
	session, err := sm.storage.GetSessionByHash(tokenHash)
	if err != nil {
		return nil, err
	}
	if session == nil {
		return nil, core.ErrSessionNotFound
	}

	// Validate session hasn't expired
	if time.Now().After(session.ExpiresAt) {
		return nil, core.ErrSessionExpired
	}

	// Cache the session for future requests if caching is enabled
	if sm.cache != nil {
		_ = sm.cache.Set(tokenHash, session)
	}

	return session, nil
}

func (sm *SessionManager) Destroy(token string) error {
	// Validate input
	if token == "" {
		return core.ErrInvalidToken
	}

	// Hash token to find session
	tokenHash := crypto.HashToken(token)

	// Delete session from storage by hash
	err := sm.storage.DeleteSessionByHash(tokenHash)
	if err != nil {
		return err
	}

	// Remove from cache if caching is enabled
	if sm.cache != nil {
		_ = sm.cache.Delete(tokenHash)
	}

	return nil
}

func (sm *SessionManager) DestroyBySessionID(sessionID string) error {
	// Validate input
	if sessionID == "" {
		return core.ErrSessionNotFound
	}

	// Get session first to obtain tokenHash for cache invalidation
	if sm.cache != nil {
		session, err := sm.storage.GetSessionByID(sessionID)
		if err == nil && session != nil {
			// Remove from cache (ignore errors)
			_ = sm.cache.Delete(session.TokenHash)
		}
	}

	// Delete session from storage by ID
	return sm.storage.DeleteSessionByID(sessionID)
}

func (sm *SessionManager) DestroyAllUserSessions(userID string) (int, error) {
	// Validate input
	if userID == "" {
		return 0, core.ErrUserNotFound
	}

	// Delete all user sessions from storage
	count, err := sm.storage.DeleteUserSessions(userID)
	if err != nil {
		return 0, err
	}

	// Clear entire cache when destroying all user sessions if caching is enabled
	// This is a conservative approach - we could be more selective but would need
	// to fetch all user sessions first, which defeats the performance benefit
	if sm.cache != nil && count > 0 {
		_ = sm.cache.Clear()
	}

	return count, nil
}

// SignUp creates a new user account and session.
func (sm *SessionManager) SignUp(input core.SignUpInput, ipAddress, userAgent string) (*core.SignUpResult, error) {
	// Validate email
	if err := validateEmail(input.Email); err != nil {
		return nil, err
	}

	// Validate password
	if err := validatePassword(input.Password); err != nil {
		return nil, err
	}

	// Validate name length
	if err := validateName(input.Name); err != nil {
		return nil, err
	}

	// Sanitize name input to prevent XSS
	sanitizedName := sanitizeInput(input.Name)

	// Check if user already exists
	_, err := sm.storage.GetUserByEmail(input.Email)
	if err == nil {
		// User exists
		return nil, core.ErrUserExists
	}
	if err != core.ErrUserNotFound {
		// Some other error occurred
		return nil, err
	}

	// Hash password
	hashedPassword, err := sm.passwords.Hash(input.Password)
	if err != nil {
		return nil, err
	}

	// Generate user ID
	userID, err := sm.nanoid.Generate()
	if err != nil {
		return nil, err
	}

	// Create user
	now := time.Now()
	user := &core.User{
		ID:        userID,
		Email:     input.Email,
		Name:      sanitizedName,
		Image:     input.Image,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := sm.storage.CreateUser(user); err != nil {
		return nil, err
	}

	// Create account with hashed password
	accountID, err := sm.nanoid.Generate()
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

	if err := sm.storage.CreateAccount(account); err != nil {
		// Cleanup: delete the user if account creation fails
		_ = sm.storage.DeleteUser(userID)
		return nil, err
	}

	// Create session
	sessionResult, err := sm.Create(userID, ipAddress, userAgent)
	if err != nil {
		// Cleanup: delete user and account if session creation fails
		_ = sm.storage.DeleteUser(userID)
		_ = sm.storage.DeleteAccount(accountID)
		return nil, err
	}

	return &core.SignUpResult{
		User:    user,
		Session: sessionResult.Session,
		Token:   sessionResult.Token,
	}, nil
}

// SignIn authenticates a user and creates a session.
func (sm *SessionManager) SignIn(input core.SignInInput, ipAddress, userAgent string) (*core.SignInResult, error) {
	// Validate email
	if err := validateEmail(input.Email); err != nil {
		return nil, err
	}

	// Validate password
	if err := validatePassword(input.Password); err != nil {
		return nil, err
	}

	// Get user by email
	user, err := sm.storage.GetUserByEmail(input.Email)
	if err != nil {
		if err == core.ErrUserNotFound {
			return nil, core.ErrUserNotFound
		}
		return nil, err
	}

	// Get account(s) for this user with credential provider
	accounts, err := sm.storage.GetAccountByUserAndProvider(user.ID, "credential")
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
	match, err := sm.passwords.Verify(input.Password, *account.Password)
	if err != nil {
		return nil, err
	}
	if !match {
		return nil, core.ErrInvalidCredentials
	}

	// Create session
	sessionResult, err := sm.Create(user.ID, ipAddress, userAgent)
	if err != nil {
		return nil, err
	}

	return &core.SignInResult{
		User:    user,
		Session: sessionResult.Session,
		Token:   sessionResult.Token,
	}, nil
}

// SignOut destroys a session (alias for Destroy for clearer API naming).
func (sm *SessionManager) SignOut(token string) error {
	return sm.Destroy(token)
}

// GetSession retrieves session data by token and returns user information.
func (sm *SessionManager) GetSession(token string) (*core.SessionData, error) {
	// Validate input
	if token == "" {
		return nil, core.ErrInvalidToken
	}

	// Verify session by token
	session, err := sm.Verify(token)
	if err != nil {
		return nil, err
	}

	// Get user
	user, err := sm.storage.GetUserByID(session.UserID)
	if err != nil {
		return nil, err
	}

	return &core.SessionData{
		Session: session,
		User:    user,
	}, nil
}

// Refresh extends a session's expiry time and returns a new session and token.
// The old token becomes invalid immediately.
func (sm *SessionManager) Refresh(token string) (*core.RefreshResult, error) {
	// Validate input
	if token == "" {
		return nil, core.ErrInvalidToken
	}

	// Verify current session by token
	oldSession, err := sm.Verify(token)
	if err != nil {
		return nil, err
	}

	// Destroy old session
	if err := sm.Destroy(token); err != nil {
		return nil, err
	}

	// Create new session with same userID, IP, and UserAgent
	newSessionResult, err := sm.Create(oldSession.UserID, oldSession.IPAddress, oldSession.UserAgent)
	if err != nil {
		return nil, err
	}

	return &core.RefreshResult{
		Session: newSessionResult.Session,
		Token:   newSessionResult.Token,
	}, nil
}
