package fiber

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/lborres/kuta/core"
	"github.com/lborres/kuta/pkg/cache"
	"github.com/lborres/kuta/pkg/crypto"
	"github.com/lborres/kuta/services"
)

// fakeStorage is an in-memory storage implementation for testing
type fakeStorage struct {
	users    map[string]*core.User    // keyed by ID
	accounts map[string]*core.Account // keyed by userID
	sessions map[string]*core.Session // keyed by token
	emails   map[string]string        // email -> userID lookup
	idGen    *crypto.NanoIDGenerator
}

func newFakeStorage() *fakeStorage {
	idGen, _ := crypto.NewNanoID()
	return &fakeStorage{
		users:    make(map[string]*core.User),
		accounts: make(map[string]*core.Account),
		sessions: make(map[string]*core.Session),
		emails:   make(map[string]string),
		idGen:    idGen,
	}
}

func (f *fakeStorage) CreateUser(user *core.User) error {
	if user.CreatedAt.IsZero() {
		user.CreatedAt = time.Now()
	}
	if user.UpdatedAt.IsZero() {
		user.UpdatedAt = time.Now()
	}
	f.users[user.ID] = user
	f.emails[user.Email] = user.ID
	return nil
}

func (f *fakeStorage) GetUserByID(id string) (*core.User, error) {
	user, ok := f.users[id]
	if !ok {
		return nil, core.ErrUserNotFound
	}
	return user, nil
}

func (f *fakeStorage) GetUserByEmail(email string) (*core.User, error) {
	userID, ok := f.emails[email]
	if !ok {
		return nil, core.ErrUserNotFound
	}
	return f.users[userID], nil
}

func (f *fakeStorage) UpdateUser(user *core.User) error {
	if _, ok := f.users[user.ID]; !ok {
		return core.ErrUserNotFound
	}
	user.UpdatedAt = time.Now()
	f.users[user.ID] = user
	return nil
}

func (f *fakeStorage) DeleteUser(id string) error {
	user, ok := f.users[id]
	if !ok {
		return core.ErrUserNotFound
	}
	delete(f.emails, user.Email)
	delete(f.users, id)
	return nil
}

func (f *fakeStorage) CreateAccount(account *core.Account) error {
	if account.CreatedAt.IsZero() {
		account.CreatedAt = time.Now()
	}
	if account.UpdatedAt.IsZero() {
		account.UpdatedAt = time.Now()
	}
	f.accounts[account.UserID] = account
	return nil
}

func (f *fakeStorage) GetAccountByUserID(userID string) (*core.Account, error) {
	account, ok := f.accounts[userID]
	if !ok {
		return nil, core.ErrUserNotFound
	}
	return account, nil
}

func (f *fakeStorage) UpdateAccount(account *core.Account) error {
	if _, ok := f.accounts[account.UserID]; !ok {
		return core.ErrUserNotFound
	}
	account.UpdatedAt = time.Now()
	f.accounts[account.UserID] = account
	return nil
}

func (f *fakeStorage) DeleteAccount(id string) error {
	for userID, account := range f.accounts {
		if account.ID == id {
			delete(f.accounts, userID)
			return nil
		}
	}
	return core.ErrUserNotFound
}

func (f *fakeStorage) CreateSession(session *core.Session) error {
	id, _ := f.idGen.Generate()
	session.ID = id
	session.CreatedAt = time.Now()
	session.UpdatedAt = time.Now()
	f.sessions[session.TokenHash] = session
	return nil
}

func (f *fakeStorage) GetSessionByToken(token string) (*core.Session, error) {
	// For testing, we use token as the hash directly
	session, ok := f.sessions[token]
	if !ok {
		return nil, core.ErrSessionNotFound
	}
	return session, nil
}

func (f *fakeStorage) UpdateSession(session *core.Session) error {
	if _, ok := f.sessions[session.TokenHash]; !ok {
		return core.ErrSessionNotFound
	}
	session.UpdatedAt = time.Now()
	f.sessions[session.TokenHash] = session
	return nil
}

func (f *fakeStorage) DeleteSession(id string) error {
	for token, session := range f.sessions {
		if session.ID == id {
			delete(f.sessions, token)
			return nil
		}
	}
	return core.ErrSessionNotFound
}

func (f *fakeStorage) DeleteSessionByID(id string) error {
	return f.DeleteSession(id)
}

func (f *fakeStorage) DeleteSessionByHash(tokenHash string) error {
	delete(f.sessions, tokenHash)
	return nil
}

func (f *fakeStorage) GetSessionByHash(tokenHash string) (*core.Session, error) {
	session, ok := f.sessions[tokenHash]
	if !ok {
		return nil, core.ErrSessionNotFound
	}
	return session, nil
}

func (f *fakeStorage) GetSessionByID(id string) (*core.Session, error) {
	for _, session := range f.sessions {
		if session.ID == id {
			return session, nil
		}
	}
	return nil, core.ErrSessionNotFound
}

func (f *fakeStorage) GetUserSessions(userID string) ([]*core.Session, error) {
	var sessions []*core.Session
	for _, session := range f.sessions {
		if session.UserID == userID {
			sessions = append(sessions, session)
		}
	}
	return sessions, nil
}

func (f *fakeStorage) DeleteUserSessions(userID string) (int, error) {
	count := 0
	for hash, session := range f.sessions {
		if session.UserID == userID {
			delete(f.sessions, hash)
			count++
		}
	}
	return count, nil
}

func (f *fakeStorage) DeleteExpiredSessions() (int, error) {
	count := 0
	now := time.Now()
	for hash, session := range f.sessions {
		if now.After(session.ExpiresAt) {
			delete(f.sessions, hash)
			count++
		}
	}
	return count, nil
}

func (f *fakeStorage) GetAccountByID(id string) (*core.Account, error) {
	for _, account := range f.accounts {
		if account.ID == id {
			return account, nil
		}
	}
	return nil, core.ErrUserNotFound
}

func (f *fakeStorage) GetAccountByUserAndProvider(userID, providerID string) ([]*core.Account, error) {
	account, ok := f.accounts[userID]
	if !ok {
		return nil, nil
	}
	if account.ProviderID != providerID {
		return nil, nil
	}
	return []*core.Account{account}, nil
}

// setupTestApp creates a complete kuta instance for testing
func setupTestApp(t *testing.T) (*fiber.App, *fakeStorage) {
	app := fiber.New()

	storage := newFakeStorage()
	cache := cache.NewInMemoryCache(core.CacheConfig{
		TTL:     5 * time.Minute,
		MaxSize: 100,
	})
	passwordMgr := crypto.NewArgon2()

	sessionMgr := services.NewSessionManager(
		core.SessionConfig{
			ExpiresIn:    time.Hour,
			UpdateAge:    30 * time.Minute,
			CookieConfig: core.DefaultCookieConfig(),
		},
		storage,
		cache,
		passwordMgr,
	)

	sessionCfg := &core.SessionConfig{
		ExpiresIn:    time.Hour,
		UpdateAge:    30 * time.Minute,
		CookieConfig: core.DefaultCookieConfig(),
	}

	adapter := New(app)
	if err := adapter.RegisterRoutes(sessionMgr, "/auth", sessionCfg); err != nil {
		t.Fatal(err)
	}

	return app, storage
}

// Requirement: Complete sign-up flow creates user and returns valid session
func TestIntegration_SignUpFlow(t *testing.T) {
	app, _ := setupTestApp(t)

	signUpBody, _ := json.Marshal(map[string]string{
		"email":    "test@example.com",
		"password": "Password123!",
		"name":     "Test User",
	})

	req := httptest.NewRequest("POST", "/auth/sign-up", bytes.NewReader(signUpBody))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}

	if resp.StatusCode != 201 {
		// Read the error body
		bodyBytes, _ := io.ReadAll(resp.Body)
		t.Fatalf("sign-up should return 201; got %d, body: %s", resp.StatusCode, string(bodyBytes))
	}

	var result core.SignUpResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}

	if result.User.Email != "test@example.com" {
		t.Errorf("user email should be test@example.com; got %s", result.User.Email)
	}

	resultJSON, _ := json.MarshalIndent(result, "", "  ")
	t.Logf("result: %s", resultJSON)

	if result.Token == "" {
		t.Error("sign-up should return a token")
	}
}

// Requirement: Sign-up with duplicate email returns 409 conflict
func TestIntegration_SignUpDuplicateEmail(t *testing.T) {
	app, _ := setupTestApp(t)

	signUpBody, _ := json.Marshal(map[string]string{
		"email":    "duplicate@example.com",
		"password": "Password123!",
	})

	// First sign-up
	req := httptest.NewRequest("POST", "/auth/sign-up", bytes.NewReader(signUpBody))
	req.Header.Set("Content-Type", "application/json")
	app.Test(req)

	// Second sign-up with same email
	req = httptest.NewRequest("POST", "/auth/sign-up", bytes.NewReader(signUpBody))
	req.Header.Set("Content-Type", "application/json")

	resp, _ := app.Test(req)
	if resp.StatusCode != 409 {
		t.Errorf("duplicate email should return 409; got %d", resp.StatusCode)
	}
}

// Requirement: Full authentication flow - sign-up, get session, sign-out
func TestIntegration_FullAuthFlow(t *testing.T) {
	app, _ := setupTestApp(t)

	// Step 1: Sign up
	signUpBody, _ := json.Marshal(map[string]string{
		"email":    "fullflow@example.com",
		"password": "Password123!",
	})

	req := httptest.NewRequest("POST", "/auth/sign-up", bytes.NewReader(signUpBody))
	req.Header.Set("Content-Type", "application/json")

	resp, _ := app.Test(req)
	var signUpResult core.SignUpResult
	json.NewDecoder(resp.Body).Decode(&signUpResult)
	token := signUpResult.Token

	if token == "" {
		t.Fatal("sign-up should return a token")
	}

	// Step 2: Get session
	req = httptest.NewRequest("GET", "/auth/session", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, _ = app.Test(req)
	if resp.StatusCode != 200 {
		t.Errorf("get session should return 200; got %d", resp.StatusCode)
	}

	var sessionData core.SessionData
	json.NewDecoder(resp.Body).Decode(&sessionData)
	if sessionData.User.Email != "fullflow@example.com" {
		t.Errorf("session user email should be fullflow@example.com; got %s", sessionData.User.Email)
	}

	// Step 3: Sign out
	req = httptest.NewRequest("POST", "/auth/sign-out", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, _ = app.Test(req)
	if resp.StatusCode != 200 {
		t.Errorf("sign-out should return 200; got %d", resp.StatusCode)
	}

	// Step 4: Session should be invalid
	req = httptest.NewRequest("GET", "/auth/session", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, _ = app.Test(req)
	if resp.StatusCode != 401 {
		t.Errorf("session after sign-out should return 401; got %d", resp.StatusCode)
	}
}

// Requirement: Sign-in with correct credentials returns session
func TestIntegration_SignInFlow(t *testing.T) {
	app, storage := setupTestApp(t)

	// Create user
	signUpBody, _ := json.Marshal(map[string]string{
		"email":    "signin@example.com",
		"password": "Password123!",
	})
	req := httptest.NewRequest("POST", "/auth/sign-up", bytes.NewReader(signUpBody))
	req.Header.Set("Content-Type", "application/json")

	signUpResp, _ := app.Test(req)
	if signUpResp.StatusCode != 201 {
		var errResp map[string]any
		json.NewDecoder(signUpResp.Body).Decode(&errResp)
		t.Fatalf("sign-up failed with %d: %v", signUpResp.StatusCode, errResp)
	}

	// Debug: Check if user and account were created
	user, err := storage.GetUserByEmail("signin@example.com")
	if err != nil {
		t.Fatalf("user not found after sign-up: %v", err)
	}
	accounts, err := storage.GetAccountByUserAndProvider(user.ID, "credential")
	if err != nil {
		t.Fatalf("error fetching account: %v", err)
	}
	if len(accounts) == 0 {
		t.Fatal("no credential account found for user")
	}
	t.Logf("DEBUG: User ID: %s, Account ID: %s, Has Password: %v", user.ID, accounts[0].ID, accounts[0].Password != nil)

	// Sign in
	signInBody, _ := json.Marshal(map[string]string{
		"email":    "signin@example.com",
		"password": "Password123!",
	})
	req = httptest.NewRequest("POST", "/auth/sign-in", bytes.NewReader(signInBody))
	req.Header.Set("Content-Type", "application/json")

	resp, _ := app.Test(req)
	if resp.StatusCode != 200 {
		var errResp map[string]any
		json.NewDecoder(resp.Body).Decode(&errResp)
		t.Fatalf("sign-in should return 200; got %d: %v", resp.StatusCode, errResp)
	}

	var result core.SignInResult
	json.NewDecoder(resp.Body).Decode(&result)
	if result.Token == "" {
		t.Error("sign-in should return a token")
	}
}

// Requirement: Sign-in with wrong password returns 401
func TestIntegration_SignInWrongPassword(t *testing.T) {
	app, _ := setupTestApp(t)

	// Create user
	signUpBody, _ := json.Marshal(map[string]string{
		"email":    "wrongpass@example.com",
		"password": "Password123!",
	})
	req := httptest.NewRequest("POST", "/auth/sign-up", bytes.NewReader(signUpBody))
	req.Header.Set("Content-Type", "application/json")
	app.Test(req)

	// Sign in with wrong password
	signInBody, _ := json.Marshal(map[string]string{
		"email":    "wrongpass@example.com",
		"password": "WrongPassword!",
	})
	req = httptest.NewRequest("POST", "/auth/sign-in", bytes.NewReader(signInBody))
	req.Header.Set("Content-Type", "application/json")

	resp, _ := app.Test(req)
	if resp.StatusCode != 401 {
		t.Errorf("wrong password should return 401; got %d", resp.StatusCode)
	}
}

// Requirement: Refresh token extends session and returns new token
func TestIntegration_RefreshToken(t *testing.T) {
	app, _ := setupTestApp(t)

	// Sign up
	signUpBody, _ := json.Marshal(map[string]string{
		"email":    "refresh@example.com",
		"password": "Password123!",
	})
	req := httptest.NewRequest("POST", "/auth/sign-up", bytes.NewReader(signUpBody))
	req.Header.Set("Content-Type", "application/json")

	resp, _ := app.Test(req)
	var signUpResult core.SignUpResult
	json.NewDecoder(resp.Body).Decode(&signUpResult)
	oldToken := signUpResult.Token

	// Refresh
	req = httptest.NewRequest("POST", "/auth/refresh", nil)
	req.Header.Set("Authorization", "Bearer "+oldToken)

	resp, _ = app.Test(req)
	if resp.StatusCode != 200 {
		t.Errorf("refresh should return 200; got %d", resp.StatusCode)
	}

	var refreshResult core.RefreshResult
	json.NewDecoder(resp.Body).Decode(&refreshResult)

	if refreshResult.Token == "" {
		t.Error("refresh should return a new token")
	}

	if refreshResult.Token == oldToken {
		t.Error("refresh should return a different token")
	}

	// Old token should be invalid
	req = httptest.NewRequest("GET", "/auth/session", nil)
	req.Header.Set("Authorization", "Bearer "+oldToken)

	resp, _ = app.Test(req)
	if resp.StatusCode != 401 {
		t.Errorf("old token after refresh should return 401; got %d", resp.StatusCode)
	}

	// New token should work
	req = httptest.NewRequest("GET", "/auth/session", nil)
	req.Header.Set("Authorization", "Bearer "+refreshResult.Token)

	resp, _ = app.Test(req)
	if resp.StatusCode != 200 {
		t.Errorf("new token should return 200; got %d", resp.StatusCode)
	}
}
