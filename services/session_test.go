package services

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/lborres/kuta/core"
	"github.com/lborres/kuta/pkg/crypto"
)

// Helper function to create a SessionManager for tests
func newTestSessionManager(storage core.StorageProvider, cache core.Cache) *SessionManager {
	config := core.SessionConfig{MaxAge: 24 * time.Hour}
	passwords := crypto.NewArgon2()
	return NewSessionManager(config, storage, cache, passwords)
}

// Requirement: Create generates a new session with a token.
func TestSessionManager_Create(t *testing.T) {
	tests := []struct {
		name      string
		userID    string
		ip        string
		userAgent string
		wantErr   bool
	}{
		{name: "creates session successfully", userID: "user123", ip: "192.168.1.1", userAgent: "Mozilla/5.0", wantErr: false},
		{name: "empty userID", userID: "", ip: "192.168.1.1", userAgent: "Mozilla/5.0", wantErr: false},
		{name: "empty IP", userID: "user123", ip: "", userAgent: "Mozilla/5.0", wantErr: false},
		{name: "empty userAgent", userID: "user123", ip: "192.168.1.1", userAgent: "", wantErr: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Arrange
			storage := NewFakeStorageProvider()
			manager := newTestSessionManager(storage, nil)

			// Act
			result, err := manager.Create(test.userID, test.ip, test.userAgent)

			// Debug output
			if !test.wantErr {
				fmt.Printf("Session: %#v, Token: %s\n", *result.Session, result.Token)
			}

			// Assert
			if (err != nil) != test.wantErr {
				t.Fatalf("Create() error = %v, wantErr %v", err, test.wantErr)
			}
			if !test.wantErr {
				if result == nil {
					t.Fatal("Create() returned nil")
				}
				if result.Session == nil {
					t.Fatal("Session is nil")
				}
				if result.Token == "" {
					t.Fatal("Token is empty")
				}
				if result.Session.UserID != test.userID {
					t.Errorf("Session.UserID = %q, want %q", result.Session.UserID, test.userID)
				}
			}
		})
	}
}

// Requirement: TokenHash must never be exposed in JSON responses (security).
func TestSessionManager_Create_TokenHashNotExposed(t *testing.T) {
	tests := []struct {
		name          string
		checkProperty func(map[string]interface{}) string // returns error message or empty string
	}{
		{
			name: "TokenHash not in JSON",
			checkProperty: func(m map[string]interface{}) string {
				if _, exists := m["tokenHash"]; exists {
					return "TokenHash exposed in JSON (security leak)"
				}
				return ""
			},
		},
		{
			name: "Token not in Session JSON",
			checkProperty: func(m map[string]interface{}) string {
				if _, exists := m["token"]; exists {
					return "Token should not be in Session JSON"
				}
				return ""
			},
		},
		{
			name: "required fields present",
			checkProperty: func(m map[string]interface{}) string {
				required := []string{"id", "userId", "ipAddress", "userAgent", "expiresAt", "createdAt", "updatedAt"}
				for _, field := range required {
					if _, exists := m[field]; !exists {
						return "required field " + field + " missing"
					}
				}
				return ""
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Arrange
			storage := NewFakeStorageProvider()
			config := core.SessionConfig{MaxAge: 24 * time.Hour}
			passwords := crypto.NewArgon2()
			manager := NewSessionManager(config, storage, nil, passwords)

			// Act
			result, err := manager.Create("user123", "192.168.1.1", "Mozilla/5.0")

			// Assert
			if err != nil {
				t.Fatalf("Create() error = %v", err)
			}

			jsonBytes, err := json.Marshal(result.Session)
			if err != nil {
				t.Fatalf("json.Marshal() error = %v", err)
			}

			var sessionMap map[string]interface{}
			if err := json.Unmarshal(jsonBytes, &sessionMap); err != nil {
				t.Fatalf("json.Unmarshal() error = %v", err)
			}

			// Run the check
			if errMsg := test.checkProperty(sessionMap); errMsg != "" {
				t.Error(errMsg)
			}
		})
	}
}

// Requirement: Verify retrieves and validates a session by token.
func TestSessionManager_Verify(t *testing.T) {
	tests := []struct {
		name         string
		setupSession func(*FakeStorageProvider) string // returns token to use
		wantErr      bool
		wantSession  bool
	}{
		{
			name: "returns session for valid token",
			setupSession: func(storage *FakeStorageProvider) string {
				manager := newTestSessionManager(storage, nil)
				result, _ := manager.Create("user123", "192.168.1.1", "Mozilla/5.0")
				return result.Token
			},
			wantErr:     false,
			wantSession: true,
		},
		{
			name: "returns error for empty token",
			setupSession: func(storage *FakeStorageProvider) string {
				return ""
			},
			wantErr:     true,
			wantSession: false,
		},
		{
			name: "returns error for invalid token",
			setupSession: func(storage *FakeStorageProvider) string {
				manager := newTestSessionManager(storage, nil)
				manager.Create("user123", "192.168.1.1", "Mozilla/5.0")
				return "invalid_token_xyz"
			},
			wantErr:     true,
			wantSession: false,
		},
		{
			name: "returns error for expired session",
			setupSession: func(storage *FakeStorageProvider) string {
				config := core.SessionConfig{MaxAge: -1 * time.Hour}
				passwords := crypto.NewArgon2()
				manager := NewSessionManager(config, storage, nil, passwords)
				result, _ := manager.Create("user123", "192.168.1.1", "Mozilla/5.0")
				return result.Token
			},
			wantErr:     true,
			wantSession: false,
		},
		{
			name: "returns error when token not found in storage",
			setupSession: func(storage *FakeStorageProvider) string {
				manager := newTestSessionManager(storage, nil)
				result, _ := manager.Create("user123", "192.168.1.1", "Mozilla/5.0")
				storage.DeleteSessionByID(result.Session.ID) // delete it
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
			token := test.setupSession(storage)
			manager := newTestSessionManager(storage, nil)

			// Act
			session, err := manager.Verify(token)

			// Assert
			if (err != nil) != test.wantErr {
				t.Fatalf("Verify() error = %v, wantErr %v", err, test.wantErr)
			}
			if test.wantSession && session == nil {
				t.Fatal("Verify() returned nil session")
			}
			if !test.wantSession && session != nil {
				t.Errorf("Verify() returned session, want error")
			}
			if test.wantSession && session != nil {
				if session.UserID != "user123" {
					t.Errorf("Session.UserID = %q, want %q", session.UserID, "user123")
				}
			}
		})
	}
}

// Requirement: Destroy removes a session by token.
func TestSessionManager_Destroy(t *testing.T) {
	tests := []struct {
		name         string
		setupSession func(*FakeStorageProvider) string // returns token to destroy
		wantErr      bool
	}{
		{
			name: "successfully destroys session by token",
			setupSession: func(storage *FakeStorageProvider) string {
				manager := newTestSessionManager(storage, nil)
				result, _ := manager.Create("user123", "192.168.1.1", "Mozilla/5.0")
				return result.Token
			},
			wantErr: false,
		},
		{
			name: "returns error for empty token",
			setupSession: func(storage *FakeStorageProvider) string {
				return ""
			},
			wantErr: true,
		},
		{
			name: "returns error for invalid token",
			setupSession: func(storage *FakeStorageProvider) string {
				return "invalid_token_xyz"
			},
			wantErr: true,
		},
		{
			name: "prevents session use after destruction",
			setupSession: func(storage *FakeStorageProvider) string {
				manager := newTestSessionManager(storage, nil)
				result, _ := manager.Create("user123", "192.168.1.1", "Mozilla/5.0")
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
			manager := newTestSessionManager(storage, nil)
			token := test.setupSession(storage)

			// Act
			err := manager.Destroy(token)

			// Assert
			if (err != nil) != test.wantErr {
				t.Fatalf("Destroy() error = %v, wantErr %v", err, test.wantErr)
			}

			// If destroy succeeded, verify token can't be used
			if !test.wantErr && test.name == "prevents session use after destruction" {
				_, err := manager.Verify(token)
				if err == nil {
					t.Error("Verify() should fail after Destroy()")
				}
			}
		})
	}
}

// Requirement: DestroyBySessionID removes a session by ID.
func TestSessionManager_DestroyBySessionID(t *testing.T) {
	tests := []struct {
		name         string
		setupSession func(*FakeStorageProvider) string // returns sessionID to destroy
		wantErr      bool
	}{
		{
			name: "successfully destroys session by ID",
			setupSession: func(storage *FakeStorageProvider) string {
				manager := newTestSessionManager(storage, nil)
				result, _ := manager.Create("user123", "192.168.1.1", "Mozilla/5.0")
				return result.Session.ID
			},
			wantErr: false,
		},
		{
			name: "returns error for empty session ID",
			setupSession: func(storage *FakeStorageProvider) string {
				return ""
			},
			wantErr: true,
		},
		{
			name: "returns error for nonexistent session ID",
			setupSession: func(storage *FakeStorageProvider) string {
				return "nonexistent_session_id"
			},
			wantErr: true,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			// Arrange
			storage := NewFakeStorageProvider()
			manager := newTestSessionManager(storage, nil)
			sessionID := test.setupSession(storage)

			// Act
			err := manager.DestroyBySessionID(sessionID)

			// Assert
			if (err != nil) != test.wantErr {
				t.Fatalf("DestroyBySessionID() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}

// Requirement: DestroyAllUserSessions removes all sessions for a user.
func TestSessionManager_DestroyAllUserSessions(t *testing.T) {
	tests := []struct {
		name          string
		userID        string
		setupSessions func(*FakeStorageProvider) int // creates sessions, returns count
		wantErr       bool
		wantDestroyed int
	}{
		{
			name:   "destroys all sessions for user",
			userID: "user123",
			setupSessions: func(storage *FakeStorageProvider) int {
				manager := newTestSessionManager(storage, nil)
				manager.Create("user123", "192.168.1.1", "Mozilla/5.0")
				manager.Create("user123", "192.168.1.2", "Chrome/5.0")
				manager.Create("user123", "192.168.1.3", "Safari/5.0")
				return 3
			},
			wantErr:       false,
			wantDestroyed: 3,
		},
		{
			name:   "returns zero for user with no sessions",
			userID: "nonexistent_user",
			setupSessions: func(storage *FakeStorageProvider) int {
				return 0
			},
			wantErr:       false,
			wantDestroyed: 0,
		},
		{
			name:   "returns error for empty userID",
			userID: "",
			setupSessions: func(storage *FakeStorageProvider) int {
				return 0
			},
			wantErr:       true,
			wantDestroyed: 0,
		},
		{
			name:   "only destroys specified user's sessions",
			userID: "user123",
			setupSessions: func(storage *FakeStorageProvider) int {
				manager := newTestSessionManager(storage, nil)
				manager.Create("user123", "192.168.1.1", "Mozilla/5.0")
				manager.Create("user123", "192.168.1.2", "Chrome/5.0")
				manager.Create("user456", "192.168.1.3", "Safari/5.0")
				return 2 // only user123's sessions
			},
			wantErr:       false,
			wantDestroyed: 2,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			// Arrange
			storage := NewFakeStorageProvider()
			manager := newTestSessionManager(storage, nil)
			_ = test.setupSessions(storage)

			// Act
			destroyed, err := manager.DestroyAllUserSessions(test.userID)

			// Assert
			if (err != nil) != test.wantErr {
				t.Fatalf("DestroyAllUserSessions() error = %v, wantErr %v", err, test.wantErr)
			}
			if !test.wantErr && destroyed != test.wantDestroyed {
				t.Errorf("DestroyAllUserSessions() destroyed = %d, want %d", destroyed, test.wantDestroyed)
			}
		})
	}
}

// Requirement: SessionManager supports optional caching and works without it.
func TestSessionManager_Create_CacheBehavior(t *testing.T) {
	tests := []struct {
		name       string
		cache      core.Cache
		checkCache func(core.Cache, string) error // optional cache verification
	}{
		{
			name:  "caches session when cache is provided",
			cache: NewFakeCache(),
			checkCache: func(c core.Cache, token string) error {
				tokenHash := crypto.HashToken(token)
				_, err := c.Get(tokenHash)
				if errors.Is(err, core.ErrCacheNotFound) {
					return errors.New("session not cached")
				}
				return err
			},
		},
		{
			name:  "works without cache when cache is nil",
			cache: nil,
		},
		{
			name:  "continues despite cache errors",
			cache: &fakeFailingCache{},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			// Arrange
			storage := NewFakeStorageProvider()
			config := core.SessionConfig{MaxAge: 24 * time.Hour}
			passwords := crypto.NewArgon2()
			manager := NewSessionManager(config, storage, test.cache, passwords)
			result, err := manager.Create("user123", "192.168.1.1", "Mozilla/5.0")

			// Assert
			if err != nil {
				t.Errorf("Create() should not fail: %v", err)
			}
			if result == nil || result.Token == "" {
				t.Fatal("Create() returned invalid result")
			}

			// Verify in storage
			tokenHash := crypto.HashToken(result.Token)
			stored, err := storage.GetSessionByHash(tokenHash)
			if err != nil || stored.UserID != "user123" {
				t.Error("Session not properly stored")
			}

			// Check cache if verification provided
			if test.checkCache != nil {
				if err := test.checkCache(test.cache, result.Token); err != nil {
					t.Errorf("Cache verification failed: %v", err)
				}
			}
		})
	}
}

// Requirement: Verify uses cache-aside pattern for performance.
func TestSessionManager_Verify_CachePattern(t *testing.T) {
	tests := []struct {
		name            string
		setupCache      func() core.Cache
		wantCacheHits   int
		wantCacheMisses int
	}{
		{
			name: "loads from storage on cache miss, then caches",
			setupCache: func() core.Cache {
				cache := NewFakeCache()
				// Clear cache to force a miss on first verify
				return cache
			},
			wantCacheHits:   1,
			wantCacheMisses: 1,
		},
		{
			name: "misses cache after clear",
			setupCache: func() core.Cache {
				cache := NewFakeCache()
				// We'll clear after first create but before second verify
				return cache
			},
			wantCacheHits:   1,
			wantCacheMisses: 1,
		},
		{
			name: "works without cache",
			setupCache: func() core.Cache {
				return nil
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			// Arrange
			storage := NewFakeStorageProvider()
			cache := test.setupCache()
			config := core.SessionConfig{MaxAge: 24 * time.Hour}
			passwords := crypto.NewArgon2()
			manager := NewSessionManager(config, storage, cache, passwords)

			result, _ := manager.Create("user123", "192.168.1.1", "Mozilla/5.0")
			token := result.Token

			// Clear cache to force first verify to miss (all test cases need this)
			if cache != nil {
				cache.Clear()
			}

			// Act: Verify session multiple times
			for i := 0; i < 2; i++ {
				_, err := manager.Verify(token)
				if err != nil {
					t.Fatalf("Verify iteration %d failed: %v", i+1, err)
				}
			}

			// Assert
			if cache != nil {
				fakeCache, ok := cache.(*FakeCache)
				if ok {
					stats := fakeCache.Stats()
					if stats.Hits != int64(test.wantCacheHits) {
						t.Errorf("Expected %d cache hits, got %d", test.wantCacheHits, stats.Hits)
					}
					if stats.Misses != int64(test.wantCacheMisses) {
						t.Errorf("Expected %d cache misses, got %d", test.wantCacheMisses, stats.Misses)
					}
				}
			}
		})
	}
}

// Requirement: Expired sessions in cache are removed and rejected.
func TestSessionManager_Verify_ExpiredSessionHandling(t *testing.T) {
	tests := []struct {
		name        string
		withCache   bool
		wantErr     bool
		wantInCache bool // if cache is used
	}{
		{
			name:        "rejects expired session with cache",
			withCache:   true,
			wantErr:     true,
			wantInCache: false,
		},
		{
			name:      "rejects expired session without cache",
			withCache: false,
			wantErr:   true,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			// Arrange
			storage := NewFakeStorageProvider()
			var cache core.Cache
			if test.withCache {
				cache = NewFakeCache()
			}
			config := core.SessionConfig{MaxAge: -1 * time.Hour} // Already expired
			passwords := crypto.NewArgon2()
			manager := NewSessionManager(config, storage, cache, passwords)

			result, _ := manager.Create("user123", "192.168.1.1", "Mozilla/5.0")
			token := result.Token
			tokenHash := crypto.HashToken(token)

			// Act
			_, err := manager.Verify(token)

			// Assert
			if (err != nil) != test.wantErr {
				t.Fatalf("Verify() error = %v, wantErr %v", err, test.wantErr)
			}
			if !errors.Is(err, core.ErrSessionExpired) {
				t.Errorf("Expected ErrSessionExpired, got %v", err)
			}

			// Verify removed from cache if applicable
			if test.withCache && test.wantInCache == false {
				if cache != nil {
					_, err := cache.Get(tokenHash)
					if !errors.Is(err, core.ErrCacheNotFound) {
						t.Error("Expired session should be removed from cache")
					}
				}
			}
		})
	}
}

// Requirement: Destroy removes sessions from cache and storage.
func TestSessionManager_Destroy_CacheInvalidation(t *testing.T) {
	tests := []struct {
		name      string
		withCache bool
	}{
		{
			name:      "invalidates cache on destroy",
			withCache: true,
		},
		{
			name:      "works without cache on destroy",
			withCache: false,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			// Arrange
			storage := NewFakeStorageProvider()
			var cache core.Cache
			if test.withCache {
				cache = NewFakeCache()
			}
			config := core.SessionConfig{MaxAge: 24 * time.Hour}
			passwords := crypto.NewArgon2()
			manager := NewSessionManager(config, storage, cache, passwords)

			result, _ := manager.Create("user123", "192.168.1.1", "Mozilla/5.0")
			token := result.Token
			tokenHash := crypto.HashToken(token)

			// Act
			err := manager.Destroy(token)

			// Assert
			if err != nil {
				t.Fatalf("Destroy() error = %v", err)
			}

			// Verify removed from storage
			_, err = storage.GetSessionByHash(tokenHash)
			if err == nil {
				t.Error("Session should be removed from storage")
			}

			// Verify removed from cache if applicable
			if test.withCache {
				_, err := cache.Get(tokenHash)
				if !errors.Is(err, core.ErrCacheNotFound) {
					t.Error("Session should be removed from cache")
				}
			}
		})
	}
}

// Requirement: DestroyBySessionID invalidates cache.
func TestSessionManager_DestroyBySessionID_CacheInvalidation(t *testing.T) {
	tests := []struct {
		name      string
		withCache bool
	}{
		{
			name:      "invalidates cache when destroying by ID",
			withCache: true,
		},
		{
			name:      "works without cache",
			withCache: false,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			// Arrange
			storage := NewFakeStorageProvider()
			var cache core.Cache
			if test.withCache {
				cache = NewFakeCache()
			}
			config := core.SessionConfig{MaxAge: 24 * time.Hour}
			passwords := crypto.NewArgon2()
			manager := NewSessionManager(config, storage, cache, passwords)

			result, _ := manager.Create("user123", "192.168.1.1", "Mozilla/5.0")
			sessionID := result.Session.ID
			tokenHash := crypto.HashToken(result.Token)

			// Act
			err := manager.DestroyBySessionID(sessionID)

			// Assert
			if err != nil {
				t.Fatalf("DestroyBySessionID() error = %v", err)
			}

			// Verify removed from storage
			_, err = storage.GetSessionByID(sessionID)
			if err == nil {
				t.Error("Session should be removed from storage")
			}

			// Verify removed from cache if applicable
			if test.withCache {
				_, err := cache.Get(tokenHash)
				if !errors.Is(err, core.ErrCacheNotFound) {
					t.Error("Session should be removed from cache")
				}
			}
		})
	}
}

// Requirement: DestroyAllUserSessions clears cache to ensure consistency.
func TestSessionManager_DestroyAllUserSessions_CacheClearing(t *testing.T) {
	tests := []struct {
		name         string
		withCache    bool
		sessionCount int
	}{
		{
			name:         "clears cache when destroying user sessions",
			withCache:    true,
			sessionCount: 3,
		},
		{
			name:         "works without cache",
			withCache:    false,
			sessionCount: 2,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			// Arrange
			storage := NewFakeStorageProvider()
			var cache core.Cache
			if test.withCache {
				cache = NewFakeCache()
			}
			config := core.SessionConfig{MaxAge: 24 * time.Hour}
			passwords := crypto.NewArgon2()
			manager := NewSessionManager(config, storage, cache, passwords)

			// Create multiple sessions
			for i := 0; i < test.sessionCount; i++ {
				manager.Create("user123", "192.168.1.1", "Mozilla/5.0")
			}

			if test.withCache {
				fakeCache, ok := cache.(*FakeCache)
				if ok && fakeCache.Len() != test.sessionCount {
					t.Errorf("Expected %d cached sessions, got %d", test.sessionCount, fakeCache.Len())
				}
			}

			// Act
			destroyed, err := manager.DestroyAllUserSessions("user123")

			// Assert
			if err != nil {
				t.Fatalf("DestroyAllUserSessions() error = %v", err)
			}
			if destroyed != test.sessionCount {
				t.Errorf("Expected %d sessions destroyed, got %d", test.sessionCount, destroyed)
			}

			// Verify cache is cleared if applicable
			if test.withCache && destroyed > 0 {
				fakeCache, ok := cache.(*FakeCache)
				if ok && fakeCache.Len() != 0 {
					t.Errorf("Cache should be cleared, but has %d entries", fakeCache.Len())
				}
			}
		})
	}
}

// Requirement: Refresh extends a session's expiry time and returns a new token.
// The old token becomes invalid immediately.
func TestSessionManager_Refresh(t *testing.T) {
	tests := []struct {
		name      string
		setupAuth func(*FakeStorageProvider, crypto.PasswordHandler) string // returns token to refresh
		wantErr   bool
		wantToken bool
	}{
		{
			name: "successfully refreshes valid token",
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

				config := core.SessionConfig{MaxAge: 24 * time.Hour}
				service := NewSessionManager(config, storage, nil, passwords)
				result, _ := service.SignIn(core.SignInInput{
					Email:    "alice@example.com",
					Password: "SecurePass123!",
				}, "127.0.0.1", "test-agent")
				return result.Token
			},
			wantErr:   false,
			wantToken: true,
		},
		{
			name: "returns error for empty token",
			setupAuth: func(storage *FakeStorageProvider, passwords crypto.PasswordHandler) string {
				return ""
			},
			wantErr:   true,
			wantToken: false,
		},
		{
			name: "returns error for invalid token",
			setupAuth: func(storage *FakeStorageProvider, passwords crypto.PasswordHandler) string {
				return "invalid_token_xyz"
			},
			wantErr:   true,
			wantToken: false,
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
				config := core.SessionConfig{MaxAge: -1 * time.Hour}
				service := NewSessionManager(config, storage, nil, passwords)
				result, _ := service.SignIn(core.SignInInput{
					Email:    "charlie@example.com",
					Password: "SecurePass123!",
				}, "127.0.0.1", "test-agent")
				return result.Token
			},
			wantErr:   true,
			wantToken: false,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			// Arrange
			storage := NewFakeStorageProvider()
			passwords := crypto.NewArgon2()
			config := core.SessionConfig{MaxAge: 24 * time.Hour}
			service := NewSessionManager(config, storage, nil, passwords)

			token := test.setupAuth(storage, passwords)

			// Act
			result, err := service.Refresh(token)

			// Assert
			if (err != nil) != test.wantErr {
				t.Fatalf("Refresh() error = %v, wantErr %v", err, test.wantErr)
			}
			if test.wantToken && result != nil && result.Token == "" {
				t.Error("Refresh() should return token")
			}
			if !test.wantErr && result != nil {
				if result.Session == nil {
					t.Error("Refresh() should return session")
				}
				// Verify new token is different from old token
				if result.Token == token {
					t.Error("Refresh() should return a new token, not the old one")
				}
				// Verify old token can't be used anymore
				_, err := service.Verify(token)
				if err == nil {
					t.Error("Old token should be invalid after refresh")
				}
			}
		})
	}
}

// Requirement: Refresh invalidates old token in cache and caches new session.
func TestSessionManager_Refresh_CacheBehavior(t *testing.T) {
	tests := []struct {
		name      string
		withCache bool
	}{
		{
			name:      "invalidates old token and caches new session",
			withCache: true,
		},
		{
			name:      "works without cache",
			withCache: false,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			// Arrange
			storage := NewFakeStorageProvider()
			config := core.SessionConfig{MaxAge: 24 * time.Hour}
			var cache core.Cache
			if test.withCache {
				cache = NewFakeCache()
			}
			passwords := crypto.NewArgon2()
			service := NewSessionManager(config, storage, cache, passwords)

			// Create initial session
			result, err := service.Create("user123", "192.168.1.1", "Mozilla/5.0")
			if err != nil {
				t.Fatalf("Create() failed: %v", err)
			}
			oldToken := result.Token

			// Warm cache by verifying the session
			if test.withCache {
				service.Verify(oldToken)
			}

			// Act: Refresh the token
			refreshResult, err := service.Refresh(oldToken)
			if err != nil {
				t.Fatalf("Refresh() failed: %v", err)
			}

			// Assert
			if refreshResult.Token == "" {
				t.Fatal("Refresh() should return a new token")
			}

			// Verify old token is completely removed
			_, err = service.Verify(oldToken)
			if err == nil {
				t.Error("Old token should be invalid after refresh")
			}

			// Verify new token works
			newSession, err := service.Verify(refreshResult.Token)
			if err != nil {
				t.Fatalf("New token should be valid: %v", err)
			}
			if newSession.UserID != "user123" {
				t.Errorf("New session has wrong user: got %q, want %q", newSession.UserID, "user123")
			}

			// Verify new session has extended expiry
			if !newSession.ExpiresAt.After(result.Session.ExpiresAt) {
				t.Error("Refreshed session should have extended expiry")
			}
		})
	}
}

// Requirement: SignUp creates a new user account and returns a result with user and session.
func TestSessionManager_SignUp(t *testing.T) {
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
			config := core.SessionConfig{MaxAge: 24 * time.Hour}
			passwords := crypto.NewArgon2()
			service := NewSessionManager(config, storage, nil, passwords)

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
func TestSessionManager_SignIn(t *testing.T) {
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
			config := core.SessionConfig{MaxAge: 24 * time.Hour}
			passwords := crypto.NewArgon2()
			service := NewSessionManager(config, storage, nil, passwords)
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
func TestSessionManager_SignOut(t *testing.T) {
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

				config := core.SessionConfig{MaxAge: 24 * time.Hour}
				service := NewSessionManager(config, storage, nil, passwords)
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

				config := core.SessionConfig{MaxAge: 24 * time.Hour}
				service := NewSessionManager(config, storage, nil, passwords)
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
			config := core.SessionConfig{MaxAge: 24 * time.Hour}
			service := NewSessionManager(config, storage, nil, passwords)

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
func TestSessionManager_GetSession(t *testing.T) {
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

				config := core.SessionConfig{MaxAge: 24 * time.Hour}
				service := NewSessionManager(config, storage, nil, passwords)
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
				config := core.SessionConfig{MaxAge: -1 * time.Hour}
				service := NewSessionManager(config, storage, nil, passwords)
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
			config := core.SessionConfig{MaxAge: 24 * time.Hour}
			service := NewSessionManager(config, storage, nil, passwords)

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
