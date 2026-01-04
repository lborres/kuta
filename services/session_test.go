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
			storage := NewFakeSessionStorage()
			config := core.SessionConfig{MaxAge: 24 * time.Hour}
			manager, err := NewSessionManager(config, storage, nil)
			if err != nil {
				t.Fatalf("NewSessionManager() error = %v", err)
			}

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
			storage := NewFakeSessionStorage()
			config := core.SessionConfig{MaxAge: 24 * time.Hour}
			manager, _ := NewSessionManager(config, storage, nil)

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
		setupSession func(*FakeSessionStorage) string // returns token to use
		wantErr      bool
		wantSession  bool
	}{
		{
			name: "returns session for valid token",
			setupSession: func(storage *FakeSessionStorage) string {
				manager, _ := NewSessionManager(core.SessionConfig{MaxAge: 24 * time.Hour}, storage, nil)
				result, _ := manager.Create("user123", "192.168.1.1", "Mozilla/5.0")
				return result.Token
			},
			wantErr:     false,
			wantSession: true,
		},
		{
			name: "returns error for empty token",
			setupSession: func(storage *FakeSessionStorage) string {
				return ""
			},
			wantErr:     true,
			wantSession: false,
		},
		{
			name: "returns error for invalid token",
			setupSession: func(storage *FakeSessionStorage) string {
				manager, _ := NewSessionManager(core.SessionConfig{MaxAge: 24 * time.Hour}, storage, nil)
				manager.Create("user123", "192.168.1.1", "Mozilla/5.0")
				return "invalid_token_xyz"
			},
			wantErr:     true,
			wantSession: false,
		},
		{
			name: "returns error for expired session",
			setupSession: func(storage *FakeSessionStorage) string {
				manager, _ := NewSessionManager(core.SessionConfig{MaxAge: -1 * time.Hour}, storage, nil)
				result, _ := manager.Create("user123", "192.168.1.1", "Mozilla/5.0")
				return result.Token
			},
			wantErr:     true,
			wantSession: false,
		},
		{
			name: "returns error when token not found in storage",
			setupSession: func(storage *FakeSessionStorage) string {
				manager, _ := NewSessionManager(core.SessionConfig{MaxAge: 24 * time.Hour}, storage, nil)
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
			storage := NewFakeSessionStorage()
			manager, err := NewSessionManager(core.SessionConfig{MaxAge: 24 * time.Hour}, storage, nil)
			if err != nil {
				t.Fatalf("NewSessionManager() error = %v", err)
			}

			token := test.setupSession(storage)

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
		setupSession func(*FakeSessionStorage) string // returns token to destroy
		wantErr      bool
	}{
		{
			name: "successfully destroys session by token",
			setupSession: func(storage *FakeSessionStorage) string {
				manager, _ := NewSessionManager(core.SessionConfig{MaxAge: 24 * time.Hour}, storage, nil)
				result, _ := manager.Create("user123", "192.168.1.1", "Mozilla/5.0")
				return result.Token
			},
			wantErr: false,
		},
		{
			name: "returns error for empty token",
			setupSession: func(storage *FakeSessionStorage) string {
				return ""
			},
			wantErr: true,
		},
		{
			name: "returns error for invalid token",
			setupSession: func(storage *FakeSessionStorage) string {
				return "invalid_token_xyz"
			},
			wantErr: true,
		},
		{
			name: "prevents session use after destruction",
			setupSession: func(storage *FakeSessionStorage) string {
				manager, _ := NewSessionManager(core.SessionConfig{MaxAge: 24 * time.Hour}, storage, nil)
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
			storage := NewFakeSessionStorage()
			manager, _ := NewSessionManager(core.SessionConfig{MaxAge: 24 * time.Hour}, storage, nil)
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
		setupSession func(*FakeSessionStorage) string // returns sessionID to destroy
		wantErr      bool
	}{
		{
			name: "successfully destroys session by ID",
			setupSession: func(storage *FakeSessionStorage) string {
				manager, _ := NewSessionManager(core.SessionConfig{MaxAge: 24 * time.Hour}, storage, nil)
				result, _ := manager.Create("user123", "192.168.1.1", "Mozilla/5.0")
				return result.Session.ID
			},
			wantErr: false,
		},
		{
			name: "returns error for empty session ID",
			setupSession: func(storage *FakeSessionStorage) string {
				return ""
			},
			wantErr: true,
		},
		{
			name: "returns error for nonexistent session ID",
			setupSession: func(storage *FakeSessionStorage) string {
				return "nonexistent_session_id"
			},
			wantErr: true,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			// Arrange
			storage := NewFakeSessionStorage()
			manager, _ := NewSessionManager(core.SessionConfig{MaxAge: 24 * time.Hour}, storage, nil)
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
		setupSessions func(*FakeSessionStorage) int // creates sessions, returns count
		wantErr       bool
		wantDestroyed int
	}{
		{
			name:   "destroys all sessions for user",
			userID: "user123",
			setupSessions: func(storage *FakeSessionStorage) int {
				manager, _ := NewSessionManager(core.SessionConfig{MaxAge: 24 * time.Hour}, storage, nil)
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
			setupSessions: func(storage *FakeSessionStorage) int {
				return 0
			},
			wantErr:       false,
			wantDestroyed: 0,
		},
		{
			name:   "returns error for empty userID",
			userID: "",
			setupSessions: func(storage *FakeSessionStorage) int {
				return 0
			},
			wantErr:       true,
			wantDestroyed: 0,
		},
		{
			name:   "only destroys specified user's sessions",
			userID: "user123",
			setupSessions: func(storage *FakeSessionStorage) int {
				manager, _ := NewSessionManager(core.SessionConfig{MaxAge: 24 * time.Hour}, storage, nil)
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
			storage := NewFakeSessionStorage()
			manager, _ := NewSessionManager(core.SessionConfig{MaxAge: 24 * time.Hour}, storage, nil)
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
			storage := NewFakeSessionStorage()
			config := core.SessionConfig{MaxAge: 24 * time.Hour}
			manager, err := NewSessionManager(config, storage, test.cache)
			if err != nil {
				t.Fatalf("NewSessionManager() error = %v", err)
			}

			// Act
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
			storage := NewFakeSessionStorage()
			cache := test.setupCache()
			config := core.SessionConfig{MaxAge: 24 * time.Hour}
			manager, _ := NewSessionManager(config, storage, cache)

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
			storage := NewFakeSessionStorage()
			var cache core.Cache
			if test.withCache {
				cache = NewFakeCache()
			}
			config := core.SessionConfig{MaxAge: -1 * time.Hour} // Already expired
			manager, _ := NewSessionManager(config, storage, cache)

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
			storage := NewFakeSessionStorage()
			var cache core.Cache
			if test.withCache {
				cache = NewFakeCache()
			}
			config := core.SessionConfig{MaxAge: 24 * time.Hour}
			manager, _ := NewSessionManager(config, storage, cache)

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
			storage := NewFakeSessionStorage()
			var cache core.Cache
			if test.withCache {
				cache = NewFakeCache()
			}
			config := core.SessionConfig{MaxAge: 24 * time.Hour}
			manager, _ := NewSessionManager(config, storage, cache)

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
			storage := NewFakeSessionStorage()
			var cache core.Cache
			if test.withCache {
				cache = NewFakeCache()
			}
			config := core.SessionConfig{MaxAge: 24 * time.Hour}
			manager, _ := NewSessionManager(config, storage, cache)

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
