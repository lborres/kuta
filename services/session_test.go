package services

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/lborres/kuta/core"
	"github.com/lborres/kuta/pkg/cache"
)

type MockSessionStorage struct {
	sessions  map[string]*core.Session
	mu        sync.RWMutex // make mock storage thread safe
	createErr error
	getErr    error
	deleteErr error
}

func NewMockSessionStorage() *MockSessionStorage {
	return &MockSessionStorage{
		sessions: make(map[string]*core.Session),
	}
}

func (m *MockSessionStorage) CreateSession(session *core.Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.createErr != nil {
		return m.createErr
	}
	m.sessions[session.TokenHash] = session
	return nil
}

func (m *MockSessionStorage) GetSessionByHash(tokenHash string) (*core.Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.getErr != nil {
		return nil, m.getErr
	}
	session, exists := m.sessions[tokenHash]
	if !exists {
		return nil, errors.New("session not found")
	}
	return session, nil
}

func (m *MockSessionStorage) GetSessionByID(id string) (*core.Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, session := range m.sessions {
		if session.ID == id {
			return session, nil
		}
	}
	return nil, errors.New("session not found")
}

func (m *MockSessionStorage) GetUserSessions(userID string) ([]*core.Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var sessions []*core.Session
	for _, session := range m.sessions {
		if session.UserID == userID {
			sessions = append(sessions, session)
		}
	}
	return sessions, nil
}

func (m *MockSessionStorage) UpdateSession(session *core.Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.sessions[session.TokenHash] = session
	return nil
}

func (m *MockSessionStorage) DeleteSessionByID(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.deleteErr != nil {
		return m.deleteErr
	}
	for hash, session := range m.sessions {
		if session.ID == id {
			delete(m.sessions, hash)
			return nil
		}
	}
	return nil
}

func (m *MockSessionStorage) DeleteSessionByHash(tokenHash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.deleteErr != nil {
		return m.deleteErr
	}
	delete(m.sessions, tokenHash)
	return nil
}

func (m *MockSessionStorage) DeleteUserSessions(userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for hash, session := range m.sessions {
		if session.UserID == userID {
			delete(m.sessions, hash)
		}
	}
	return nil
}

func (m *MockSessionStorage) DeleteExpiredSessions() (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	count := 0
	now := time.Now()
	for hash, session := range m.sessions {
		if now.After(session.ExpiresAt) {
			delete(m.sessions, hash)
			count++
		}
	}
	return count, nil
}

func TestSessionManagerCreateShouldGenerateValidSessionAndToken(t *testing.T) {
	storage := NewMockSessionStorage()
	manager := NewSessionService(DefaultSessionConfig(), storage, nil)

	result, err := manager.Create("user123", "192.168.1.1", "Mozilla/5.0")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Check session fields
	if result.Session.UserID != "user123" {
		t.Errorf("Expected userID user123, got %s", result.Session.UserID)
	}

	if result.Session.IPAddress != "192.168.1.1" {
		t.Errorf("Expected IP 192.168.1.1, got %s", result.Session.IPAddress)
	}

	if result.Session.UserAgent != "Mozilla/5.0" {
		t.Errorf("Expected UserAgent Mozilla/5.0, got %s", result.Session.UserAgent)
	}

	// Check token is generated
	if result.Token == "" {
		t.Error("Token should not be empty")
	}

	if result.Session.TokenHash == "" {
		t.Error("TokenHash should not be empty")
	}

	// Check ID is generated
	if result.Session.ID == "" {
		t.Error("Session ID should not be empty")
	}

	// Check timestamps
	if result.Session.CreatedAt.IsZero() {
		t.Error("CreatedAt should be set")
	}

	if result.Session.UpdatedAt.IsZero() {
		t.Error("UpdatedAt should be set")
	}

	// Check expiry
	expectedExpiry := time.Now().Add(24 * time.Hour)
	diff := result.Session.ExpiresAt.Sub(expectedExpiry)
	if diff > time.Second || diff < -time.Second {
		t.Errorf("ExpiresAt should be ~24 hours from now, got %v", result.Session.ExpiresAt)
	}
}

func TestSessionManagerCreateMultipleUsersShouldProduceDistinctSessionsAndTokens(t *testing.T) {
	storage := NewMockSessionStorage()
	manager := NewSessionService(DefaultSessionConfig(), storage, nil)

	// Create sessions for different users
	result1, _ := manager.Create("user1", "192.168.1.1", "Chrome")
	result2, _ := manager.Create("user2", "192.168.1.2", "Firefox")
	t.Logf("%+v", result1.Session)
	t.Logf("%+v", result2.Session)

	// Should have different IDs
	if result1.Session.ID == result2.Session.ID {
		t.Error("Different sessions should have different IDs")
	}

	// Should have different tokens
	if result1.Token == result2.Token {
		t.Error("Different sessions should have different tokens")
	}

	// Should have different hashes
	if result1.Session.TokenHash == result2.Session.TokenHash {
		t.Error("Different sessions should have different token hashes")
	}
}

func TestSessionManagerVerifyValidSessionShouldReturnSession(t *testing.T) {
	storage := NewMockSessionStorage()
	manager := NewSessionService(DefaultSessionConfig(), storage, nil)

	// Create a session
	result, _ := manager.Create("user123", "192.168.1.1", "Mozilla/5.0")

	// Verify with the token
	session, err := manager.Verify(result.Token)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if session.UserID != "user123" {
		t.Errorf("Expected userID user123, got %s", session.UserID)
	}

	if session.ID != result.Session.ID {
		t.Error("Verified session should have same ID as created session")
	}
}

func TestSessionManagerVerifyEmptyTokenShouldReturnErrInvalidToken(t *testing.T) {
	storage := NewMockSessionStorage()
	manager := NewSessionService(DefaultSessionConfig(), storage, nil)

	_, err := manager.Verify("")
	if err != core.ErrInvalidToken {
		t.Errorf("Expected core.ErrInvalidToken for empty token, got %v", err)
	}
}

func TestSessionManagerVerifyInvalidTokenShouldReturnErrSessionNotFound(t *testing.T) {
	storage := NewMockSessionStorage()
	manager := NewSessionService(DefaultSessionConfig(), storage, nil)

	_, err := manager.Verify("invalid-token-that-doesnt-exist")
	if err != core.ErrSessionNotFound {
		t.Errorf("Expected core.ErrSessionNotFound for invalid token, got %v", err)
	}
}

func TestSessionManagerVerifyExpiredSessionShouldReturnErrSessionExpiredAndDeleteItFromStorage(t *testing.T) {
	storage := NewMockSessionStorage()
	config := core.SessionConfig{MaxAge: 100 * time.Millisecond}
	manager := NewSessionService(config, storage, nil)

	// Create session
	result, _ := manager.Create("user123", "192.168.1.1", "Mozilla/5.0")

	// Wait for expiry
	time.Sleep(150 * time.Millisecond)

	// Verify should fail
	_, err := manager.Verify(result.Token)
	if err != core.ErrSessionExpired {
		t.Errorf("Expected core.ErrSessionExpired, got %v", err)
	}

	// Session should be deleted from storage
	_, err = storage.GetSessionByHash(result.Session.TokenHash)
	if err == nil {
		t.Error("Expired session should be deleted from storage")
	}
}

func TestSessionManagerVerifyStorageErrorShouldReturnErrSessionNotFound(t *testing.T) {
	storage := NewMockSessionStorage()
	manager := NewSessionService(DefaultSessionConfig(), storage, nil)

	// Create a session first
	result, _ := manager.Create("user123", "192.168.1.1", "Mozilla/5.0")

	// Simulate storage error
	storage.getErr = errors.New("database connection lost")

	_, err := manager.Verify(result.Token)
	if err != core.ErrSessionNotFound {
		t.Errorf("Expected core.ErrSessionNotFound when storage fails, got %v", err)
	}
}

func TestSessionManagerDestroyBySessionIDShouldRemoveSession(t *testing.T) {
	storage := NewMockSessionStorage()
	manager := NewSessionService(DefaultSessionConfig(), storage, nil)

	// Create session
	result, _ := manager.Create("user123", "192.168.1.1", "Mozilla/5.0")
	sessionID := result.Session.ID

	// Destroy by ID
	err := manager.DestroyBySessionID(sessionID)
	if err != nil {
		t.Fatalf("DestroyBySessionID failed: %v", err)
	}

	// Verify should fail
	_, err = manager.Verify(result.Token)
	if err != core.ErrSessionNotFound {
		t.Errorf("Session should be destroyed, got: %v", err)
	}

	// Should not exist in storage
	_, err = storage.GetSessionByID(sessionID)
	if err == nil {
		t.Error("Session should be deleted from storage")
	}
}

func TestSessionManagerDestroyBySessionIDNonExistentShouldNotPanic(t *testing.T) {
	storage := NewMockSessionStorage()
	manager := NewSessionService(DefaultSessionConfig(), storage, nil)

	// Try to destroy non-existent session
	err := manager.DestroyBySessionID("nonexistent-id")
	// Should not panic, may or may not error
	_ = err
}

func TestSessionManagerDestroyAllUserSessionsShouldRemoveOnlyUserSessions(t *testing.T) {
	storage := NewMockSessionStorage()
	manager := NewSessionService(DefaultSessionConfig(), storage, nil)

	// Create multiple sessions for user123
	result1, _ := manager.Create("user123", "192.168.1.1", "Chrome")
	result2, _ := manager.Create("user123", "192.168.1.2", "Firefox")
	result3, _ := manager.Create("user123", "192.168.1.3", "Safari")

	// Create session for different user
	result4, _ := manager.Create("user456", "192.168.1.4", "Edge")

	// Destroy all sessions for user123
	err := manager.DestroyAllUserSessions("user123")
	if err != nil {
		t.Fatalf("DestroyAllUserSessions failed: %v", err)
	}

	// All user123 sessions should be invalid
	_, err = manager.Verify(result1.Token)
	if err != core.ErrSessionNotFound {
		t.Error("Session 1 should be destroyed")
	}

	_, err = manager.Verify(result2.Token)
	if err != core.ErrSessionNotFound {
		t.Error("Session 2 should be destroyed")
	}

	_, err = manager.Verify(result3.Token)
	if err != core.ErrSessionNotFound {
		t.Error("Session 3 should be destroyed")
	}

	// user456 session should still be valid
	session, err := manager.Verify(result4.Token)
	if err != nil {
		t.Fatalf("user456 session should still be valid: %v", err)
	}

	if session.UserID != "user456" {
		t.Error("user456 session should be untouched")
	}

	// Check storage
	sessions, _ := storage.GetUserSessions("user123")
	if len(sessions) != 0 {
		t.Errorf("Expected 0 sessions for user123, got %d", len(sessions))
	}

	sessions, _ = storage.GetUserSessions("user456")
	if len(sessions) != 1 {
		t.Errorf("Expected 1 session for user456, got %d", len(sessions))
	}
}

func TestSessionManagerDestroyAllUserSessionsNoSessionsShouldNotError(t *testing.T) {
	storage := NewMockSessionStorage()
	manager := NewSessionService(DefaultSessionConfig(), storage, nil)

	// Try to destroy sessions for user with no sessions
	err := manager.DestroyAllUserSessions("nonexistent-user")
	if err != nil {
		t.Errorf("Should not error when user has no sessions, got: %v", err)
	}
}

func TestSessionManagerDefaultSessionConfigShouldSet24Hours(t *testing.T) {
	config := DefaultSessionConfig()

	if config.MaxAge != 24*time.Hour {
		t.Errorf("Expected MaxAge 24h, got %v", config.MaxAge)
	}
}

func TestSessionManagerCustomConfigShouldRespectMaxAge(t *testing.T) {
	storage := NewMockSessionStorage()
	config := core.SessionConfig{MaxAge: 1 * time.Hour}
	manager := NewSessionService(config, storage, nil)

	result, _ := manager.Create("user123", "192.168.1.1", "Mozilla/5.0")

	// Expiry should be ~1 hour from now
	expectedExpiry := time.Now().Add(1 * time.Hour)
	diff := result.Session.ExpiresAt.Sub(expectedExpiry)
	if diff > time.Second || diff < -time.Second {
		t.Errorf("ExpiresAt should be ~1 hour from now, got %v", result.Session.ExpiresAt)
	}
}

func TestSessionManagerConcurrentCreateShouldCreateMultipleSessions(t *testing.T) {
	storage := NewMockSessionStorage()
	manager := NewSessionService(DefaultSessionConfig(), storage, nil)

	// Create 100 sessions concurrently
	done := make(chan bool, 100)

	for i := 0; i < 100; i++ {
		go func(id int) {
			_, err := manager.Create("user123", "192.168.1.1", "Mozilla/5.0")
			if err != nil {
				t.Errorf("Concurrent create failed: %v", err)
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 100; i++ {
		<-done
	}

	// Should have 100 sessions
	sessions, _ := storage.GetUserSessions("user123")
	if len(sessions) != 100 {
		t.Errorf("Expected 100 sessions, got %d", len(sessions))
	}
}

func TestSessionManagerConcurrentVerifyShouldHandleConcurrentVerifies(t *testing.T) {
	storage := NewMockSessionStorage()
	manager := NewSessionService(DefaultSessionConfig(), storage, nil)

	// Create one session
	result, _ := manager.Create("user123", "192.168.1.1", "Mozilla/5.0")

	// Verify 100 times concurrently
	done := make(chan bool, 100)
	errors := make(chan error, 100)

	for i := 0; i < 100; i++ {
		go func() {
			_, err := manager.Verify(result.Token)
			if err != nil {
				errors <- err
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 100; i++ {
		<-done
	}

	close(errors)

	// Should have no errors
	for err := range errors {
		t.Errorf("Concurrent verify failed: %v", err)
	}
}

func TestSessionManagerWithCacheHitShouldReturnFromCacheOnSecondVerify(t *testing.T) {
	storage := NewMockSessionStorage()
	cache := cache.NewInMemoryCache(core.CacheConfig{
		TTL:     5 * time.Minute,
		MaxSize: 500,
	})
	manager := NewSessionService(DefaultSessionConfig(), storage, cache)

	// Create session
	result, _ := manager.Create("user123", "192.168.1.1", "Mozilla/5.0")

	// First verify (cache miss, queries storage, caches result)
	session1, err := manager.Verify(result.Token)
	if err != nil {
		t.Fatalf("First verify failed: %v", err)
	}

	// Break storage to prove second verify uses cache
	storage.getErr = core.ErrSessionNotFound

	// Second verify should hit cache (storage is "broken")
	session2, err := manager.Verify(result.Token)
	if err != nil {
		t.Fatalf("Second verify should succeed from cache: %v", err)
	}

	if session1.ID != session2.ID {
		t.Error("Both verifies should return same session")
	}

	// Verify cache was actually used
	if cache.Len() != 1 {
		t.Errorf("Expected 1 session in cache, got %d", cache.Len())
	}
}

func TestSessionManagerWithCacheMissShouldCacheSessionAfterVerify(t *testing.T) {
	storage := NewMockSessionStorage()
	cache := cache.NewInMemoryCache(core.CacheConfig{
		TTL:     5 * time.Minute,
		MaxSize: 500,
	})
	manager := NewSessionService(DefaultSessionConfig(), storage, cache)

	// Create session
	result, _ := manager.Create("user123", "192.168.1.1", "Mozilla/5.0")

	// Verify (should query storage and cache)
	_, err := manager.Verify(result.Token)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	// Verify session is cached
	if cache.Len() != 1 {
		t.Error("Session should be cached after first verify")
	}
}

func TestSessionManagerWithCacheDestroyInvalidatesCacheShouldClearCacheAfterDestroy(t *testing.T) {
	storage := NewMockSessionStorage()
	cache := cache.NewInMemoryCache(core.CacheConfig{
		TTL:     5 * time.Minute,
		MaxSize: 500,
	})
	manager := NewSessionService(DefaultSessionConfig(), storage, cache)

	// Create and verify session (caches it)
	result, _ := manager.Create("user123", "192.168.1.1", "Mozilla/5.0")
	manager.Verify(result.Token)

	// Verify it's cached
	if cache.Len() != 1 {
		t.Error("Session should be cached")
	}

	// Destroy
	err := manager.Destroy(result.Token)
	if err != nil {
		t.Fatalf("Destroy failed: %v", err)
	}

	// Cache should be invalidated
	if cache.Len() != 0 {
		t.Error("Cache should be empty after Destroy")
	}

	// Verify should fail
	_, err = manager.Verify(result.Token)
	if err != core.ErrSessionNotFound {
		t.Error("Session should be destroyed")
	}
}

func TestSessionManagerWithCacheDestroyByIDInvalidatesCacheShouldClearCache(t *testing.T) {
	storage := NewMockSessionStorage()
	cache := cache.NewInMemoryCache(core.CacheConfig{
		TTL:     5 * time.Minute,
		MaxSize: 500,
	})
	manager := NewSessionService(DefaultSessionConfig(), storage, cache)

	// Create and verify session (caches it)
	result, _ := manager.Create("user123", "192.168.1.1", "Mozilla/5.0")
	manager.Verify(result.Token)

	// Destroy by ID
	err := manager.DestroyBySessionID(result.Session.ID)
	if err != nil {
		t.Fatalf("DestroyBySessionID failed: %v", err)
	}

	// Cache should be invalidated
	if cache.Len() != 0 {
		t.Error("Cache should be empty after DestroyBySessionID")
	}
}

func TestSessionManagerWithCacheDestroyAllUserSessionsClearsCacheShouldClearCache(t *testing.T) {
	storage := NewMockSessionStorage()
	cache := cache.NewInMemoryCache(core.CacheConfig{
		TTL:     5 * time.Minute,
		MaxSize: 500,
	})
	manager := NewSessionService(DefaultSessionConfig(), storage, cache)

	// Create multiple sessions and cache them
	result1, _ := manager.Create("user123", "192.168.1.1", "Chrome")
	result2, _ := manager.Create("user123", "192.168.1.2", "Firefox")
	result3, _ := manager.Create("user456", "192.168.1.3", "Safari")

	manager.Verify(result1.Token)
	manager.Verify(result2.Token)
	manager.Verify(result3.Token)

	// Should have 3 cached sessions
	if cache.Len() != 3 {
		t.Errorf("Expected 3 cached sessions, got %d", cache.Len())
	}

	// Destroy all user123 sessions
	err := manager.DestroyAllUserSessions("user123")
	if err != nil {
		t.Fatalf("DestroyAllUserSessions failed: %v", err)
	}

	// Cache should be cleared (simple implementation clears all)
	if cache.Len() != 0 {
		t.Error("Cache should be cleared after DestroyAllUserSessions")
	}
}

func TestSessionManagerWithCacheExpiredInCacheShouldDetectExpiryAndRemoveFromCache(t *testing.T) {
	storage := NewMockSessionStorage()
	cache := cache.NewInMemoryCache(core.CacheConfig{
		TTL:     5 * time.Minute,
		MaxSize: 500,
	})
	config := core.SessionConfig{MaxAge: 100 * time.Millisecond}
	manager := NewSessionService(config, storage, cache)

	// Create session
	result, _ := manager.Create("user123", "192.168.1.1", "Mozilla/5.0")

	// Verify (caches it)
	manager.Verify(result.Token)

	// Wait for session to expire (but still in cache)
	time.Sleep(150 * time.Millisecond)

	// Verify should detect expiry and remove from cache
	_, err := manager.Verify(result.Token)
	if err != core.ErrSessionExpired {
		t.Errorf("Expected core.ErrSessionExpired, got %v", err)
	}

	// Cache should be invalidated
	if cache.Len() != 0 {
		t.Error("Expired session should be removed from cache")
	}
}
