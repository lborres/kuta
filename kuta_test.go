package kuta

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

type MockAuthStorage struct {
	mu       sync.RWMutex
	sessions map[string]*Session
	getErr   error
}

func NewMockAuthStorage() *MockAuthStorage {
	return &MockAuthStorage{sessions: make(map[string]*Session)}
}

// SessionStorage methods
func (m *MockAuthStorage) CreateSession(session *Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[session.TokenHash] = session
	return nil
}

func (m *MockAuthStorage) GetSessionByHash(tokenHash string) (*Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.getErr != nil {
		return nil, m.getErr
	}
	s, ok := m.sessions[tokenHash]
	if !ok {
		return nil, ErrSessionNotFound
	}
	return s, nil
}

func (m *MockAuthStorage) GetSessionByID(id string) (*Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, s := range m.sessions {
		if s.ID == id {
			return s, nil
		}
	}
	return nil, ErrSessionNotFound
}

func (m *MockAuthStorage) GetUserSessions(userID string) ([]*Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []*Session
	for _, s := range m.sessions {
		if s.UserID == userID {
			out = append(out, s)
		}
	}
	return out, nil
}

func (m *MockAuthStorage) UpdateSession(session *Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[session.TokenHash] = session
	return nil
}

func (m *MockAuthStorage) DeleteSessionByID(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, s := range m.sessions {
		if s.ID == id {
			delete(m.sessions, k)
			return nil
		}
	}
	return nil
}

func (m *MockAuthStorage) DeleteSessionByHash(tokenHash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, tokenHash)
	return nil
}

func (m *MockAuthStorage) DeleteUserSessions(userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, s := range m.sessions {
		if s.UserID == userID {
			delete(m.sessions, k)
		}
	}
	return nil
}

func (m *MockAuthStorage) DeleteExpiredSessions() (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	count := 0
	now := time.Now()
	for k, s := range m.sessions {
		if now.After(s.ExpiresAt) {
			delete(m.sessions, k)
			count++
		}
	}
	return count, nil
}

// UserStorage methods (minimal stubs)
func (m *MockAuthStorage) CreateUser(u *User) error                   { return nil }
func (m *MockAuthStorage) GetUserByID(id string) (*User, error)       { return nil, nil }
func (m *MockAuthStorage) GetUserByEmail(email string) (*User, error) { return nil, nil }
func (m *MockAuthStorage) UpdateUser(u *User) error                   { return nil }
func (m *MockAuthStorage) DeleteUser(id string) error                 { return nil }

// AccountStorage methods (minimal stubs)
func (m *MockAuthStorage) CreateAccount(a *Account) error             { return nil }
func (m *MockAuthStorage) GetAccountByID(id string) (*Account, error) { return nil, nil }
func (m *MockAuthStorage) GetAccountByUserAndProvider(userID, providerID string) ([]*Account, error) {
	return nil, nil
}
func (m *MockAuthStorage) UpdateAccount(a *Account) error { return nil }
func (m *MockAuthStorage) DeleteAccount(id string) error  { return nil }

// dummy HTTP Adapter
type dummyHTTP struct{}

func (d *dummyHTTP) RegisterRoutes(k *Kuta) error { return nil }

func TestNewShouldNotUseCacheWhenDisableCacheTrue(t *testing.T) {
	storage := NewMockAuthStorage()
	adapter := &dummyHTTP{}

	cfg := Config{
		Secret:       "01234567890123456789012345678901",
		Database:     storage,
		HTTP:         adapter,
		DisableCache: true,
	}

	k, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// Create a session
	res, err := k.SessionManager.Create("user1", "127.0.0.1", "ua")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Simulate storage failure - with no cache, Verify should hit storage and fail
	storage.getErr = ErrSessionNotFound
	_, err = k.SessionManager.Verify(res.Token)
	if err != ErrSessionNotFound {
		t.Fatalf("expected ErrSessionNotFound because cache disabled, got %v", err)
	}
}

func TestNewShouldReturnErrSecretTooShort(t *testing.T) {
	storage := NewMockAuthStorage()
	adapter := &dummyHTTP{}

	cfg := Config{
		Secret:   "short-secret",
		Database: storage,
		HTTP:     adapter,
	}

	_, err := New(cfg)
	if !errors.Is(err, ErrSecretTooShort) {
		t.Fatalf("expected ErrSecretTooShort sentinel (errors.Is), got %v", err)
	}
	// Message should include the minimum length
	if !strings.Contains(err.Error(), "32") {
		t.Fatalf("expected error message to include minimum length, got %v", err)
	}
}
