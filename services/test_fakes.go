package services

import (
	"errors"
	"sync"

	"github.com/lborres/kuta/core"
)

// FakeSessionStorage is a test-only fake implementing core.SessionStorage.
// It stores sessions in a map and exposes error fields for behavior injection.
type FakeSessionStorage struct {
	sessions  map[string]*core.Session
	mu        sync.RWMutex
	createErr error
	getErr    error
	deleteErr error
}

func NewFakeSessionStorage() *FakeSessionStorage {
	return &FakeSessionStorage{
		sessions: make(map[string]*core.Session),
	}
}

func (f *FakeSessionStorage) CreateSession(s *core.Session) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.createErr != nil {
		return f.createErr
	}

	f.sessions[s.TokenHash] = s
	return nil
}

func (f *FakeSessionStorage) GetSessionByHash(tokenHash string) (*core.Session, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.getErr != nil {
		return nil, f.getErr
	}
	s, ok := f.sessions[tokenHash]
	if !ok {
		return nil, errors.New("session not found")
	}
	return s, nil
}

func (f *FakeSessionStorage) GetSessionByID(id string) (*core.Session, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	for _, s := range f.sessions {
		if s.ID == id {
			return s, nil
		}
	}
	return nil, errors.New("session not found")
}

func (f *FakeSessionStorage) DeleteSessionByHash(tokenHash string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.deleteErr != nil {
		return f.deleteErr
	}
	if _, ok := f.sessions[tokenHash]; !ok {
		return core.ErrSessionNotFound
	}
	delete(f.sessions, tokenHash)
	return nil
}

func (f *FakeSessionStorage) DeleteSessionByID(id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.deleteErr != nil {
		return f.deleteErr
	}
	for k, s := range f.sessions {
		if s.ID == id {
			delete(f.sessions, k)
			return nil
		}
	}
	return core.ErrSessionNotFound
}

func (f *FakeSessionStorage) GetUserSessions(userID string) ([]*core.Session, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	var sessions []*core.Session
	for _, s := range f.sessions {
		if s.UserID == userID {
			sessions = append(sessions, s)
		}
	}
	return sessions, nil
}
func (f *FakeSessionStorage) UpdateSession(s *core.Session) error {
	panic("not implemented")
}
func (f *FakeSessionStorage) DeleteUserSessions(userID string) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	count := 0
	for k, s := range f.sessions {
		if s.UserID == userID {
			delete(f.sessions, k)
			count++
		}
	}
	return count, nil
}
func (f *FakeSessionStorage) DeleteExpiredSessions() (int, error) {
	panic("not implemented")
}

// FakeStorageProvider is a test-only fake implementing core.StorageProvider.
// It combines session, user, and account storage fakes.
type FakeStorageProvider struct {
	*FakeSessionStorage
	users    map[string]*core.User
	accounts map[string]*core.Account
}

func NewFakeStorageProvider() *FakeStorageProvider {
	return &FakeStorageProvider{
		FakeSessionStorage: NewFakeSessionStorage(),
		users:              make(map[string]*core.User),
		accounts:           make(map[string]*core.Account),
	}
}

// UserStorage implementation
func (f *FakeStorageProvider) CreateUser(u *core.User) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, exists := f.users[u.ID]; exists {
		return core.ErrUserExists
	}
	f.users[u.ID] = u
	return nil
}

func (f *FakeStorageProvider) GetUserByID(id string) (*core.User, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if u, ok := f.users[id]; ok {
		return u, nil
	}
	return nil, core.ErrUserNotFound
}

func (f *FakeStorageProvider) GetUserByEmail(email string) (*core.User, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	for _, u := range f.users {
		if u.Email == email {
			return u, nil
		}
	}
	return nil, core.ErrUserNotFound
}

func (f *FakeStorageProvider) UpdateUser(u *core.User) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, exists := f.users[u.ID]; !exists {
		return core.ErrUserNotFound
	}
	f.users[u.ID] = u
	return nil
}

func (f *FakeStorageProvider) DeleteUser(id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, exists := f.users[id]; !exists {
		return core.ErrUserNotFound
	}
	delete(f.users, id)
	return nil
}

// AccountStorage implementation
func (f *FakeStorageProvider) CreateAccount(a *core.Account) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.accounts[a.ID] = a
	return nil
}

func (f *FakeStorageProvider) GetAccountByID(id string) (*core.Account, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if a, ok := f.accounts[id]; ok {
		return a, nil
	}
	return nil, errors.New("account not found")
}

func (f *FakeStorageProvider) GetAccountByUserAndProvider(userID, providerID string) ([]*core.Account, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	var accounts []*core.Account
	for _, a := range f.accounts {
		if a.UserID == userID && a.ProviderID == providerID {
			accounts = append(accounts, a)
		}
	}
	return accounts, nil
}

func (f *FakeStorageProvider) UpdateAccount(a *core.Account) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, exists := f.accounts[a.ID]; !exists {
		return errors.New("account not found")
	}
	f.accounts[a.ID] = a
	return nil
}

func (f *FakeStorageProvider) DeleteAccount(id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, exists := f.accounts[id]; !exists {
		return errors.New("account not found")
	}
	delete(f.accounts, id)
	return nil
}

// FakeCache is a test-only fake implementing core.Cache.
// It stores sessions in a map and exposes error fields for behavior injection.
type FakeCache struct {
	cache    map[string]*core.Session
	mu       sync.RWMutex
	getErr   error
	setErr   error
	delErr   error
	clearErr error
	hits     int
	misses   int
}

func NewFakeCache() *FakeCache {
	return &FakeCache{
		cache: make(map[string]*core.Session),
	}
}

func (f *FakeCache) Get(tokenHash string) (*core.Session, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	if f.getErr != nil {
		return nil, f.getErr
	}

	s, ok := f.cache[tokenHash]
	if !ok {
		f.misses++
		return nil, core.ErrCacheNotFound
	}

	f.hits++
	return s, nil
}

func (f *FakeCache) Set(tokenHash string, session *core.Session) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.setErr != nil {
		return f.setErr
	}

	f.cache[tokenHash] = session
	return nil
}

func (f *FakeCache) Delete(tokenHash string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.delErr != nil {
		return f.delErr
	}

	delete(f.cache, tokenHash)
	return nil
}

func (f *FakeCache) Clear() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.clearErr != nil {
		return f.clearErr
	}

	f.cache = make(map[string]*core.Session)
	return nil
}

func (f *FakeCache) Stats() core.CacheStats {
	f.mu.RLock()
	defer f.mu.RUnlock()

	return core.CacheStats{
		Hits:   int64(f.hits),
		Misses: int64(f.misses),
		Size:   len(f.cache),
	}
}

// Test helper methods
func (f *FakeCache) SetGetError(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.getErr = err
}

func (f *FakeCache) SetSetError(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.setErr = err
}

func (f *FakeCache) SetDeleteError(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.delErr = err
}

func (f *FakeCache) Len() int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return len(f.cache)
}

// fakeFailingCache is a cache that always fails Set operations.
type fakeFailingCache struct{}

func (f *fakeFailingCache) Get(tokenHash string) (*core.Session, error) {
	return nil, core.ErrCacheNotFound
}
func (f *fakeFailingCache) Set(tokenHash string, session *core.Session) error {
	return errors.New("cache set failed")
}
func (f *fakeFailingCache) Delete(tokenHash string) error {
	return errors.New("cache delete failed")
}
func (f *fakeFailingCache) Clear() error {
	return errors.New("cache clear failed")
}
func (f *fakeFailingCache) Stats() core.CacheStats {
	return core.CacheStats{}
}
