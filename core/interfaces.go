package core

import (
	"time"
)

// Ports define interfaces for external dependencies

// ============================================
// STORAGE PORTS (Database operations)
// ============================================

// SessionStorage defines session-related database operations
type SessionStorage interface {
	CreateSession(session *Session) error
	GetSessionByHash(tokenHash string) (*Session, error)
	GetSessionByID(id string) (*Session, error)
	GetUserSessions(userID string) ([]*Session, error)
	UpdateSession(session *Session) error
	DeleteSessionByID(id string) error
	DeleteSessionByHash(tokenHash string) error
	DeleteUserSessions(userID string) error
	DeleteExpiredSessions() (int, error)
}

// UserStorage defines user-related database operations
type UserStorage interface {
	CreateUser(u *User) error
	GetUserByID(id string) (*User, error)
	GetUserByEmail(email string) (*User, error)
	UpdateUser(u *User) error
	DeleteUser(id string) error
}

// AccountStorage defines account-related database operations
type AccountStorage interface {
	CreateAccount(a *Account) error
	GetAccountByID(id string) (*Account, error)
	GetAccountByUserAndProvider(userID, providerID string) ([]*Account, error)
	UpdateAccount(a *Account) error
	DeleteAccount(id string) error
}

type StorageAdapter interface {
	UserStorage
	AccountStorage
	SessionStorage
}

// ============================================
// CACHE PORT
// ============================================

// Cache defines session caching operations
type Cache interface {
	Get(tokenHash string) (*Session, error)
	Set(tokenHash string, session *Session) error
	Delete(tokenHash string) error
	Clear() error
}

// CacheWithStats extends Cache with statistics tracking
type CacheWithStats interface {
	Cache
	Stats() CacheStats
}

// CacheConfig configures cache behavior
type CacheConfig struct {
	TTL     time.Duration
	MaxSize int
}

// CacheStats tracks cache performance metrics
type CacheStats struct {
	Hits      int64         `json:"hits"`
	Misses    int64         `json:"misses"`
	Sets      int64         `json:"sets"`
	Deletes   int64         `json:"deletes"`
	Evictions int64         `json:"evictions"`
	Size      int           `json:"size"`
	TTL       time.Duration `json:"ttl"`
}

// ============================================
// AUTH HANDLER (for HTTP adapters)
// ============================================

// AuthHandler provides authentication operations for HTTP adapters
type AuthHandler interface {
	SignUp(input SignUpInput, ipAddress, userAgent string) (*SignUpResult, error)
	SignIn(input SignInInput, ipAddress, userAgent string) (*SignInResult, error)
	SignOut(token string) error
	GetSession(token string) (*SessionData, error)
}

// ============================================
// HTTP PORT
// ============================================

type HTTPAdapter interface {
	RegisterRoutes(handler AuthHandler, basePath string, ttl time.Duration) error
}
