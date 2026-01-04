package services

import (
	"time"

	"github.com/lborres/kuta/core"
	"github.com/lborres/kuta/pkg/crypto"
)

type SessionManager struct {
	config  core.SessionConfig
	storage core.SessionStorage
	cache   core.Cache // optional, can be nil if caching is disabled
	nanoid  *crypto.NanoIDGenerator
}

func NewSessionManager(config core.SessionConfig, storage core.SessionStorage, cache core.Cache) *SessionManager {
	nanoid, _ := crypto.NewNanoID()
	return &SessionManager{config: config, storage: storage, cache: cache, nanoid: nanoid}
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
		ExpiresAt: now.Add(sm.config.MaxAge),
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
