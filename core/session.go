package core

import (
	"fmt"
	"time"

	"github.com/lborres/kuta/pkg/crypto"
)

type SessionConfig struct {
	MaxAge time.Duration
}

type SessionManager struct {
	config  SessionConfig
	storage SessionStorage
	cache   Cache
}

type CreateSessionResult struct {
	Session *Session `json:"session"`
	Token   string   `json:"token"`
}

func DefaultSessionConfig() SessionConfig {
	return SessionConfig{
		MaxAge: 24 * time.Hour,
	}
}

func NewSessionManager(config SessionConfig, storage SessionStorage, cache Cache) *SessionManager {
	return &SessionManager{
		config:  config,
		storage: storage,
		cache:   cache,
	}
}

func (sm *SessionManager) Create(userID, ipAddress, userAgent string) (*CreateSessionResult, error) {
	nanoid := crypto.NewNanoID()

	token, err := crypto.GenerateHashedToken(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	id, err := nanoid.Generate()
	if err != nil {
		return nil, fmt.Errorf("failed to generate ID: %w", err)
	}

	now := time.Now()
	session := &Session{
		ID:        id,
		UserID:    userID,
		TokenHash: token.Hash,
		IPAddress: ipAddress,
		UserAgent: userAgent,
		ExpiresAt: now.Add(sm.config.MaxAge),
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := sm.storage.CreateSession(session); err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	return &CreateSessionResult{
		Session: session,
		Token:   token.Token,
	}, nil
}

func (sm *SessionManager) Verify(token string) (*Session, error) {
	if token == "" {
		return nil, ErrInvalidToken
	}

	tokenHash := crypto.HashToken(token)

	if sm.cache != nil {
		if session, err := sm.cache.Get(tokenHash); err == nil && session != nil {
			if time.Now().Before(session.ExpiresAt) {
				return session, nil
			}
			sm.cache.Delete(tokenHash)
		}
	}

	session, err := sm.storage.GetSessionByHash(tokenHash)
	if err != nil {
		return nil, ErrSessionNotFound
	}

	valid, err := crypto.VerifyToken(token, session.TokenHash)
	if err != nil || !valid {
		return nil, ErrInvalidToken
	}

	if time.Now().After(session.ExpiresAt) {
		sm.storage.DeleteSessionByID(session.ID)
		return nil, ErrSessionExpired
	}

	if sm.cache != nil {
		sm.cache.Set(tokenHash, session)
	}

	return session, nil
}

func (sm *SessionManager) Destroy(token string) error {
	tokenHash := crypto.HashToken(token)

	// Invalidate cache if available
	if sm.cache != nil {
		sm.cache.Delete(tokenHash)
	}

	return sm.storage.DeleteSessionByHash(tokenHash)
}

func (sm *SessionManager) DestroyBySessionID(sessionID string) error {
	session, err := sm.storage.GetSessionByID(sessionID)
	if err == nil && sm.cache != nil {
		sm.cache.Delete(session.TokenHash)
	}

	// still attempt to delete even if no session found
	return sm.storage.DeleteSessionByID(sessionID)
}

func (sm *SessionManager) DestroyAllUserSessions(userID string) error {
	if sm.cache != nil {
		sm.cache.Clear()
	}

	return sm.storage.DeleteUserSessions(userID)
}
