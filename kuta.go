package kuta

import (
	"time"

	"github.com/lborres/kuta/core"
	"github.com/lborres/kuta/crypto"
)

// interfaces
type (
	AuthStorage = core.AuthStorage
	Cache       = core.Cache

	HTTPAdapter = core.HTTPAdapter

	SessionManager = core.SessionManager

	PasswordHandler = crypto.PasswordHandler
)

// structs
type (
	Kuta          = core.Kuta
	Config        = core.Config
	SessionConfig = core.SessionConfig
	CacheConfig   = core.CacheConfig
)

type (
	User    = core.User
	Account = core.Account
	Session = core.Session
)

const (
	defaultBasePath = "/api/auth"
)

var (
	ErrUserExists         = core.ErrUserExists
	ErrUserNotFound       = core.ErrUserNotFound
	ErrInvalidCredentials = core.ErrInvalidCredentials
)

var (
	ErrMissingAuthHeader = core.ErrMissingAuthHeader
	ErrInvalidToken      = core.ErrInvalidToken
	ErrSessionNotFound   = core.ErrSessionNotFound
	ErrSessionExpired    = core.ErrSessionExpired
	ErrCacheNotFound     = core.ErrCacheNotFound
)

var (
	ErrInvalidAuthHeader = core.ErrInvalidAuthHeader
	ErrEmailRequired     = core.ErrEmailRequired
	ErrPasswordRequired  = core.ErrPasswordRequired
	ErrPasswordTooShort  = core.ErrPasswordTooShort
	ErrPasswordTooLong   = core.ErrPasswordTooLong
	ErrInvalidEmail      = core.ErrInvalidEmail
)

var (
	ErrDBAdapterRequired   = core.ErrDBAdapterRequired
	ErrHTTPAdapterRequired = core.ErrHTTPAdapterRequired
	ErrSecretRequired      = core.ErrSecretRequired
	ErrSecretTooShort      = core.ErrSecretTooShort
)

var (
	ErrNotImplemented = core.ErrNotImplemented
)

func New(config Config) (*Kuta, error) {
	if config.Secret == "" {
		return nil, ErrSecretRequired
	}
	if config.Database == nil {
		return nil, ErrDBAdapterRequired
	}
	if config.HTTP == nil {
		return nil, ErrHTTPAdapterRequired
	}

	// Set Defaults

	// TODO: user should be able to opt out of cache
	cacheAdapter := config.CacheAdapter
	if cacheAdapter == nil {
		cacheAdapter = core.NewInMemoryCache(CacheConfig{
			TTL:     5 * time.Minute,
			MaxSize: 500,
		})
	}

	sessionConfig := config.SessionConfig
	if sessionConfig == nil {
		sessionConfig = &SessionConfig{
			MaxAge: 24 * time.Hour,
		}
	}

	passwordHasher := config.PasswordHasher
	if passwordHasher == nil {
		passwordHasher = crypto.NewArgon2()
	}

	basePath := config.BasePath
	if basePath == "" {
		basePath = defaultBasePath
	}

	sessionManager := core.NewSessionManager(
		*sessionConfig,
		config.Database,
		cacheAdapter,
	)

	kuta := &Kuta{
		SessionManager: sessionManager,
		PasswordHasher: passwordHasher,
		Secret:         config.Secret,
		BasePath:       basePath,
	}

	if err := config.HTTP.RegisterRoutes(kuta); err != nil {
		return nil, err
	}

	return kuta, nil
}
