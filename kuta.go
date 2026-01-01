package kuta

import (
	"fmt"
	"time"

	"github.com/lborres/kuta/core"
	"github.com/lborres/kuta/pkg/cache"
	"github.com/lborres/kuta/pkg/crypto"
	"github.com/lborres/kuta/services"
)

type (
	AuthStorage = core.StorageAdapter
	AuthHandler = core.AuthHandler
	Cache       = core.Cache

	HTTPAdapter = core.HTTPAdapter

	SessionManager = services.SessionManager

	PasswordHandler = crypto.PasswordHandler
)

type (
	SessionConfig = core.SessionConfig
	CacheConfig   = core.CacheConfig
)

type (
	User        = core.User
	Account     = core.Account
	Session     = core.Session
	SessionData = core.SessionData
	CacheStats  = core.CacheStats
)

type (
	SignUpInput  = core.SignUpInput
	SignUpResult = core.SignUpResult
	SignInInput  = core.SignInInput
	SignInResult = core.SignInResult
)

const (
	defaultBasePath  = "/api/auth"
	defaultSecretLen = 32
)

// Constructors & helpers (convenience re-exports)
var (
	NewInMemoryCache = cache.NewInMemoryCache
	NewArgon2        = crypto.NewArgon2
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

type Config struct {
	Secret string

	Database core.StorageAdapter

	HTTP core.HTTPAdapter

	// Optional config
	SessionConfig  *core.SessionConfig
	PasswordHasher crypto.PasswordHandler
	BasePath       string

	CacheAdapter core.Cache
	DisableCache bool
}

type Kuta struct {
	SessionManager *services.SessionManager
	AuthService    *services.AuthService
	Database       core.StorageAdapter
	Secret         string
	BasePath       string
}

func New(config Config) (*Kuta, error) {
	if config.Secret == "" {
		return nil, core.ErrSecretRequired
	}
	if len(config.Secret) < defaultSecretLen {
		return nil, fmt.Errorf("%w - minimum of %d characters", core.ErrSecretTooShort, defaultSecretLen)
	}
	if config.Database == nil {
		return nil, core.ErrDBAdapterRequired
	}
	if config.HTTP == nil {
		return nil, core.ErrHTTPAdapterRequired
	}

	// Set Defaults

	cacheAdapter := config.CacheAdapter
	if cacheAdapter == nil && !config.DisableCache {
		cacheAdapter = cache.NewInMemoryCache(core.CacheConfig{
			TTL:     5 * time.Minute,
			MaxSize: 500,
		})
	}

	sessionConfig := config.SessionConfig
	if sessionConfig == nil {
		sessionConfig = &core.SessionConfig{
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

	sessionService := services.NewSessionService(*sessionConfig, config.Database, cacheAdapter)
	authService := services.NewAuthService(&config.Database, &passwordHasher, sessionService)

	kuta := &Kuta{
		SessionManager: sessionService,
		AuthService:    authService,
		Database:       config.Database,
		Secret:         config.Secret,
		BasePath:       basePath,
	}

	if err := config.HTTP.RegisterRoutes(authService, basePath, sessionConfig.MaxAge); err != nil {
		return nil, err
	}

	// return kuta instance to provide more options for testing
	return kuta, nil
}
