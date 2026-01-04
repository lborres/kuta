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
	StorageProvider  = core.StorageProvider
	AuthProvider     = core.AuthProvider
	Cache            = core.Cache
	HTTPProvider     = core.HTTPProvider
	EndpointProvider = core.EndpointProvider
	Endpoint         = core.Endpoint
	RequestContext   = core.RequestContext
	EndpointMetadata = core.EndpointMetadata

	// SessionManager = services.SessionManager

	PasswordHandler = crypto.PasswordHandler
)

type (
	SessionConfig = core.SessionConfig
	CacheConfig   = core.CacheConfig
)

type (
	User          = core.User
	Account       = core.Account
	Session       = core.Session
	SessionData   = core.SessionData
	CacheStats    = core.CacheStats
	ErrorResponse = core.ErrorResponse
)

type (
	SignUpInput   = core.SignUpInput
	SignUpResult  = core.SignUpResult
	SignInInput   = core.SignInInput
	SignInResult  = core.SignInResult
	RefreshResult = core.RefreshResult
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

// Exposes Kuta properties for user to configure
type Config struct {
	Secret string

	Database core.StorageProvider

	HTTP core.HTTPProvider

	// Optional config
	SessionConfig   *core.SessionConfig
	PasswordHandler crypto.PasswordHandler
	BasePath        string

	CacheProvider core.Cache
	DisableCache  bool
}

type Kuta struct {
	Protected    interface{}
	authProvider core.AuthProvider
	httpAdapter  core.HTTPProvider
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

	cacheProvider := config.CacheProvider
	if cacheProvider == nil && !config.DisableCache {
		cacheProvider = cache.NewInMemoryCache(core.CacheConfig{
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

	passwordHandler := config.PasswordHandler
	if passwordHandler == nil {
		passwordHandler = crypto.NewArgon2()
	}

	basePath := config.BasePath
	if basePath == "" {
		basePath = defaultBasePath
	}

	sessionService := services.NewSessionManager(*sessionConfig, config.Database, cacheProvider, passwordHandler)

	if err := config.HTTP.RegisterRoutes(sessionService, basePath, sessionConfig.MaxAge); err != nil {
		return nil, err
	}

	k := &Kuta{
		authProvider: sessionService,
		httpAdapter:  config.HTTP,

		// Set exported Protected field to the framework-specific middleware value
		Protected: config.HTTP.BuildProtectedMiddleware(sessionService),
	}

	return k, nil
}
