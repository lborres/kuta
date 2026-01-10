package kuta

import (
	"fmt"
	"time"

	"github.com/lborres/kuta/core"
	"github.com/lborres/kuta/pkg/cache"
	"github.com/lborres/kuta/pkg/crypto"
	"github.com/lborres/kuta/services"
)

// Re-exports from core and services packages
type (
	StorageProvider  = core.StorageProvider
	AuthProvider     = core.AuthProvider
	Cache            = core.Cache
	HTTPProvider     = core.HTTPProvider
	EndpointProvider = core.EndpointProvider
	Endpoint         = core.Endpoint
	RequestContext   = core.RequestContext
	EndpointMetadata = core.EndpointMetadata
	PasswordHandler  = crypto.PasswordHandler
	SessionConfig    = core.SessionConfig
	CookieConfig     = core.CookieConfig
	CacheConfig      = core.CacheConfig
	User             = core.User
	Account          = core.Account
	Session          = core.Session
	SessionData      = core.SessionData
	CacheStats       = core.CacheStats
	ErrorResponse    = core.ErrorResponse
	SignUpInput      = core.SignUpInput
	SignUpResult     = core.SignUpResult
	SignInInput      = core.SignInInput
	SignInResult     = core.SignInResult
	RefreshResult    = core.RefreshResult
)

// Errors
var (
	ErrUserExists          = core.ErrUserExists
	ErrUserNotFound        = core.ErrUserNotFound
	ErrInvalidCredentials  = core.ErrInvalidCredentials
	ErrMissingAuthHeader   = core.ErrMissingAuthHeader
	ErrInvalidToken        = core.ErrInvalidToken
	ErrSessionNotFound     = core.ErrSessionNotFound
	ErrSessionExpired      = core.ErrSessionExpired
	ErrCacheNotFound       = core.ErrCacheNotFound
	ErrInvalidAuthHeader   = core.ErrInvalidAuthHeader
	ErrEmailRequired       = core.ErrEmailRequired
	ErrPasswordRequired    = core.ErrPasswordRequired
	ErrPasswordTooShort    = core.ErrPasswordTooShort
	ErrPasswordTooLong     = core.ErrPasswordTooLong
	ErrInvalidEmail        = core.ErrInvalidEmail
	ErrDBAdapterRequired   = core.ErrDBAdapterRequired
	ErrHTTPAdapterRequired = core.ErrHTTPAdapterRequired
	ErrSecretRequired      = core.ErrSecretRequired
	ErrSecretTooShort      = core.ErrSecretTooShort
	ErrNotImplemented      = core.ErrNotImplemented
)

// Constructors
var (
	NewInMemoryCache = cache.NewInMemoryCache
	NewArgon2        = crypto.NewArgon2
)

const (
	defaultBasePath  = "/api/auth"
	defaultSecretLen = 32
)

// Config for Kuta initialization
type Config struct {
	Secret          string
	Database        StorageProvider
	HTTP            HTTPProvider
	SessionConfig   *SessionConfig
	CookieConfig    *CookieConfig
	PasswordHandler PasswordHandler
	BasePath        string
	CacheProvider   Cache
	DisableCache    bool
}

// Kuta is the main auth instance
type Kuta struct {
	Protected    interface{}
	authProvider AuthProvider
	httpAdapter  HTTPProvider
}

// New creates a new Kuta instance
func New(config Config) (*Kuta, error) {
	if config.Secret == "" {
		return nil, ErrSecretRequired
	}
	if len(config.Secret) < defaultSecretLen {
		return nil, fmt.Errorf("%w - minimum of %d characters", ErrSecretTooShort, defaultSecretLen)
	}
	if config.Database == nil {
		return nil, ErrDBAdapterRequired
	}
	if config.HTTP == nil {
		return nil, ErrHTTPAdapterRequired
	}

	// Set defaults
	if config.CacheProvider == nil && !config.DisableCache {
		config.CacheProvider = NewInMemoryCache(CacheConfig{
			TTL:     5 * time.Minute,
			MaxSize: 500,
		})
	}

	if config.SessionConfig == nil {
		config.SessionConfig = &SessionConfig{
			ExpiresIn: 7 * 24 * time.Hour,
			UpdateAge: 24 * time.Hour,
		}
	}

	// Wire CookieConfig into SessionConfig
	if config.CookieConfig != nil {
		config.SessionConfig.CookieConfig = config.CookieConfig
	} else {
		config.SessionConfig.CookieConfig = core.DefaultCookieConfig()
	}

	if config.PasswordHandler == nil {
		config.PasswordHandler = NewArgon2()
	}

	if config.BasePath == "" {
		config.BasePath = defaultBasePath
	}

	// Create session service
	sessionService := services.NewSessionManager(
		*config.SessionConfig,
		config.Database,
		config.CacheProvider,
		config.PasswordHandler,
	)

	// Register HTTP routes
	if err := config.HTTP.RegisterRoutes(
		sessionService,
		config.BasePath,
		config.SessionConfig,
	); err != nil {
		return nil, err
	}

	return &Kuta{
		authProvider: sessionService,
		httpAdapter:  config.HTTP,

		// Set exported Protected field to the framework-specific middleware value
		Protected: config.HTTP.BuildProtectedMiddleware(sessionService),
	}, nil
}
