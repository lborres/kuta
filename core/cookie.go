package core

import "time"

const DefaultSessionTokenName = "kuta.session_token"
const DefaultSessionDataName = "kuta.session_data"

type SessionTokenAttributes struct {
	HTTPOnly bool
	Secure   bool
	SameSite string
	Path     string
}

type SessionToken struct {
	Name       string
	Attributes SessionTokenAttributes
}

type SessionDataCookie struct {
	Name        string
	SessionData any // SessionData type, avoiding field/type name conflict
}

// CookieConfig defines how session tokens are stored in cookies
type CookieConfig struct {
	SessionToken      SessionToken
	SessionDataCookie SessionDataCookie
}

// CookieCacheConfig defines behavior for client-side session caching in cookies
type CookieCacheConfig struct {
	Enabled   bool
	MaxAge    time.Duration
	UpdateAge time.Duration
}
