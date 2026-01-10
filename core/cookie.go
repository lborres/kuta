package core

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
	SessionData SessionData
}

// CookieConfig defines how session tokens are stored in cookies
type CookieConfig struct {
	SessionToken      SessionToken
	SessionDataCookie SessionDataCookie
}

func DefaultCookieConfig() *CookieConfig {
	return &CookieConfig{
		SessionToken: SessionToken{
			Name: DefaultSessionTokenName,
			Attributes: SessionTokenAttributes{
				HTTPOnly: true,
				Secure:   true,
				SameSite: "lax",
				Path:     "/",
			},
		},
		SessionDataCookie: SessionDataCookie{
			Name: DefaultSessionDataName,
		},
	}
}
