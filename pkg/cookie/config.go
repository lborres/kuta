package cookie

import "github.com/lborres/kuta/core"

// DefaultConfig returns the default cookie configuration
func DefaultConfig() *core.CookieConfig {
	return &core.CookieConfig{
		SessionToken: core.SessionToken{
			Name: core.DefaultSessionTokenName,
			Attributes: core.SessionTokenAttributes{
				HTTPOnly: true,
				Secure:   true,
				SameSite: "lax",
				Path:     "/",
			},
		},
		SessionDataCookie: core.SessionDataCookie{
			Name: core.DefaultSessionDataName,
		},
	}
}
