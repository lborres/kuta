package fiber

import (
	"net/http"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/lborres/kuta/core"
)

// authHandlers holds dependencies for auth endpoint handlers
type authHandlers struct {
	provider   core.AuthProvider
	sessionCfg *core.SessionConfig
}

func (h *authHandlers) cookieCfg() *core.CookieConfig {
	if h.sessionCfg == nil {
		return nil
	}
	return h.sessionCfg.CookieConfig
}

func (h *authHandlers) signUp(c fiber.Ctx) error {
	var input core.SignUpInput
	if err := c.Bind().Body(&input); err != nil {
		return c.Status(http.StatusBadRequest).JSON(map[string]string{
			"error": "invalid request body",
		})
	}

	result, err := h.provider.SignUp(input, c.IP(), c.Get(fiber.HeaderUserAgent))
	if err != nil {
		return h.authError(c, err)
	}

	h.setAuthCookie(c, result.Token)
	return c.Status(http.StatusCreated).JSON(result)
}

func (h *authHandlers) signIn(c fiber.Ctx) error {
	var input core.SignInInput
	if err := c.Bind().Body(&input); err != nil {
		return c.Status(http.StatusBadRequest).JSON(map[string]string{
			"error": "invalid request body",
		})
	}

	result, err := h.provider.SignIn(input, c.IP(), c.Get(fiber.HeaderUserAgent))
	if err != nil {
		return h.authError(c, err)
	}

	h.setAuthCookie(c, result.Token)
	return c.Status(http.StatusOK).JSON(result)
}

func (h *authHandlers) signOut(c fiber.Ctx) error {
	token := h.extractToken(c)
	if token == "" {
		return c.Status(http.StatusUnauthorized).JSON(map[string]string{
			"error": "missing token",
		})
	}

	if err := h.provider.SignOut(token); err != nil {
		return h.authError(c, err)
	}

	h.clearAuthCookie(c)
	return c.Status(http.StatusOK).JSON(map[string]string{
		"message": "signed out successfully",
	})
}

func (h *authHandlers) getSession(c fiber.Ctx) error {
	token := h.extractToken(c)
	if token == "" {
		return c.Status(http.StatusUnauthorized).JSON(map[string]string{
			"error": "missing token",
		})
	}

	session, err := h.provider.GetSession(token)
	if err != nil {
		return h.authError(c, err)
	}

	return c.Status(http.StatusOK).JSON(session)
}

func (h *authHandlers) refresh(c fiber.Ctx) error {
	token := h.extractToken(c)
	if token == "" {
		return c.Status(http.StatusUnauthorized).JSON(map[string]string{
			"error": "missing token",
		})
	}

	result, err := h.provider.Refresh(token)
	if err != nil {
		return h.authError(c, err)
	}

	h.setAuthCookie(c, result.Token)
	return c.Status(http.StatusOK).JSON(result)
}

// --- Helper methods ---

func (h *authHandlers) extractToken(c fiber.Ctx) string {
	return extractToken(c, h.sessionCfg)
}

func (h *authHandlers) authError(c fiber.Ctx, err error) error {
	status := mapErrorToStatus(err)
	return c.Status(status).JSON(map[string]string{
		"error": err.Error(),
	})
}

func (h *authHandlers) setAuthCookie(c fiber.Ctx, token string) {
	cfg := h.cookieCfg()
	if cfg == nil || cfg.SessionToken.Name == "" || h.sessionCfg == nil {
		return
	}

	c.Cookie(&fiber.Cookie{
		Name:     cfg.SessionToken.Name,
		Value:    token,
		HTTPOnly: cfg.SessionToken.Attributes.HTTPOnly,
		Secure:   cfg.SessionToken.Attributes.Secure,
		SameSite: cfg.SessionToken.Attributes.SameSite,
		Path:     cfg.SessionToken.Attributes.Path,
		Expires:  time.Now().Add(h.sessionCfg.ExpiresIn),
		MaxAge:   int(h.sessionCfg.ExpiresIn.Seconds()),
	})
}

func (h *authHandlers) clearAuthCookie(c fiber.Ctx) {
	cfg := h.cookieCfg()
	if cfg == nil || cfg.SessionToken.Name == "" {
		return
	}

	c.Cookie(&fiber.Cookie{
		Name:     cfg.SessionToken.Name,
		Value:    "",
		Path:     cfg.SessionToken.Attributes.Path,
		Expires:  time.Now().Add(-time.Hour),
		MaxAge:   -1,
		HTTPOnly: cfg.SessionToken.Attributes.HTTPOnly,
		Secure:   cfg.SessionToken.Attributes.Secure,
		SameSite: cfg.SessionToken.Attributes.SameSite,
	})
}

// --- Package-level helpers ---

// extractToken extracts auth token from Authorization header or cookie
func extractToken(c fiber.Ctx, sessionCfg *core.SessionConfig) string {
	// Try Bearer token first
	authHeader := c.Get(fiber.HeaderAuthorization)
	if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
		return authHeader[7:]
	}

	// Fall back to cookie
	name := core.DefaultSessionTokenName
	if sessionCfg != nil && sessionCfg.CookieConfig != nil && sessionCfg.CookieConfig.SessionToken.Name != "" {
		name = sessionCfg.CookieConfig.SessionToken.Name
	}
	return c.Cookies(name)
}

// mapErrorToStatus converts domain errors to HTTP status codes
func mapErrorToStatus(err error) int {
	if err == nil {
		return http.StatusOK
	}

	switch err {
	case core.ErrInvalidCredentials,
		core.ErrUserNotFound,
		core.ErrInvalidToken,
		core.ErrSessionNotFound,
		core.ErrSessionExpired:
		return http.StatusUnauthorized

	case core.ErrEmailRequired,
		core.ErrPasswordRequired,
		core.ErrPasswordTooShort,
		core.ErrPasswordTooLong,
		core.ErrPasswordComplexity,
		core.ErrInvalidEmail:
		return http.StatusBadRequest

	case core.ErrUserExists:
		return http.StatusConflict

	default:
		return http.StatusInternalServerError
	}
}
