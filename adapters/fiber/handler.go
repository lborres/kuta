package fiber

import (
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/lborres/kuta/core"
)

var (
	cookieConfig  *core.CookieConfig
	sessionConfig *core.SessionConfig
)

func setAuthCookie(fctx fiber.Ctx, cookiConfig *core.CookieConfig, sessionConfig *core.SessionConfig, token string) {
	if cookiConfig == nil || cookiConfig.SessionToken.Name == "" {
		return
	}

	expireTime := time.Now().Add(sessionConfig.ExpiresIn)
	maxAge := int(sessionConfig.ExpiresIn.Seconds())

	cookie := &fiber.Cookie{
		Name:     cookiConfig.SessionToken.Name,
		Value:    token,
		HTTPOnly: cookiConfig.SessionToken.Attributes.HTTPOnly,
		Secure:   cookiConfig.SessionToken.Attributes.Secure,
		SameSite: cookiConfig.SessionToken.Attributes.SameSite,
		Path:     cookiConfig.SessionToken.Attributes.Path,
		Expires:  expireTime,
		MaxAge:   maxAge,
	}

	fctx.Cookie(cookie)
}

func clearAuthCookie(fctx fiber.Ctx, cookiConfig *core.CookieConfig) {
	if cookiConfig == nil || cookiConfig.SessionToken.Name == "" {
		return
	}

	c := &fiber.Cookie{
		Name:     cookiConfig.SessionToken.Name,
		Value:    "",
		Path:     cookiConfig.SessionToken.Attributes.Path,
		Expires:  time.Now().Add(-1 * time.Hour),
		MaxAge:   -1,
		HTTPOnly: cookiConfig.SessionToken.Attributes.HTTPOnly,
		Secure:   cookiConfig.SessionToken.Attributes.Secure,
		SameSite: cookiConfig.SessionToken.Attributes.SameSite,
	}
	fctx.Cookie(c)
}

// handleSignUpFiber returns a handler for the sign-up endpoint
func handleSignUpFiber(authProvider core.AuthProvider) func(*core.RequestContext) error {
	return func(ctx *core.RequestContext) error {
		fctx := ctx.Request.(fiber.Ctx)

		var input core.SignUpInput
		if err := fctx.Bind().Body(&input); err != nil {
			return fctx.Status(http.StatusBadRequest).JSON(map[string]string{
				"error": "invalid request body",
			})
		}

		ipAddress := fctx.IP()
		userAgent := fctx.Get(fiber.HeaderUserAgent)

		result, err := authProvider.SignUp(input, ipAddress, userAgent)
		if err != nil {
			return handleAuthError(fctx, err)
		}

		if cookieConfig != nil && sessionConfig != nil {
			setAuthCookie(fctx, cookieConfig, sessionConfig, result.Token)
		}

		return fctx.Status(http.StatusCreated).JSON(result)
	}
}

// handleSignInFiber returns a handler for the sign-in endpoint
func handleSignInFiber(authProvider core.AuthProvider) func(*core.RequestContext) error {
	return func(ctx *core.RequestContext) error {
		fctx := ctx.Request.(fiber.Ctx)

		var input core.SignInInput
		if err := fctx.Bind().Body(&input); err != nil {
			return fctx.Status(http.StatusBadRequest).JSON(map[string]string{
				"error": "invalid request body",
			})
		}

		result, err := authProvider.SignIn(input, fctx.IP(), fctx.Get(fiber.HeaderUserAgent))
		if err != nil {
			return handleAuthError(fctx, err)
		}

		if cookieConfig != nil && sessionConfig != nil {
			log.Println("set cookie")
			setAuthCookie(fctx, cookieConfig, sessionConfig, result.Token)
		}

		return fctx.Status(http.StatusOK).JSON(result)
	}
}

// handleSignOutFiber returns a handler for the sign-out endpoint
func handleSignOutFiber(authProvider core.AuthProvider) func(*core.RequestContext) error {
	return func(ctx *core.RequestContext) error {
		fctx := ctx.Request.(fiber.Ctx)

		token := extractToken(fctx)
		if token == "" {
			return fctx.Status(http.StatusUnauthorized).JSON(map[string]string{
				"error": "missing token",
			})
		}

		if err := authProvider.SignOut(token); err != nil {
			return handleAuthError(fctx, err)
		}

		if cookieConfig != nil {
			clearAuthCookie(fctx, cookieConfig)
		}

		return fctx.Status(http.StatusOK).JSON(map[string]string{
			"message": "signed out successfully",
		})
	}
}

// handleGetSessionFiber returns a handler for the get-session endpoint
func handleGetSessionFiber(authProvider core.AuthProvider) func(*core.RequestContext) error {
	return func(ctx *core.RequestContext) error {
		fctx := ctx.Request.(fiber.Ctx)

		token := extractToken(fctx)
		if token == "" {
			return fctx.Status(http.StatusUnauthorized).JSON(map[string]string{
				"error": "missing token",
			})
		}

		session, err := authProvider.GetSession(token)
		if err != nil {
			return handleAuthError(fctx, err)
		}

		return fctx.Status(http.StatusOK).JSON(session)
	}
}

// handleRefreshFiber returns a handler for the refresh endpoint
func handleRefreshFiber(authProvider core.AuthProvider) func(*core.RequestContext) error {
	return func(ctx *core.RequestContext) error {
		fctx := ctx.Request.(fiber.Ctx)

		token := extractToken(fctx)
		if token == "" {
			return fctx.Status(http.StatusUnauthorized).JSON(map[string]string{
				"error": "missing token",
			})
		}

		result, err := authProvider.Refresh(token)
		if err != nil {
			return handleAuthError(fctx, err)
		}

		if cookieConfig != nil && sessionConfig != nil {
			setAuthCookie(fctx, cookieConfig, sessionConfig, result.Token)
		}

		return fctx.Status(http.StatusOK).JSON(result)
	}
}

// extractToken extracts the authentication token from the request.
// Checks Authorization header (Bearer token) first, then falls back to cookie.
func extractToken(c fiber.Ctx) string {
	// Try Bearer token first
	authHeader := c.Get(fiber.HeaderAuthorization)
	if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
		return authHeader[7:]
	}

	// Fall back to configured cookie name or default
	name := core.DefaultSessionTokenName
	if cookieConfig != nil && cookieConfig.SessionToken.Name != "" {
		name = cookieConfig.SessionToken.Name
	}

	// Fall back to cookie
	return c.Cookies(name)
}

// handleAuthError maps authentication errors to appropriate HTTP responses
func handleAuthError(c fiber.Ctx, err error) error {
	status := mapErrorToStatus(err)
	return c.Status(status).JSON(map[string]string{
		"error": err.Error(),
	})
}

// mapErrorToStatus maps kuta error types to HTTP status codes
func mapErrorToStatus(err error) int {
	if err == nil {
		return http.StatusOK
	}

	switch {
	case errors.Is(err, core.ErrInvalidCredentials),
		errors.Is(err, core.ErrUserNotFound),
		errors.Is(err, core.ErrInvalidToken),
		errors.Is(err, core.ErrSessionNotFound),
		errors.Is(err, core.ErrSessionExpired):
		return http.StatusUnauthorized

	case errors.Is(err, core.ErrEmailRequired),
		errors.Is(err, core.ErrPasswordRequired),
		errors.Is(err, core.ErrPasswordTooShort),
		errors.Is(err, core.ErrPasswordTooLong),
		errors.Is(err, core.ErrInvalidEmail):
		return http.StatusBadRequest

	default:
		return http.StatusInternalServerError
	}
}
