package fiber

import (
	"errors"
	"net/http"

	"github.com/gofiber/fiber/v3"
	"github.com/lborres/kuta/core"
)

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

	// Fall back to cookie
	return c.Cookies("auth_token")
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
