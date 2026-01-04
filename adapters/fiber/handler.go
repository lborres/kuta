package fiber

import (
	"errors"
	"net/http"

	"github.com/gofiber/fiber/v3"
	"github.com/lborres/kuta"
)

// handleSignUpFiber returns a handler for the sign-up endpoint
func handleSignUpFiber(authProvider kuta.AuthProvider) func(*kuta.RequestContext) error {
	return func(ctx *kuta.RequestContext) error {
		fctx := ctx.Request.(fiber.Ctx)

		var input kuta.SignUpInput
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
func handleSignInFiber(authProvider kuta.AuthProvider) func(*kuta.RequestContext) error {
	return func(ctx *kuta.RequestContext) error {
		fctx := ctx.Request.(fiber.Ctx)

		var input kuta.SignInInput
		if err := fctx.Bind().Body(&input); err != nil {
			return fctx.Status(http.StatusBadRequest).JSON(map[string]string{
				"error": "invalid request body",
			})
		}

		ipAddress := fctx.IP()
		userAgent := fctx.Get(fiber.HeaderUserAgent)

		result, err := authProvider.SignIn(input, ipAddress, userAgent)
		if err != nil {
			return handleAuthError(fctx, err)
		}

		return fctx.Status(http.StatusOK).JSON(result)
	}
}

// handleSignOutFiber returns a handler for the sign-out endpoint
func handleSignOutFiber(authProvider kuta.AuthProvider) func(*kuta.RequestContext) error {
	return func(ctx *kuta.RequestContext) error {
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
func handleGetSessionFiber(authProvider kuta.AuthProvider) func(*kuta.RequestContext) error {
	return func(ctx *kuta.RequestContext) error {
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
func handleRefreshFiber(authProvider kuta.AuthProvider) func(*kuta.RequestContext) error {
	return func(ctx *kuta.RequestContext) error {
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
	case errors.Is(err, kuta.ErrInvalidCredentials),
		errors.Is(err, kuta.ErrUserNotFound),
		errors.Is(err, kuta.ErrInvalidToken),
		errors.Is(err, kuta.ErrSessionExpired):
		return http.StatusUnauthorized

	case errors.Is(err, kuta.ErrEmailRequired),
		errors.Is(err, kuta.ErrPasswordRequired),
		errors.Is(err, kuta.ErrPasswordTooShort),
		errors.Is(err, kuta.ErrPasswordTooLong),
		errors.Is(err, kuta.ErrInvalidEmail):
		return http.StatusBadRequest

	default:
		return http.StatusInternalServerError
	}
}
