package fiber

import (
	"github.com/gofiber/fiber/v3"
	"github.com/lborres/kuta"
)

// BuildProtectedMiddleware creates a Fiber middleware that validates auth tokens
// and stores user/session data in the context for downstream handlers.
func (a *Adapter) BuildProtectedMiddleware(authProvider kuta.AuthProvider) interface{} {
	return func(c fiber.Ctx) error {
		// Extract and validate token from Authorization header
		token := extractToken(c)
		if token == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": kuta.ErrMissingAuthHeader.Error(),
			})
		}

		// Validate token and retrieve session data
		sessionData, err := authProvider.GetSession(token)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		// Store user and session in context for downstream handlers
		c.Locals("user", sessionData.User)
		c.Locals("session", sessionData.Session)

		return c.Next()
	}
}
