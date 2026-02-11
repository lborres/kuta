package fiber

import (
	"github.com/gofiber/fiber/v3"
	"github.com/lborres/kuta/core"
)

// BuildProtectedMiddleware creates a Fiber middleware that validates auth tokens
// and stores user/session data in the context for downstream handlers
func (a *Adapter) BuildProtectedMiddleware(authProvider core.AuthProvider) any {
	return func(c fiber.Ctx) error {
		token := extractToken(c, a.sessionCfg)
		if token == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": core.ErrMissingAuthHeader.Error(),
			})
		}

		sessionData, err := authProvider.GetSession(token)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		c.Locals("user", sessionData.User)
		c.Locals("session", sessionData.Session)

		return c.Next()
	}
}
