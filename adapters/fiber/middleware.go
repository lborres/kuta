package fiber

import (
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/lborres/kuta"
)

func (a *Adapter) requireAuth(ctx fiber.Ctx) error {
	authHeader := ctx.Get("Authorization")

	if authHeader == "" {
		return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": kuta.ErrMissingAuthHeader,
		})
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")
	if token == authHeader || token == "" {
		return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": kuta.ErrInvalidAuthHeader,
		})
	}

	// 3. TODO: Validate token and get user session
	// Example:
	// session, err := authService.ValidateToken(ctx.Context(), token)
	// if err != nil {
	//     return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
	//         "error": "invalid or expired token",
	//     })
	// }

	// 4. Store user info in context for downstream handlers
	// ctx.Locals("userId", session.UserID)
	// ctx.Locals("session", session)

	return ctx.Next()
}
