package fiber

import (
	"net/http"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/lborres/kuta/pkg/ratelimit"
)

// rateLimitMiddleware creates a Fiber middleware that applies rate limiting.
// It uses the client's IP address as the rate limit key.
func (a *Adapter) rateLimitMiddleware(limiter *ratelimit.Limiter) fiber.Handler {
	return func(c fiber.Ctx) error {
		// Use IP address as the rate limit key
		key := c.IP()

		if !limiter.Allow(key) {
			return c.Status(http.StatusTooManyRequests).JSON(fiber.Map{
				"error": "rate limit exceeded",
			})
		}

		return c.Next()
	}
}

// authRateLimitMiddleware creates more restrictive rate limiting for auth endpoints.
// Combines IP + endpoint path for finer-grained control.
func (a *Adapter) authRateLimitMiddleware(limiter *ratelimit.Limiter) fiber.Handler {
	return func(c fiber.Ctx) error {
		// Combine IP and path for endpoint-specific limiting
		key := c.IP() + ":" + c.Path()

		if !limiter.Allow(key) {
			return c.Status(http.StatusTooManyRequests).JSON(fiber.Map{
				"error": "too many authentication attempts",
			})
		}

		return c.Next()
	}
}

// newAuthRateLimiter creates a rate limiter configured for authentication endpoints.
// Defaults to 15 attempts per minute per IP+endpoint combination.
// This allows legitimate use while preventing brute-force attacks (catches ~20 rapid attempts).
func newAuthRateLimiter() *ratelimit.Limiter {
	return ratelimit.New(15, time.Minute)
}
