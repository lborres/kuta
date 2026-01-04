package main

import (
	"context"
	"log"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/logger"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/lborres/kuta"
	fiberadapter "github.com/lborres/kuta/adapters/fiber"
	pgxadapter "github.com/lborres/kuta/adapters/pgx"
)

func logFormat() string {
	format := []string{
		// Timestamp & Request ID
		"${time}|${requestid}",

		// Response metadata
		"${status}|${latency}",

		// Client info
		"${ip}:${port}",

		// Transfer size
		"${bytesReceived}|${bytesSent}",

		// Request details
		"${method}|${path}|${queryParams}",

		// Request body
		// WARN: This line exposes sensitive information in the logs.
		// WARN: Remove this in production
		"${reqHeader:Authorization}|${body}",

		// errors
		"${errors}",
	}
	return strings.Join(format, "|") + "\n"
}

func main() {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, "postgres://myuser:mypassword@localhost:5436/kuta?sslmode=disable")
	if err != nil {
		log.Fatalf("pgxpool.New: %v", err)
	}
	defer pool.Close()

	app := fiber.New()

	// Fiber's Register Fiber's built-in Logger
	// for debugging purposes only
	// disregard this block
	app.Use(logger.New(logger.Config{
		Format:     logFormat(),
		TimeFormat: "2006/01/02 15:04:05",
		TimeZone:   "Local",
	}))

	k, err := kuta.New(kuta.Config{
		// WARN: Demonstration purposes only
		// provide your secret in a more secure way such as environment variables
		Secret: "secretshouldbeatleast32charslong",

		Database:      pgxadapter.New(pool),
		HTTP:          fiberadapter.New(app),
		SessionConfig: &kuta.SessionConfig{MaxAge: 24 * time.Hour},
	})
	if err != nil {
		log.Fatalf("could not create kuta instance: %v", err)
	}

	// Protect Endpoints with the kuta middleware
	app.Get("/sensitive", k.Protected, SensitiveDataHandler)

	if err := app.Listen(":8080"); err != nil {
		log.Fatalf("app.Listen: %v", err)
	}
}

// SensitiveDataHandler is an example protected endpoint that retrieves
// user and session information from the context set by the middleware.
func SensitiveDataHandler(c fiber.Ctx) error {
	user := c.Locals("user").(*kuta.User)
	session := c.Locals("session").(*kuta.Session)

	return c.JSON(fiber.Map{
		"message": "Access granted to sensitive data",
		"user":    user,
		"session": session,
	})
}
