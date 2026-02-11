package main

import (
	"context"
	"log"
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/logger"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/lborres/kuta"
	fiberadapter "github.com/lborres/kuta/adapters/fiber"
	pgxadapter "github.com/lborres/kuta/adapters/pgx"
	"github.com/lborres/kuta/core"
	"github.com/lborres/kuta/plugins/admin"
)

func logFormat() string {
	format := []string{
		"${time}|${requestid}",
		"${status}|${latency}",
		"${ip}:${port}",
		"${bytesReceived}|${bytesSent}",
		"${method}|${path}|${queryParams}",
		"${reqHeader:Authorization}|${body}",
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

	app.Use(logger.New(logger.Config{
		Format:     logFormat(),
		TimeFormat: "2006/01/02 15:04:05",
		TimeZone:   "Local",
	}))

	// Configure admin plugin
	adminConfig := admin.DefaultConfig()
	adminConfig.AdminUserIDs = []string{"admin-user-id"} // Optional: specific user IDs with admin access

	k, err := kuta.New(kuta.Config{
		Secret:   "secretshouldbeatleast32charslong",
		Database: pgxadapter.New(pool),
		HTTP:     fiberadapter.New(app),
		Plugins: []core.Plugin{
			admin.New(adminConfig),
		},
	})
	if err != nil {
		log.Fatalf("could not create kuta instance: %v", err)
	}

	// Protected user endpoint
	app.Get("/profile", k.Protected, ProfileHandler)

	// Admin-only endpoint example
	app.Get("/admin/dashboard", k.Protected, AdminOnlyMiddleware, AdminDashboardHandler)

	log.Println("Server starting on :8080")
	log.Println("Try these endpoints:")
	log.Println("  POST /api/auth/sign-up     - Create account")
	log.Println("  POST /api/auth/sign-in     - Sign in")
	log.Println("  GET  /profile              - User profile (requires auth)")
	log.Println("  GET  /admin/dashboard      - Admin dashboard (requires admin role)")
	log.Println("")
	log.Println("Admin endpoints are automatically registered:")
	log.Println("  POST /api/auth/admin/set-role")
	log.Println("  POST /api/auth/admin/create-user")
	log.Println("  GET  /api/auth/admin/list-users")
	log.Println("  POST /api/auth/admin/ban-user")
	log.Println("  POST /api/auth/admin/unban-user")

	if err := app.Listen(":8080"); err != nil {
		log.Fatalf("app.Listen: %v", err)
	}
}

func ProfileHandler(c fiber.Ctx) error {
	user := c.Locals("user").(*kuta.User)
	session := c.Locals("session").(*kuta.Session)

	return c.JSON(fiber.Map{
		"message": "User profile",
		"user":    user,
		"session": session,
	})
}

// AdminOnlyMiddleware checks if the authenticated user has admin role
func AdminOnlyMiddleware(c fiber.Ctx) error {
	user := c.Locals("user")
	if user == nil {
		return c.Status(401).JSON(fiber.Map{"error": "Unauthorized"})
	}

	// In a real implementation, you'd check the user's role from the database
	// For now, this is just a placeholder showing the pattern
	// The admin plugin will handle role checking in its own endpoints

	return c.Next()
}

func AdminDashboardHandler(c fiber.Ctx) error {
	user := c.Locals("user").(*kuta.User)

	return c.JSON(fiber.Map{
		"message": "Admin dashboard",
		"user":    user,
		"note":    "This endpoint requires admin privileges",
	})
}
