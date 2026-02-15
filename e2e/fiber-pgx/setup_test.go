package e2e

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/lborres/kuta"
	fiberAdapter "github.com/lborres/kuta/adapters/fiber"
	pgxAdapter "github.com/lborres/kuta/adapters/pgx"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

func setupPostgresContainer(t *testing.T, ctx context.Context) (*postgres.PostgresContainer, string) {
	// Create PostgreSQL container with testcontainers
	pgContainer, err := postgres.Run(ctx,
		"postgres:16-alpine", // Docker image
		postgres.WithDatabase("kuta_test"),
		postgres.WithUsername("test"),
		postgres.WithPassword("test"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(60*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("failed to start postgres container: %v", err)
	}

	// Get connection string from container
	connStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("failed to get connection string: %v", err)
	}

	t.Logf("PostgreSQL container started: %s", connStr)
	return pgContainer, connStr
}

func setupDatabase(t *testing.T, ctx context.Context, connStr string) *pgxpool.Pool {
	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		t.Fatalf("failed to connect to database: %v", err)
	}

	migrationsDir := filepath.Join("../../migrations/postgres")
	files := []string{
		"25123001_define_nanoid.up.sql",
		"25123002_create_auth_tables.up.sql",
	}

	for _, file := range files {
		path := filepath.Join(migrationsDir, file)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("failed to read migration %s: %v", path, err)
		}

		if _, err := pool.Exec(ctx, string(data)); err != nil {
			t.Fatalf("failed to execute migration %s: %v", file, err)
		}
	}

	t.Log("Database schema created successfully from migrations")
	return pool
}

func setupE2EServer(t *testing.T) (string, func()) {
	ctx := context.Background()

	pgContainer, connStr := setupPostgresContainer(t, ctx)

	pool := setupDatabase(t, ctx, connStr)

	app := fiber.New()

	auth, err := kuta.New(kuta.Config{
		Secret:   "test-secret-minimum-32-characters-long-for-testing",
		Database: pgxAdapter.New(pool),
		HTTP:     fiberAdapter.New(app),
	})
	if err != nil {
		t.Fatalf("failed to create kuta instance: %v", err)
	}

	api := app.Group("/api")

	// Protected routes - using kuta.Protected middleware
	api.Use(auth.Protected.(fiber.Handler))
	api.Get("/protected", func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{"message": "protected route"})
	})

	port := 9877
	baseURL := fmt.Sprintf("http://localhost:%d", port)

	go func() {
		if err := app.Listen(fmt.Sprintf(":%d", port)); err != nil {
			t.Logf("Server error: %v", err)
		}
	}()

	// Return cleanup function
	cleanup := func() {
		app.Shutdown()
		pool.Close()
		if err := pgContainer.Terminate(ctx); err != nil {
			t.Logf("Failed to terminate container: %v", err)
		}
		t.Log("Test environment cleaned up")
	}

	return baseURL, cleanup
}
