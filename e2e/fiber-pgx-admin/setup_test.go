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
	"github.com/lborres/kuta/core"
	"github.com/lborres/kuta/plugins/admin"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

func setupPostgresContainer(t *testing.T, ctx context.Context) (*postgres.PostgresContainer, string) {
	pgContainer, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("kuta_admin_test"),
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

	// Create admin plugin tables
	adminSchema := `
		CREATE TABLE IF NOT EXISTS admin_users (
			user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
			role TEXT NOT NULL DEFAULT 'user',
			banned BOOLEAN NOT NULL DEFAULT false,
			ban_reason TEXT,
			ban_expires_at TIMESTAMPTZ,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);

		CREATE INDEX IF NOT EXISTS idx_admin_users_role ON admin_users(role);
		CREATE INDEX IF NOT EXISTS idx_admin_users_banned ON admin_users(banned);
	`

	if _, err := pool.Exec(ctx, adminSchema); err != nil {
		t.Fatalf("failed to create admin schema: %v", err)
	}

	t.Log("Database schema created successfully")
	return pool
}

func setupE2EServerWithAdmin(t *testing.T) (string, func()) {
	ctx := context.Background()

	pgContainer, connStr := setupPostgresContainer(t, ctx)
	pool := setupDatabase(t, ctx, connStr)

	app := fiber.New()

	// Create admin storage (assuming pgx adapter implements AdminStorageProvider)
	storage := pgxAdapter.New(pool)

	// Create admin plugin with config
	adminPlugin := admin.New(admin.Config{
		DefaultRole:  "user",
		AdminRoles:   []string{"admin"},
		AdminUserIDs: []string{}, // Will set first user as admin in tests
		Roles:        admin.DefaultRoles(),
	})

	auth, err := kuta.New(kuta.Config{
		Secret:   "test-secret-minimum-32-characters-long-for-testing",
		Database: storage,
		HTTP:     fiberAdapter.New(app),
		Plugins:  []core.Plugin{adminPlugin},
	})
	if err != nil {
		t.Fatalf("failed to create kuta instance: %v", err)
	}

	// Protected routes
	api := app.Group("/api")
	api.Use(auth.Protected.(fiber.Handler))
	api.Get("/protected", func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{"message": "protected route"})
	})

	port := 9888
	baseURL := fmt.Sprintf("http://localhost:%d", port)

	go func() {
		if err := app.Listen(fmt.Sprintf(":%d", port)); err != nil {
			t.Logf("Server error: %v", err)
		}
	}()

	// Wait for server to be ready
	time.Sleep(100 * time.Millisecond)

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
