package main

import (
	"context"
	"log"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/lborres/kuta"
	fiberadapter "github.com/lborres/kuta/adapters/fiber"
	pgxadapter "github.com/lborres/kuta/adapters/pgx"
)

func main() {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, "postgres://postgres:postgres@localhost:5432/kuta_test?sslmode=disable")
	if err != nil {
		log.Fatalf("pgxpool.New: %v", err)
	}
	defer pool.Close()

	app := fiber.New()

	_, err = kuta.New(kuta.Config{
		Secret:        "mysupersecretsecret", // Provide this with env variables
		Database:      pgxadapter.New(pool),
		HTTP:          fiberadapter.New(app),
		SessionConfig: &kuta.SessionConfig{MaxAge: 24 * time.Hour},
	})
	if err != nil {
		log.Fatalf("could not create kuta instance: %v", err)
	}

	if err := app.Listen(":8080"); err != nil {
		log.Fatalf("app.Listen: %v", err)
	}
}
