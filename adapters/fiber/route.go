package fiber

import (
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/lborres/kuta"
)

type Adapter struct {
	app     *fiber.App
	handler kuta.AuthHandler
}

var _ kuta.HTTPAdapter = (*Adapter)(nil)

func New(app *fiber.App) *Adapter {
	return &Adapter{app: app}
}

func (a *Adapter) RegisterRoutes(handler kuta.AuthHandler, basePath string, _ time.Duration) error {
	a.handler = handler
	api := a.app.Group(basePath)

	// Public routes
	api.Post("/sign-up", a.signup)
	api.Post("/sign-in", a.signin)

	// Protected routes
	api.Post("/sign-out", a.requireAuth, a.signout)
	api.Get("/session", a.requireAuth, a.session)

	return nil
}
