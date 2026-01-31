package fiber

import (
	"github.com/gofiber/fiber/v3"
	"github.com/lborres/kuta/api"
	"github.com/lborres/kuta/core"
)

// Adapter integrates kuta authentication with Fiber
type Adapter struct {
	app        *fiber.App
	provider   core.AuthProvider
	sessionCfg *core.SessionConfig
	registry   *api.EndpointRegistry
}

var _ core.HTTPProvider = (*Adapter)(nil)

// New creates a Fiber adapter
func New(app *fiber.App) *Adapter {
	return &Adapter{
		app:      app,
		registry: api.NewEndpointRegistry(),
	}
}

// RegisterRoutes registers all auth endpoints under basePath
func (a *Adapter) RegisterRoutes(provider core.AuthProvider, basePath string, sessionCfg *core.SessionConfig) error {
	a.provider = provider
	a.sessionCfg = sessionCfg

	h := &authHandlers{provider: provider, sessionCfg: sessionCfg}
	group := a.app.Group(basePath)

	// Map handlers to endpoints from registry
	handlers := map[string]fiber.Handler{
		"POST:/sign-up":  h.signUp,
		"POST:/sign-in":  h.signIn,
		"POST:/sign-out": h.signOut,
		"GET:/session":   h.getSession,
		"POST:/refresh":  h.refresh,
	}

	// Register routes from registry
	for _, ep := range a.registry.Endpoints() {
		key := ep.Method + ":" + ep.Path
		handler, ok := handlers[key]
		if !ok {
			continue
		}

		switch ep.Method {
		case "GET":
			group.Get(ep.Path, handler)
		case "POST":
			group.Post(ep.Path, handler)
		case "PUT":
			group.Put(ep.Path, handler)
		case "DELETE":
			group.Delete(ep.Path, handler)
		case "PATCH":
			group.Patch(ep.Path, handler)
		}
	}

	return nil
}

// Endpoints returns the endpoint registry for OpenAPI generation
func (a *Adapter) Endpoints() *api.EndpointRegistry {
	return a.registry
}
