package fiber

import (
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/lborres/kuta"
	"github.com/lborres/kuta/services"
)

type Adapter struct {
	app     *fiber.App
	handler kuta.AuthProvider
}

var _ kuta.HTTPProvider = (*Adapter)(nil)

func New(app *fiber.App) *Adapter {
	return &Adapter{app: app}
}

func (a *Adapter) RegisterRoutes(service kuta.AuthProvider, basePath string, _ time.Duration) error {
	a.handler = service

	// Create endpoint registry with our handler factories
	registry := services.NewEndpointRegistry()

	// Wire handler factories to endpoints
	endpoints := registry.Endpoints()
	for i, endpoint := range endpoints {
		switch endpoint.Metadata.OperationID {
		case "signUpWithEmailAndPassword":
			endpoints[i].Handler = handleSignUpFiber(service)
		case "signInWithEmailAndPassword":
			endpoints[i].Handler = handleSignInFiber(service)
		case "signOut":
			endpoints[i].Handler = handleSignOutFiber(service)
		case "getSession":
			endpoints[i].Handler = handleGetSessionFiber(service)
		case "refreshToken":
			endpoints[i].Handler = handleRefreshFiber(service)
		}
	}

	// Register all endpoints with Fiber
	api := a.app.Group(basePath)

	for _, endpoint := range endpoints {
		if endpoint.Handler == nil {
			continue // Skip endpoints without handlers
		}

		// Convert the framework-agnostic handler to a Fiber handler
		fiberHandler := a.adaptHandler(endpoint)

		// Register based on HTTP method
		switch endpoint.Method {
		case "GET":
			api.Get(endpoint.Path, fiberHandler)
		case "POST":
			api.Post(endpoint.Path, fiberHandler)
		case "PUT":
			api.Put(endpoint.Path, fiberHandler)
		case "DELETE":
			api.Delete(endpoint.Path, fiberHandler)
		case "PATCH":
			api.Patch(endpoint.Path, fiberHandler)
		}
	}

	// Check if handler supports dynamic endpoint registration (plugins)
	if provider, ok := service.(kuta.EndpointProvider); ok {
		// Use dynamic endpoint registration for plugins
		return a.registerDynamicEndpoints(provider, basePath)
	}

	return nil
}

// registerDynamicEndpoints registers endpoints provided by an EndpointProvider
func (a *Adapter) registerDynamicEndpoints(provider kuta.EndpointProvider, basePath string) error {
	api := a.app.Group(basePath)
	endpoints := provider.GetEndpoints()

	for _, endpoint := range endpoints {
		ep := endpoint // capture loop variable
		// Convert the framework-agnostic handler to a Fiber handler
		fiberHandler := a.adaptHandler(&ep)

		// Register based on HTTP method
		switch endpoint.Method {
		case "GET":
			api.Get(endpoint.Path, fiberHandler)
		case "POST":
			api.Post(endpoint.Path, fiberHandler)
		case "PUT":
			api.Put(endpoint.Path, fiberHandler)
		case "DELETE":
			api.Delete(endpoint.Path, fiberHandler)
		case "PATCH":
			api.Patch(endpoint.Path, fiberHandler)
		}
	}

	return nil
}

// adaptHandler converts a framework-agnostic endpoint handler to a Fiber handler
func (a *Adapter) adaptHandler(endpoint *kuta.Endpoint) fiber.Handler {
	return func(c fiber.Ctx) error {
		// Create RequestContext
		ctx := &kuta.RequestContext{
			Request: c,
			Auth:    a.handler,
		}

		// Call the endpoint handler
		if err := endpoint.Handler(ctx); err != nil {
			return err
		}

		return nil
	}
}
