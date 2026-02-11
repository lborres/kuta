package fiber

import (
	"net/http"
	"time"

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

// RegisterRoutes registers all core auth endpoints under basePath
func (a *Adapter) RegisterRoutes(provider core.AuthProvider, basePath string, sessionCfg *core.SessionConfig) error {
	a.provider = provider
	a.sessionCfg = sessionCfg

	// Use framework-agnostic core handlers
	coreHandlers := &core.CoreAuthHandlers{
		Provider:   provider,
		SessionCfg: sessionCfg,
	}

	// Register core auth endpoints directly under basePath (no plugin ID prefix)
	group := a.app.Group(basePath)
	endpoints := coreHandlers.GetCoreEndpoints()

	for _, ep := range endpoints {
		handler := a.wrapPluginHandler(ep)

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

// RegisterPluginEndpoints registers a plugin's self-contained endpoints.
// Each PluginEndpoint handler is wrapped into a Fiber handler automatically.
func (a *Adapter) RegisterPluginEndpoints(basePath string, pluginID string, endpoints []core.PluginEndpoint) error {
	prefix := basePath + "/" + pluginID
	group := a.app.Group(prefix)

	for _, ep := range endpoints {
		handler := a.wrapPluginHandler(ep)

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

// wrapPluginHandler converts a framework-agnostic PluginEndpoint into a Fiber handler.
func (a *Adapter) wrapPluginHandler(ep core.PluginEndpoint) fiber.Handler {
	return func(c fiber.Ctx) error {
		rctx := &core.RequestContext{
			IP:          c.IP(),
			UserAgent:   c.Get(fiber.HeaderUserAgent),
			PathParams:  make(map[string]string),
			QueryParams: make(map[string]string),
			Headers:     make(map[string]string),
		}

		// Populate path params from Fiber's route params
		pathParams := make(map[string]string)
		if err := c.Bind().URI(&pathParams); err == nil {
			rctx.PathParams = pathParams
		}

		// Populate query params
		rctx.QueryParams = c.Queries()

		// Populate common headers
		for _, name := range []string{"content-type", "authorization", "x-request-id"} {
			if v := c.Get(name); v != "" {
				rctx.Headers[name] = v
			}
		}

		// Read body
		if ep.Method != "GET" {
			body := c.Body()
			if len(body) > 0 {
				rctx.Body = body
			}
		}

		// Extract token for session-aware endpoints
		token := extractToken(c, a.sessionCfg)
		rctx.Token = token

		// If the endpoint requires a session, authenticate before calling handler
		if ep.RequireSession {
			if token == "" {
				return c.Status(http.StatusUnauthorized).JSON(fiber.Map{
					"error": core.ErrMissingAuthHeader.Error(),
				})
			}
			sessionData, err := a.provider.GetSession(token)
			if err != nil {
				return c.Status(http.StatusUnauthorized).JSON(fiber.Map{
					"error": err.Error(),
				})
			}
			rctx.Session = sessionData
		}

		// Call the plugin handler
		if err := ep.Handler(rctx); err != nil {
			status := mapErrorToStatus(err)
			return c.Status(status).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		// Handle cookie actions if present
		if rctx.Response != nil {
			if respMap, ok := rctx.Response.(map[string]any); ok {
				if cookieAction, exists := respMap["_cookieAction"]; exists {
					if action, ok := cookieAction.(*core.CookieAction); ok {
						if action.Action == "set" {
							a.setAuthCookie(c, action.Name, action.Value)
						} else if action.Action == "clear" {
							a.clearAuthCookie(c, action.Name)
						}
						// Remove _cookieAction from response before sending
						delete(respMap, "_cookieAction")
					}
				}
			}
		}

		// Write response
		status := rctx.StatusCode
		if status == 0 {
			status = http.StatusOK
		}
		if rctx.Response != nil {
			return c.Status(status).JSON(rctx.Response)
		}
		return c.SendStatus(status)
	}
}

// Endpoints returns the endpoint registry for OpenAPI generation
func (a *Adapter) Endpoints() *api.EndpointRegistry {
	return a.registry
}

// setAuthCookie sets the session cookie
func (a *Adapter) setAuthCookie(c fiber.Ctx, name string, token string) {
	if a.sessionCfg == nil || a.sessionCfg.CookieConfig == nil {
		return
	}
	cfg := a.sessionCfg.CookieConfig
	if name == "" {
		return
	}

	c.Cookie(&fiber.Cookie{
		Name:     name,
		Value:    token,
		HTTPOnly: cfg.SessionToken.Attributes.HTTPOnly,
		Secure:   cfg.SessionToken.Attributes.Secure,
		SameSite: cfg.SessionToken.Attributes.SameSite,
		Path:     cfg.SessionToken.Attributes.Path,
		Expires:  time.Now().Add(a.sessionCfg.ExpiresIn),
		MaxAge:   int(a.sessionCfg.ExpiresIn.Seconds()),
	})
}

// clearAuthCookie clears the session cookie
func (a *Adapter) clearAuthCookie(c fiber.Ctx, name string) {
	if a.sessionCfg == nil || a.sessionCfg.CookieConfig == nil {
		return
	}
	cfg := a.sessionCfg.CookieConfig
	if name == "" {
		return
	}

	c.Cookie(&fiber.Cookie{
		Name:     name,
		Value:    "",
		Path:     cfg.SessionToken.Attributes.Path,
		Expires:  time.Now().Add(-time.Hour),
		MaxAge:   -1,
		HTTPOnly: cfg.SessionToken.Attributes.HTTPOnly,
		Secure:   cfg.SessionToken.Attributes.Secure,
		SameSite: cfg.SessionToken.Attributes.SameSite,
	})
}

// extractToken extracts auth token from Authorization header or cookie
func extractToken(c fiber.Ctx, sessionCfg *core.SessionConfig) string {
	// Try Bearer token first
	authHeader := c.Get(fiber.HeaderAuthorization)
	if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
		return authHeader[7:]
	}

	// Fall back to cookie
	name := core.DefaultSessionTokenName
	if sessionCfg != nil && sessionCfg.CookieConfig != nil && sessionCfg.CookieConfig.SessionToken.Name != "" {
		name = sessionCfg.CookieConfig.SessionToken.Name
	}
	return c.Cookies(name)
}

// mapErrorToStatus converts domain errors to HTTP status codes
func mapErrorToStatus(err error) int {
	if err == nil {
		return http.StatusOK
	}

	switch err {
	case core.ErrInvalidCredentials,
		core.ErrUserNotFound,
		core.ErrInvalidToken,
		core.ErrSessionNotFound,
		core.ErrSessionExpired:
		return http.StatusUnauthorized

	case core.ErrEmailRequired,
		core.ErrPasswordRequired,
		core.ErrPasswordTooShort,
		core.ErrPasswordTooLong,
		core.ErrPasswordComplexity,
		core.ErrInvalidEmail:
		return http.StatusBadRequest

	case core.ErrUserExists:
		return http.StatusConflict

	default:
		return http.StatusInternalServerError
	}
}
