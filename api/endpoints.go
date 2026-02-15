package api

import (
	"net/http"

	"github.com/lborres/kuta/core"
)

// CoreAuthHandlers provides the built-in auth endpoint handlers.
// These are framework-agnostic and work with RequestContext.
type CoreAuthHandlers struct {
	Provider   core.AuthProvider
	SessionCfg *core.SessionConfig
}

// GetCoreEndpoints returns the built-in auth endpoints (signUp, signIn, etc.).
// These are registered automatically by the adapter.
func (h *CoreAuthHandlers) GetCoreEndpoints() []core.PluginEndpoint {
	return []core.PluginEndpoint{
		{
			Path:           "/sign-up",
			Method:         "POST",
			Handler:        h.handleSignUp,
			RequireSession: false,
			Metadata: core.EndpointMetadata{
				OperationID: "signUp",
				Description: "Register a new user account",
			},
		},
		{
			Path:           "/sign-in",
			Method:         "POST",
			Handler:        h.handleSignIn,
			RequireSession: false,
			Metadata: core.EndpointMetadata{
				OperationID: "signIn",
				Description: "Authenticate with email and password",
			},
		},
		{
			Path:           "/sign-out",
			Method:         "POST",
			Handler:        h.handleSignOut,
			RequireSession: true,
			Metadata: core.EndpointMetadata{
				OperationID: "signOut",
				Description: "End the current session",
			},
		},
		{
			Path:           "/session",
			Method:         "GET",
			Handler:        h.handleGetSession,
			RequireSession: true,
			Metadata: core.EndpointMetadata{
				OperationID: "getSession",
				Description: "Get current session information",
			},
		},
		{
			Path:           "/refresh",
			Method:         "POST",
			Handler:        h.handleRefresh,
			RequireSession: true,
			Metadata: core.EndpointMetadata{
				OperationID: "refresh",
				Description: "Refresh session token",
			},
		},
	}
}

func (h *CoreAuthHandlers) handleSignUp(ctx *core.RequestContext) error {
	var input core.SignUpInput
	if err := ctx.Bind(&input); err != nil {
		ctx.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return nil
	}

	result, err := h.Provider.SignUp(input, ctx.IP, ctx.UserAgent)
	if err != nil {
		return err
	}

	// Set session cookie
	if ctx.SetCookies == nil {
		ctx.SetCookies = make(map[string]string)
	}
	ctx.SetCookies[h.getSessionTokenName()] = result.Token

	ctx.Response = map[string]any{
		"user":    result.User,
		"session": result.Session,
		"token":   result.Token,
	}
	ctx.StatusCode = http.StatusCreated
	return nil
}

func (h *CoreAuthHandlers) handleSignIn(ctx *core.RequestContext) error {
	var input core.SignInInput
	if err := ctx.Bind(&input); err != nil {
		ctx.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return nil
	}

	result, err := h.Provider.SignIn(input, ctx.IP, ctx.UserAgent)
	if err != nil {
		return err
	}

	// Set session cookie
	if ctx.SetCookies == nil {
		ctx.SetCookies = make(map[string]string)
	}
	ctx.SetCookies[h.getSessionTokenName()] = result.Token

	ctx.Response = map[string]any{
		"user":    result.User,
		"session": result.Session,
		"token":   result.Token,
	}
	ctx.StatusCode = http.StatusOK
	return nil
}

func (h *CoreAuthHandlers) handleSignOut(ctx *core.RequestContext) error {
	// Session is already validated by RequireSession
	if err := h.Provider.SignOut(ctx.Token); err != nil {
		return err
	}

	// Clear session cookie
	ctx.ClearCookies = append(ctx.ClearCookies, h.getSessionTokenName())

	ctx.Response = map[string]any{
		"message": "signed out successfully",
	}
	ctx.StatusCode = http.StatusOK
	return nil
}

func (h *CoreAuthHandlers) handleGetSession(ctx *core.RequestContext) error {
	// Session is already validated and populated by RequireSession
	ctx.JSON(http.StatusOK, ctx.Session)
	return nil
}

func (h *CoreAuthHandlers) handleRefresh(ctx *core.RequestContext) error {
	result, err := h.Provider.Refresh(ctx.Token)
	if err != nil {
		return err
	}

	// Set refreshed session cookie
	if ctx.SetCookies == nil {
		ctx.SetCookies = make(map[string]string)
	}
	ctx.SetCookies[h.getSessionTokenName()] = result.Token

	ctx.Response = map[string]any{
		"session": result.Session,
		"token":   result.Token,
	}
	ctx.StatusCode = http.StatusOK
	return nil
}

// --- Helpers ---

func (h *CoreAuthHandlers) getSessionTokenName() string {
	if h.SessionCfg != nil && h.SessionCfg.CookieConfig != nil && h.SessionCfg.CookieConfig.SessionToken.Name != "" {
		return h.SessionCfg.CookieConfig.SessionToken.Name
	}
	return core.DefaultSessionTokenName
}

// BaseEndpoints returns framework-agnostic endpoint specifications
// for all core authentication endpoints.
//
// These mirror the endpoints defined in CoreAuthHandlers and are used
// for OpenAPI documentation generation.
func BaseEndpoints() []core.Endpoint {
	// Get endpoints from a zero-value handler (metadata only, no actual execution)
	endpoints := (&CoreAuthHandlers{}).GetCoreEndpoints()

	// Convert PluginEndpoint to Endpoint for OpenAPI documentation
	result := make([]core.Endpoint, 0, len(endpoints))
	for _, pe := range endpoints {
		result = append(result, core.Endpoint{
			Path:     pe.Path,
			Method:   pe.Method,
			Handler:  nil, // Handler is nil for documentation purposes
			Metadata: pe.Metadata,
		})
	}

	return result
}

// EndpointRegistry manages endpoint metadata for documentation purposes.
// This is primarily used for OpenAPI/Swagger generation.
type EndpointRegistry struct {
	endpoints map[string]*core.Endpoint
}

// NewEndpointRegistry creates a registry with base auth endpoints
func NewEndpointRegistry() *EndpointRegistry {
	reg := &EndpointRegistry{
		endpoints: make(map[string]*core.Endpoint),
	}

	for _, ep := range BaseEndpoints() {
		ep := ep
		reg.endpoints[ep.Method+":"+ep.Path] = &ep
	}

	return reg
}

// Endpoints returns all registered endpoints
func (r *EndpointRegistry) Endpoints() []*core.Endpoint {
	result := make([]*core.Endpoint, 0, len(r.endpoints))
	for _, ep := range r.endpoints {
		result = append(result, ep)
	}
	return result
}

// Get returns an endpoint by method and path
func (r *EndpointRegistry) Get(method, path string) *core.Endpoint {
	return r.endpoints[method+":"+path]
}
