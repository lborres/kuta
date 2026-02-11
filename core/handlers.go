package core

import "net/http"

// CoreAuthHandlers provides the built-in auth endpoint handlers.
// These are framework-agnostic and work with RequestContext.
type CoreAuthHandlers struct {
	Provider   AuthProvider
	SessionCfg *SessionConfig
}

// CookieAction instructs the adapter to set or clear a cookie after the handler completes.
type CookieAction struct {
	Action string // "set" or "clear"
	Name   string
	Value  string // only for "set"
}

// GetCoreEndpoints returns the built-in auth endpoints (signUp, signIn, etc.).
// These are registered automatically by the adapter.
func (h *CoreAuthHandlers) GetCoreEndpoints() []PluginEndpoint {
	return []PluginEndpoint{
		{
			Path:           "/sign-up",
			Method:         "POST",
			Handler:        h.handleSignUp,
			RequireSession: false,
			Metadata: EndpointMetadata{
				OperationID: "signUp",
				Description: "Register a new user account",
			},
		},
		{
			Path:           "/sign-in",
			Method:         "POST",
			Handler:        h.handleSignIn,
			RequireSession: false,
			Metadata: EndpointMetadata{
				OperationID: "signIn",
				Description: "Authenticate with email and password",
			},
		},
		{
			Path:           "/sign-out",
			Method:         "POST",
			Handler:        h.handleSignOut,
			RequireSession: true,
			Metadata: EndpointMetadata{
				OperationID: "signOut",
				Description: "End the current session",
			},
		},
		{
			Path:           "/session",
			Method:         "GET",
			Handler:        h.handleGetSession,
			RequireSession: true,
			Metadata: EndpointMetadata{
				OperationID: "getSession",
				Description: "Get current session information",
			},
		},
		{
			Path:           "/refresh",
			Method:         "POST",
			Handler:        h.handleRefresh,
			RequireSession: true,
			Metadata: EndpointMetadata{
				OperationID: "refresh",
				Description: "Refresh session token",
			},
		},
	}
}

// --- Handler implementations ---

func (h *CoreAuthHandlers) handleSignUp(ctx *RequestContext) error {
	var input SignUpInput
	if err := ctx.Bind(&input); err != nil {
		ctx.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return nil
	}

	result, err := h.Provider.SignUp(input, ctx.IP, ctx.UserAgent)
	if err != nil {
		return err
	}

	// Instruct adapter to set cookie
	ctx.Response = map[string]any{
		"user":    result.User,
		"session": result.Session,
		"token":   result.Token,
		"_cookieAction": &CookieAction{
			Action: "set",
			Name:   h.getSessionTokenName(),
			Value:  result.Token,
		},
	}
	ctx.StatusCode = http.StatusCreated
	return nil
}

func (h *CoreAuthHandlers) handleSignIn(ctx *RequestContext) error {
	var input SignInInput
	if err := ctx.Bind(&input); err != nil {
		ctx.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return nil
	}

	result, err := h.Provider.SignIn(input, ctx.IP, ctx.UserAgent)
	if err != nil {
		return err
	}

	// Instruct adapter to set cookie
	ctx.Response = map[string]any{
		"user":    result.User,
		"session": result.Session,
		"token":   result.Token,
		"_cookieAction": &CookieAction{
			Action: "set",
			Name:   h.getSessionTokenName(),
			Value:  result.Token,
		},
	}
	ctx.StatusCode = http.StatusOK
	return nil
}

func (h *CoreAuthHandlers) handleSignOut(ctx *RequestContext) error {
	// Session is already validated by RequireSession
	if err := h.Provider.SignOut(ctx.Token); err != nil {
		return err
	}

	// Instruct adapter to clear cookie
	ctx.Response = map[string]any{
		"message": "signed out successfully",
		"_cookieAction": &CookieAction{
			Action: "clear",
			Name:   h.getSessionTokenName(),
		},
	}
	ctx.StatusCode = http.StatusOK
	return nil
}

func (h *CoreAuthHandlers) handleGetSession(ctx *RequestContext) error {
	// Session is already validated and populated by RequireSession
	ctx.JSON(http.StatusOK, ctx.Session)
	return nil
}

func (h *CoreAuthHandlers) handleRefresh(ctx *RequestContext) error {
	result, err := h.Provider.Refresh(ctx.Token)
	if err != nil {
		return err
	}

	// Instruct adapter to set cookie
	ctx.Response = map[string]any{
		"session": result.Session,
		"token":   result.Token,
		"_cookieAction": &CookieAction{
			Action: "set",
			Name:   h.getSessionTokenName(),
			Value:  result.Token,
		},
	}
	ctx.StatusCode = http.StatusOK
	return nil
}

// --- Helpers ---

func (h *CoreAuthHandlers) getSessionTokenName() string {
	if h.SessionCfg != nil && h.SessionCfg.CookieConfig != nil && h.SessionCfg.CookieConfig.SessionToken.Name != "" {
		return h.SessionCfg.CookieConfig.SessionToken.Name
	}
	return DefaultSessionTokenName
}
