package core

type HTTPProvider interface {
	// RegisterRoutes registers the core auth endpoints under basePath.
	RegisterRoutes(handler AuthProvider, basePath string, sessionConfig *SessionConfig) error

	// RegisterPluginEndpoints registers a plugin's self-contained endpoints.
	// The adapter wraps each PluginEndpoint handler into a framework-specific
	// route handler, applying authentication when RequireSession is true.
	RegisterPluginEndpoints(basePath string, pluginID string, endpoints []PluginEndpoint) error

	// BuildProtectedMiddleware returns a framework-specific middleware value
	// that validates auth tokens and populates user/session in context.
	BuildProtectedMiddleware(authProvider AuthProvider) any
}
