package core

type HTTPProvider interface {
	RegisterRoutes(handler AuthProvider, basePath string, sessionConfig *SessionConfig) error
	BuildProtectedMiddleware(authProvider AuthProvider) interface{}
}
