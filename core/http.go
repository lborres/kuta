package core

import "time"

type HTTPProvider interface {
	RegisterRoutes(handler AuthProvider, basePath string, ttl time.Duration) error
	BuildProtectedMiddleware(authProvider AuthProvider) interface{}
}
