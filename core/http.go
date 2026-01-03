package core

import "time"

type HTTPAdapter interface {
	RegisterRoutes(handler AuthService, basePath string, ttl time.Duration) error
}
