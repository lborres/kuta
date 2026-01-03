package core

// EndpointProvider provides a list of endpoints to register dynamically
type EndpointProvider interface {
	GetEndpoints() []Endpoint
}

type Endpoint struct {
	Path     string
	Method   string
	Handler  func(ctx *RequestContext) error
	Metadata EndpointMetadata
}

type EndpointMetadata struct {
	OperationID string
	Description string
	RequestBody interface{} // for validation
	Responses   map[int]interface{}
}

type RequestContext struct {
	// Framework-agnostic context
	Request interface{} // could be *http.Request, fiber.Ctx, etc
	Auth    AuthService
	Session *Session
	DB      AuthStorage
}

// ErrorResponse represents an error response structure
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
	Code    int    `json:"code,omitempty"`
}
