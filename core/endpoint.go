package core

import "encoding/json"

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
	RequestBody any // for validation
	Responses   map[int]any
}

// RequestContext is a framework-agnostic context for plugin endpoint handlers.
// HTTP adapters populate this before calling the plugin handler, and read
// the result fields after the handler returns.
type RequestContext struct {
	// --- Input (set by adapter before calling handler) ---

	// Body is the raw JSON request body.
	Body json.RawMessage

	// Session is the authenticated session data (nil if unauthenticated).
	Session *SessionData

	// Token is the raw session token extracted from Authorization header or cookie.
	Token string

	// PathParams holds named path parameters (e.g. {"userId": "abc123"}).
	PathParams map[string]string

	// QueryParams holds query string parameters.
	QueryParams map[string]string

	// Headers provides access to request headers (lowercase keys).
	Headers map[string]string

	// IP is the client's IP address.
	IP string

	// UserAgent is the client's User-Agent string.
	UserAgent string

	// --- Output (set by handler, read by adapter after handler returns) ---

	// StatusCode is the HTTP status to send. 0 defaults to 200.
	StatusCode int

	// Response is the value to serialize as the JSON response body.
	Response any
}

// Bind decodes the JSON body into the target struct.
func (ctx *RequestContext) Bind(target any) error {
	if ctx.Body == nil {
		return ErrInvalidRequestBody
	}
	return json.Unmarshal(ctx.Body, target)
}

// JSON sets the response status code and body.
func (ctx *RequestContext) JSON(status int, body any) {
	ctx.StatusCode = status
	ctx.Response = body
}

// PluginEndpoint defines a single HTTP endpoint contributed by a plugin.
// The handler receives a fully populated RequestContext and writes its
// response to the same context. Middleware booleans control what the
// HTTP adapter should do before invoking the handler.
type PluginEndpoint struct {
	// Path is the route path relative to the plugin's namespace.
	// Example: "/set-role" — the adapter prepends basePath + "/admin".
	Path   string
	Method string // "GET", "POST", "PUT", "PATCH", "DELETE"

	// Handler is the framework-agnostic handler function.
	Handler func(ctx *RequestContext) error

	// RequireSession indicates the adapter must authenticate the request
	// and populate ctx.Session before calling Handler. If the request is
	// unauthenticated the adapter should return 401 without calling Handler.
	RequireSession bool

	// Metadata for OpenAPI generation.
	Metadata EndpointMetadata
}

// ErrorResponse represents an error response structure
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
	Code    int    `json:"code,omitempty"`
}
