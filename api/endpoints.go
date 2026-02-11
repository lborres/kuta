package api

import (
	"github.com/lborres/kuta/core"
)

// BaseEndpoints returns framework-agnostic endpoint specifications
// for all core authentication endpoints.
//
// Each endpoint is a template with metadata for OpenAPI documentation.
// Handlers are nil - they are provided by framework adapters.
func BaseEndpoints() []core.Endpoint {
	return []core.Endpoint{
		{
			Path:   "/sign-up",
			Method: "POST",
			Metadata: core.EndpointMetadata{
				OperationID: "signUpWithEmailAndPassword",
				Description: "Sign up a user using email and password",
				RequestBody: core.SignUpInput{},
				Responses: map[int]any{
					201: core.SignUpResult{},
					400: core.ErrorResponse{},
					409: core.ErrorResponse{},
				},
			},
		},
		{
			Path:   "/sign-in",
			Method: "POST",
			Metadata: core.EndpointMetadata{
				OperationID: "signInWithEmailAndPassword",
				Description: "Sign in a user using email and password",
				RequestBody: core.SignInInput{},
				Responses: map[int]any{
					200: core.SignInResult{},
					400: core.ErrorResponse{},
					401: core.ErrorResponse{},
				},
			},
		},
		{
			Path:   "/sign-out",
			Method: "POST",
			Metadata: core.EndpointMetadata{
				OperationID: "signOut",
				Description: "Sign out the current user and invalidate the session",
				Responses: map[int]any{
					200: map[string]string{"message": "signed out successfully"},
					401: core.ErrorResponse{},
				},
			},
		},
		{
			Path:   "/session",
			Method: "GET",
			Metadata: core.EndpointMetadata{
				OperationID: "getSession",
				Description: "Get the current user's session data",
				Responses: map[int]any{
					200: core.SessionData{},
					401: core.ErrorResponse{},
				},
			},
		},
		{
			Path:   "/refresh",
			Method: "POST",
			Metadata: core.EndpointMetadata{
				OperationID: "refreshToken",
				Description: "Refresh an expired or expiring authentication token",
				Responses: map[int]any{
					200: core.RefreshResult{},
					401: core.ErrorResponse{},
				},
			},
		},
	}
}

// EndpointRegistry manages endpoints with conflict detection
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
