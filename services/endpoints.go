package services

import (
	"fmt"

	"github.com/lborres/kuta/core"
)

// BaseEndpoints returns framework-agnostic endpoint specifications
// for all core authentication endpoints.
//
// Each endpoint is a template:
// - Path and Method are set
// - Handler is nil (provided by adapters)
// - Metadata contains OpenAPI information
//
// This allows multiple adapters (Fiber, Gin, Echo) to share the same
// endpoint definitions while providing their own framework-specific handlers.
func BaseEndpoints() []core.Endpoint {
	return []core.Endpoint{
		{
			Path:    "/sign-up",
			Method:  "POST",
			Handler: nil,
			Metadata: core.EndpointMetadata{
				OperationID: "signUpWithEmailAndPassword",
				Description: "Sign up a user using email and password",
			},
		},
		{
			Path:    "/sign-in",
			Method:  "POST",
			Handler: nil,
			Metadata: core.EndpointMetadata{
				OperationID: "signInWithEmailAndPassword",
				Description: "Sign in a user using email and password",
			},
		},
		{
			Path:    "/sign-out",
			Method:  "POST",
			Handler: nil,
			Metadata: core.EndpointMetadata{
				OperationID: "signOut",
				Description: "Sign out the current user and invalidate the session",
			},
		},
		{
			Path:    "/session",
			Method:  "GET",
			Handler: nil,
			Metadata: core.EndpointMetadata{
				OperationID: "getSession",
				Description: "Get the current user's session data",
			},
		},
		{
			Path:    "/refresh",
			Method:  "POST",
			Handler: nil,
			Metadata: core.EndpointMetadata{
				OperationID: "refreshToken",
				Description: "Refresh an expired or expiring authentication token",
			},
		},
	}
}

// EndpointRegistry manages a collection of framework-agnostic endpoints
// and handles conflict detection for duplicate METHOD:PATH combinations.
//
// It starts with base authentication endpoints and supports registration of
// additional plugin endpoints with automatic conflict detection.
type EndpointRegistry struct {
	// endpoints stores all registered endpoints keyed by "METHOD:PATH"
	endpoints map[string]*core.Endpoint
}

// NewEndpointRegistry creates a new registry with all base authentication endpoints
// pre-registered.
func NewEndpointRegistry() *EndpointRegistry {
	reg := &EndpointRegistry{
		endpoints: make(map[string]*core.Endpoint),
	}

	// Register all base endpoints
	for i := range BaseEndpoints() {
		ep := BaseEndpoints()[i]
		reg.register(&ep)
	}

	return reg
}

// register adds a single endpoint to the registry with conflict detection.
// Returns error if an endpoint with the same METHOD:PATH already exists.
func (r *EndpointRegistry) register(ep *core.Endpoint) error {
	key := fmt.Sprintf("%s:%s", ep.Method, ep.Path)

	if _, exists := r.endpoints[key]; exists {
		return fmt.Errorf("endpoint conflict: %s %s already registered", ep.Method, ep.Path)
	}

	r.endpoints[key] = ep
	return nil
}

// RegisterPlugin registers additional plugin endpoints to the registry.
// Returns error if any plugin endpoint conflicts with existing endpoints
// or with other plugin endpoints in the same batch.
//
// If an error occurs, no endpoints from the plugin are registered.
func (r *EndpointRegistry) RegisterPlugin(endpoints []core.Endpoint) error {
	// First, check for conflicts with existing endpoints
	for i := range endpoints {
		ep := &endpoints[i]
		key := fmt.Sprintf("%s:%s", ep.Method, ep.Path)

		if _, exists := r.endpoints[key]; exists {
			return fmt.Errorf("plugin endpoint conflict: %s %s already registered", ep.Method, ep.Path)
		}
	}

	// Check for conflicts within the plugin set itself
	seen := make(map[string]bool)
	for i := range endpoints {
		ep := &endpoints[i]
		key := fmt.Sprintf("%s:%s", ep.Method, ep.Path)

		if seen[key] {
			return fmt.Errorf("plugin contains duplicate endpoint: %s %s", ep.Method, ep.Path)
		}
		seen[key] = true
	}

	// No conflicts found, register all plugin endpoints
	for i := range endpoints {
		ep := &endpoints[i]
		r.endpoints[fmt.Sprintf("%s:%s", ep.Method, ep.Path)] = ep
	}

	return nil
}

// Endpoints returns a slice of all registered endpoints
// (both base and plugin endpoints).
func (r *EndpointRegistry) Endpoints() []*core.Endpoint {
	result := make([]*core.Endpoint, 0, len(r.endpoints))
	for _, ep := range r.endpoints {
		result = append(result, ep)
	}
	return result
}
