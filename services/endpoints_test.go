package services

import (
	"testing"

	"github.com/lborres/kuta/core"
)

// Requirement: BaseEndpoints returns framework-agnostic endpoint specifications
// with all required paths, methods, metadata, and handlers set to nil (templates).
func TestBaseEndpoints(t *testing.T) {
	tests := []struct {
		name           string
		wantPath       string
		wantMethod     string
		wantOpID       string
		wantDesc       string
		wantHandlerNil bool
	}{
		{
			name:           "returns sign-up endpoint with correct path and method",
			wantPath:       "/sign-up",
			wantMethod:     "POST",
			wantOpID:       "signUpWithEmailAndPassword",
			wantDesc:       "Sign up a user using email and password",
			wantHandlerNil: true,
		},
		{
			name:           "returns sign-in endpoint with correct path and method",
			wantPath:       "/sign-in",
			wantMethod:     "POST",
			wantOpID:       "signInWithEmailAndPassword",
			wantDesc:       "Sign in a user using email and password",
			wantHandlerNil: true,
		},
		{
			name:           "returns sign-out endpoint with correct path and method",
			wantPath:       "/sign-out",
			wantMethod:     "POST",
			wantOpID:       "signOut",
			wantDesc:       "Sign out the current user and invalidate the session",
			wantHandlerNil: true,
		},
		{
			name:           "returns session endpoint with correct path and method",
			wantPath:       "/session",
			wantMethod:     "GET",
			wantOpID:       "getSession",
			wantDesc:       "Get the current user's session data",
			wantHandlerNil: true,
		},
		{
			name:           "returns refresh endpoint with correct path and method",
			wantPath:       "/refresh",
			wantMethod:     "POST",
			wantOpID:       "refreshToken",
			wantDesc:       "Refresh an expired or expiring authentication token",
			wantHandlerNil: true,
		},
	}

	// Arrange
	endpoints := BaseEndpoints()

	// Verify endpoint count matches expectations
	if len(endpoints) != len(tests) {
		t.Fatalf("BaseEndpoints should return %d endpoints, got %d", len(tests), len(endpoints))
	}

	// Build a map of endpoints by path for easy lookup
	endpointsByPath := make(map[string]*struct {
		Method     string
		OpID       string
		Desc       string
		HandlerNil bool
	})
	for _, ep := range endpoints {
		endpointsByPath[ep.Path] = &struct {
			Method     string
			OpID       string
			Desc       string
			HandlerNil bool
		}{
			Method:     ep.Method,
			OpID:       ep.Metadata.OperationID,
			Desc:       ep.Metadata.Description,
			HandlerNil: ep.Handler == nil,
		}
	}

	// Act & Assert
	for _, test := range tests {
		test := test // capture range variable
		t.Run(test.name, func(t *testing.T) {
			ep, found := endpointsByPath[test.wantPath]
			if !found {
				t.Fatalf("BaseEndpoints should include endpoint for path %q", test.wantPath)
			}

			if ep.Method != test.wantMethod {
				t.Errorf("endpoint %q should have method %s; got %s", test.wantPath, test.wantMethod, ep.Method)
			}

			if ep.OpID != test.wantOpID {
				t.Errorf("endpoint %q should have OperationID %q; got %q", test.wantPath, test.wantOpID, ep.OpID)
			}

			if ep.Desc != test.wantDesc {
				t.Errorf("endpoint %q should have description %q; got %q", test.wantPath, test.wantDesc, ep.Desc)
			}

			if ep.HandlerNil != test.wantHandlerNil {
				t.Errorf("endpoint %q handler should be nil; got non-nil", test.wantPath)
			}
		})
	}
}

// Requirement: All endpoints must have unique OperationIDs.
func TestBaseEndpoints_OperationIDsAreUnique(t *testing.T) {
	// Arrange
	endpoints := BaseEndpoints()

	// Act & Assert
	operationIDs := make(map[string]bool)
	for _, ep := range endpoints {
		if operationIDs[ep.Metadata.OperationID] {
			t.Errorf("BaseEndpoints contains duplicate OperationID: %q", ep.Metadata.OperationID)
		}
		operationIDs[ep.Metadata.OperationID] = true
	}
}

// Requirement: All endpoints must have unique paths.
func TestBaseEndpoints_PathsAreUnique(t *testing.T) {
	// Arrange
	endpoints := BaseEndpoints()

	// Act & Assert
	paths := make(map[string]bool)
	for _, ep := range endpoints {
		if paths[ep.Path] {
			t.Errorf("BaseEndpoints contains duplicate path: %q", ep.Path)
		}
		paths[ep.Path] = true
	}
}

// Requirement: EndpointRegistry registers all base endpoints on creation
// and provides access to them via Endpoints() method.
func TestEndpointRegistry_RegistersBaseEndpoints(t *testing.T) {
	// Arrange & Act
	registry := NewEndpointRegistry()

	// Assert
	endpoints := registry.Endpoints()

	if len(endpoints) != 5 {
		t.Fatalf("EndpointRegistry should register 5 base endpoints; got %d", len(endpoints))
	}

	expectedPaths := map[string]bool{
		"/sign-up":  true,
		"/sign-in":  true,
		"/sign-out": true,
		"/session":  true,
		"/refresh":  true,
	}

	for _, ep := range endpoints {
		if !expectedPaths[ep.Path] {
			t.Errorf("EndpointRegistry contains unexpected endpoint: %q", ep.Path)
		}
	}
}

// Requirement: EndpointRegistry detects and rejects duplicate endpoint registrations
// (same METHOD:PATH combination).
func TestEndpointRegistry_DetectsConflicts(t *testing.T) {
	tests := []struct {
		name           string
		conflictPath   string
		conflictMethod string
		wantErr        bool
	}{
		{
			name:           "rejects duplicate POST /sign-up",
			conflictPath:   "/sign-up",
			conflictMethod: "POST",
			wantErr:        true,
		},
		{
			name:           "rejects duplicate GET /session",
			conflictPath:   "/session",
			conflictMethod: "GET",
			wantErr:        true,
		},
		{
			name:           "allows different path same method",
			conflictPath:   "/custom",
			conflictMethod: "POST",
			wantErr:        false,
		},
		{
			name:           "allows same path different method",
			conflictPath:   "/sign-up",
			conflictMethod: "GET",
			wantErr:        false,
		},
	}

	for _, test := range tests {
		test := test // capture range variable
		t.Run(test.name, func(t *testing.T) {
			// Arrange
			registry := NewEndpointRegistry()

			plugin := []struct {
				Path   string
				Method string
				OpID   string
			}{
				{
					Path:   test.conflictPath,
					Method: test.conflictMethod,
					OpID:   "customOp",
				},
			}

			// Act
			err := registry.RegisterPlugin(makeEndpoints(plugin))

			// Assert
			if (err != nil) != test.wantErr {
				t.Errorf("RegisterPlugin should error=%v; got error=%v (%v)", test.wantErr, err != nil, err)
			}
		})
	}
}

// Requirement: EndpointRegistry can register additional plugin endpoints
// without conflicts and includes them in Endpoints().
func TestEndpointRegistry_RegistersPluginEndpoints(t *testing.T) {
	tests := []struct {
		name    string
		plugins []struct {
			Path string
			OpID string
		}
		wantTotalCount int
		wantErr        bool
	}{
		{
			name: "registers single plugin endpoint",
			plugins: []struct {
				Path string
				OpID string
			}{
				{Path: "/verify-email", OpID: "verifyEmail"},
			},
			wantTotalCount: 6,
			wantErr:        false,
		},
		{
			name: "registers multiple plugin endpoints",
			plugins: []struct {
				Path string
				OpID string
			}{
				{Path: "/verify-email", OpID: "verifyEmail"},
				{Path: "/change-password", OpID: "changePassword"},
				{Path: "/reset-password", OpID: "resetPassword"},
			},
			wantTotalCount: 8,
			wantErr:        false,
		},
		{
			name: "rejects plugins with conflicts within plugin set",
			plugins: []struct {
				Path string
				OpID string
			}{
				{Path: "/verify-email", OpID: "verifyEmail"},
				{Path: "/verify-email", OpID: "verifyEmailDuplicate"}, // duplicate path
			},
			wantTotalCount: 5, // unchanged, registration failed
			wantErr:        true,
		},
	}

	for _, test := range tests {
		test := test // capture range variable
		t.Run(test.name, func(t *testing.T) {
			// Arrange
			registry := NewEndpointRegistry()

			pluginEndpoints := makePluginEndpoints(test.plugins)

			// Act
			err := registry.RegisterPlugin(pluginEndpoints)

			// Assert
			if (err != nil) != test.wantErr {
				t.Errorf("RegisterPlugin should error=%v; got error=%v", test.wantErr, err != nil)
			}

			endpoints := registry.Endpoints()
			if len(endpoints) != test.wantTotalCount {
				t.Errorf("EndpointRegistry should have %d endpoints after plugin registration; got %d", test.wantTotalCount, len(endpoints))
			}
		})
	}
}

// Helper functions for tests

// makeEndpoints creates core.Endpoint structs from test data.
func makeEndpoints(data []struct {
	Path   string
	Method string
	OpID   string
}) []core.Endpoint {
	result := make([]core.Endpoint, len(data))
	for i, d := range data {
		result[i] = core.Endpoint{
			Path:    d.Path,
			Method:  d.Method,
			Handler: nil,
			Metadata: core.EndpointMetadata{
				OperationID: d.OpID,
				Description: "Plugin endpoint",
			},
		}
	}
	return result
}

// makePluginEndpoints creates plugin endpoint specs from test data.
func makePluginEndpoints(data []struct {
	Path string
	OpID string
}) []core.Endpoint {
	result := make([]core.Endpoint, len(data))
	for i, d := range data {
		result[i] = core.Endpoint{
			Path:    d.Path,
			Method:  "POST", // Default to POST for plugins
			Handler: nil,
			Metadata: core.EndpointMetadata{
				OperationID: d.OpID,
				Description: "Plugin endpoint",
			},
		}
	}
	return result
}
