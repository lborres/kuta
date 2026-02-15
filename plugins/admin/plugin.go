package admin

import (
	"fmt"

	"github.com/lborres/kuta/core"
)

// AdminPlugin wraps the admin service and implements core.Plugin
type AdminPlugin struct {
	config  Config
	service *Service
}

// Compile-time check that AdminPlugin implements PluginWithEndpoints
var _ core.PluginWithEndpoints = (*AdminPlugin)(nil)

// New creates a new admin plugin with the given configuration
func New(config Config) *AdminPlugin {
	return &AdminPlugin{config: config}
}

// ID returns the plugin identifier
func (p *AdminPlugin) ID() string {
	return "admin"
}

// Init initializes the admin plugin with core dependencies
func (p *AdminPlugin) Init(deps core.PluginDependencies) error {
	// Validate storage implements AdminStorageProvider
	adminStorage, ok := deps.Storage.(AdminStorageProvider)
	if !ok {
		return fmt.Errorf("admin plugin requires storage to implement AdminStorageProvider")
	}

	// Initialize the service
	p.service = NewService(p.config, adminStorage, deps.Passwords, deps.Auth)
	return nil
}

// Service returns the initialized admin service
// This should only be called after Init()
func (p *AdminPlugin) Service() *Service {
	return p.service
}

// Endpoints returns all admin HTTP endpoints.
// Each handler is self-contained — no adapter-specific code needed.
func (p *AdminPlugin) Endpoints() []core.PluginEndpoint {
	return []core.PluginEndpoint{
		{
			Path:           "/set-role",
			Method:         "POST",
			RequireSession: true,
			Handler:        p.handleSetRole,
			Metadata: core.EndpointMetadata{
				OperationID: "adminSetRole",
				Description: "Set a user's role",
			},
		},
		{
			Path:           "/create-user",
			Method:         "POST",
			RequireSession: true,
			Handler:        p.handleCreateUser,
			Metadata: core.EndpointMetadata{
				OperationID: "adminCreateUser",
				Description: "Create a new user as admin",
			},
		},
		{
			Path:           "/list-users",
			Method:         "GET",
			RequireSession: true,
			Handler:        p.handleListUsers,
			Metadata: core.EndpointMetadata{
				OperationID: "adminListUsers",
				Description: "List users with pagination and filtering",
			},
		},
		{
			Path:           "/get-user",
			Method:         "GET",
			RequireSession: true,
			Handler:        p.handleGetUser,
			Metadata: core.EndpointMetadata{
				OperationID: "adminGetUser",
				Description: "Get a user by ID",
			},
		},
		{
			Path:           "/update-user",
			Method:         "POST",
			RequireSession: true,
			Handler:        p.handleUpdateUser,
			Metadata: core.EndpointMetadata{
				OperationID: "adminUpdateUser",
				Description: "Update a user's fields",
			},
		},
		{
			Path:           "/delete-user",
			Method:         "POST",
			RequireSession: true,
			Handler:        p.handleDeleteUser,
			Metadata: core.EndpointMetadata{
				OperationID: "adminDeleteUser",
				Description: "Delete a user",
			},
		},
		{
			Path:           "/ban-user",
			Method:         "POST",
			RequireSession: true,
			Handler:        p.handleBanUser,
			Metadata: core.EndpointMetadata{
				OperationID: "adminBanUser",
				Description: "Ban a user",
			},
		},
		{
			Path:           "/unban-user",
			Method:         "POST",
			RequireSession: true,
			Handler:        p.handleUnbanUser,
			Metadata: core.EndpointMetadata{
				OperationID: "adminUnbanUser",
				Description: "Unban a user",
			},
		},
		{
			Path:           "/set-password",
			Method:         "POST",
			RequireSession: true,
			Handler:        p.handleSetPassword,
			Metadata: core.EndpointMetadata{
				OperationID: "adminSetPassword",
				Description: "Set a user's password",
			},
		},
		{
			Path:           "/list-sessions",
			Method:         "GET",
			RequireSession: true,
			Handler:        p.handleListSessions,
			Metadata: core.EndpointMetadata{
				OperationID: "adminListUserSessions",
				Description: "List a user's sessions",
			},
		},
		{
			Path:           "/revoke-session",
			Method:         "POST",
			RequireSession: true,
			Handler:        p.handleRevokeSession,
			Metadata: core.EndpointMetadata{
				OperationID: "adminRevokeSession",
				Description: "Revoke a specific session",
			},
		},
		{
			Path:           "/revoke-user-sessions",
			Method:         "POST",
			RequireSession: true,
			Handler:        p.handleRevokeUserSessions,
			Metadata: core.EndpointMetadata{
				OperationID: "adminRevokeUserSessions",
				Description: "Revoke all sessions for a user",
			},
		},
	}
}
