package admin

import (
	"fmt"
	"net/http"

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

// --- Self-contained endpoint handlers ---

// actorFromSession extracts actor ID and role from the session.
// Plugins that extend the user model resolve the role from storage.
func (p *AdminPlugin) actorFromSession(ctx *core.RequestContext) (actorID, actorRole string, err error) {
	if ctx.Session == nil || ctx.Session.User == nil {
		return "", "", ErrNotAuthorized
	}
	actorID = ctx.Session.User.ID

	// Look up the user's role from admin storage
	userWithRole, lookupErr := p.service.storage.GetUserWithRole(actorID)
	if lookupErr != nil {
		// Fall back to default role if user not found in admin storage
		actorRole = p.service.config.DefaultRole
	} else {
		actorRole = userWithRole.Role
	}

	return actorID, actorRole, nil
}

func (p *AdminPlugin) handleSetRole(ctx *core.RequestContext) error {
	actorID, actorRole, err := p.actorFromSession(ctx)
	if err != nil {
		return err
	}

	var input SetRoleInput
	if err := ctx.Bind(&input); err != nil {
		ctx.JSON(http.StatusBadRequest, core.ErrorResponse{Error: "invalid request body"})
		return nil
	}

	result, err := p.service.SetRole(actorID, actorRole, input)
	if err != nil {
		return err
	}

	ctx.JSON(http.StatusOK, result)
	return nil
}

func (p *AdminPlugin) handleCreateUser(ctx *core.RequestContext) error {
	actorID, actorRole, err := p.actorFromSession(ctx)
	if err != nil {
		return err
	}

	var input CreateUserInput
	if err := ctx.Bind(&input); err != nil {
		ctx.JSON(http.StatusBadRequest, core.ErrorResponse{Error: "invalid request body"})
		return nil
	}

	result, err := p.service.CreateUser(actorID, actorRole, input)
	if err != nil {
		return err
	}

	ctx.JSON(http.StatusCreated, result)
	return nil
}

func (p *AdminPlugin) handleListUsers(ctx *core.RequestContext) error {
	actorID, actorRole, err := p.actorFromSession(ctx)
	if err != nil {
		return err
	}

	// Build input from query params
	input := ListUsersInput{
		SearchField: ctx.QueryParams["searchField"],
		SearchValue: ctx.QueryParams["searchValue"],
		SortBy:      ctx.QueryParams["sortBy"],
		FilterField: ctx.QueryParams["filterField"],
		FilterValue: ctx.QueryParams["filterValue"],
	}

	result, err := p.service.ListUsers(actorID, actorRole, input)
	if err != nil {
		return err
	}

	ctx.JSON(http.StatusOK, result)
	return nil
}

func (p *AdminPlugin) handleGetUser(ctx *core.RequestContext) error {
	actorID, actorRole, err := p.actorFromSession(ctx)
	if err != nil {
		return err
	}

	targetUserID := ctx.QueryParams["userId"]
	if targetUserID == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorResponse{Error: "userId query parameter is required"})
		return nil
	}

	result, err := p.service.GetUser(actorID, actorRole, targetUserID)
	if err != nil {
		return err
	}

	ctx.JSON(http.StatusOK, result)
	return nil
}

func (p *AdminPlugin) handleUpdateUser(ctx *core.RequestContext) error {
	actorID, actorRole, err := p.actorFromSession(ctx)
	if err != nil {
		return err
	}

	var input UpdateUserInput
	if err := ctx.Bind(&input); err != nil {
		ctx.JSON(http.StatusBadRequest, core.ErrorResponse{Error: "invalid request body"})
		return nil
	}

	result, err := p.service.UpdateUser(actorID, actorRole, input)
	if err != nil {
		return err
	}

	ctx.JSON(http.StatusOK, result)
	return nil
}

func (p *AdminPlugin) handleDeleteUser(ctx *core.RequestContext) error {
	actorID, actorRole, err := p.actorFromSession(ctx)
	if err != nil {
		return err
	}

	var input struct {
		UserID string `json:"userId"`
	}
	if err := ctx.Bind(&input); err != nil {
		ctx.JSON(http.StatusBadRequest, core.ErrorResponse{Error: "invalid request body"})
		return nil
	}

	if err := p.service.DeleteUser(actorID, actorRole, input.UserID); err != nil {
		return err
	}

	ctx.JSON(http.StatusOK, map[string]string{"message": "user deleted"})
	return nil
}

func (p *AdminPlugin) handleBanUser(ctx *core.RequestContext) error {
	actorID, actorRole, err := p.actorFromSession(ctx)
	if err != nil {
		return err
	}

	var input BanUserInput
	if err := ctx.Bind(&input); err != nil {
		ctx.JSON(http.StatusBadRequest, core.ErrorResponse{Error: "invalid request body"})
		return nil
	}

	result, err := p.service.BanUser(actorID, actorRole, input)
	if err != nil {
		return err
	}

	ctx.JSON(http.StatusOK, result)
	return nil
}

func (p *AdminPlugin) handleUnbanUser(ctx *core.RequestContext) error {
	actorID, actorRole, err := p.actorFromSession(ctx)
	if err != nil {
		return err
	}

	var input struct {
		UserID string `json:"userId"`
	}
	if err := ctx.Bind(&input); err != nil {
		ctx.JSON(http.StatusBadRequest, core.ErrorResponse{Error: "invalid request body"})
		return nil
	}

	result, err := p.service.UnbanUser(actorID, actorRole, input.UserID)
	if err != nil {
		return err
	}

	ctx.JSON(http.StatusOK, result)
	return nil
}

func (p *AdminPlugin) handleSetPassword(ctx *core.RequestContext) error {
	actorID, actorRole, err := p.actorFromSession(ctx)
	if err != nil {
		return err
	}

	var input struct {
		UserID   string `json:"userId"`
		Password string `json:"password"`
	}
	if err := ctx.Bind(&input); err != nil {
		ctx.JSON(http.StatusBadRequest, core.ErrorResponse{Error: "invalid request body"})
		return nil
	}

	if err := p.service.SetUserPassword(actorID, actorRole, input.UserID, input.Password); err != nil {
		return err
	}

	ctx.JSON(http.StatusOK, map[string]string{"message": "password updated"})
	return nil
}

func (p *AdminPlugin) handleListSessions(ctx *core.RequestContext) error {
	actorID, actorRole, err := p.actorFromSession(ctx)
	if err != nil {
		return err
	}

	targetUserID := ctx.QueryParams["userId"]
	if targetUserID == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorResponse{Error: "userId query parameter is required"})
		return nil
	}

	sessions, err := p.service.ListUserSessions(actorID, actorRole, targetUserID)
	if err != nil {
		return err
	}

	ctx.JSON(http.StatusOK, sessions)
	return nil
}

func (p *AdminPlugin) handleRevokeSession(ctx *core.RequestContext) error {
	actorID, actorRole, err := p.actorFromSession(ctx)
	if err != nil {
		return err
	}

	var input struct {
		SessionID string `json:"sessionId"`
	}
	if err := ctx.Bind(&input); err != nil {
		ctx.JSON(http.StatusBadRequest, core.ErrorResponse{Error: "invalid request body"})
		return nil
	}

	if err := p.service.RevokeSession(actorID, actorRole, input.SessionID); err != nil {
		return err
	}

	ctx.JSON(http.StatusOK, map[string]string{"message": "session revoked"})
	return nil
}

func (p *AdminPlugin) handleRevokeUserSessions(ctx *core.RequestContext) error {
	actorID, actorRole, err := p.actorFromSession(ctx)
	if err != nil {
		return err
	}

	var input struct {
		UserID string `json:"userId"`
	}
	if err := ctx.Bind(&input); err != nil {
		ctx.JSON(http.StatusBadRequest, core.ErrorResponse{Error: "invalid request body"})
		return nil
	}

	count, err := p.service.RevokeUserSessions(actorID, actorRole, input.UserID)
	if err != nil {
		return err
	}

	ctx.JSON(http.StatusOK, map[string]any{
		"message": "sessions revoked",
		"revoked": count,
	})
	return nil
}
