package admin

import (
	"net/http"

	"github.com/lborres/kuta/core"
)

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
