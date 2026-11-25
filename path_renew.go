package authjson

import (
	"context"
	"errors"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/martinhristov90/authjson/internal/jsonauthhelper"
)

func (b *backend) PathAuthRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.Logger().Debug("auth renew requested")

	b.l.RLock()
	defer b.l.RUnlock()

	if req.Auth == nil {
		b.Logger().Error("login failed")
		return nil, errors.New("request auth was nil")
	}

	// Both values are stored in InternalData at login, tokens issued without them cannot be renewed
	secretValueRoleName, ok := req.Auth.InternalData["team_role"].(string)
	if !ok {
		b.Logger().Trace("renew operation expected string for team_role")
		return nil, logical.ErrPermissionDenied
	}
	userID, ok := req.Auth.InternalData["user_id"].(string)
	if !ok {
		b.Logger().Trace("renew operation expected string for user_id")
		return nil, logical.ErrPermissionDenied
	}

	// The user must still be present in the users file, and still be in the team the token was issued for
	users, err := b.loadUsers(ctx, req.Storage)
	if err != nil {
		b.Logger().Error("failed to load users during renew", "err", err.Error())
		return nil, logical.ErrPermissionDenied
	}
	user := jsonauthhelper.FindUser(userID, users)
	if user == nil || user.TeamRole != secretValueRoleName {
		b.Logger().Debug("renew denied - user was removed or changed team", "user_id", userID)
		return nil, logical.ErrPermissionDenied
	}

	// The role must still exist as well
	role, err := b.role(ctx, req.Storage, secretValueRoleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, logical.ErrPermissionDenied
	}
	a := framework.LeaseExtend(role.TokenTTL, role.TokenMaxTTL, b.System())
	resp, err := a(ctx, req, d)
	if err != nil || resp == nil || resp.Auth == nil {
		return resp, err
	}
	// Keep the role's period on renewal, otherwise periodic tokens would lose it
	resp.Auth.Period = role.TokenPeriod
	b.Logger().Trace("auth renew succeeded")
	return resp, nil
}
