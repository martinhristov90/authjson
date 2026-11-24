package authjson

import (
	"context"
	"errors"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *backend) PathAuthRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.Logger().Debug("auth renew requested")

	b.l.RLock()
	defer b.l.RUnlock()

	if req.Auth == nil {
		b.Logger().Error("login failed")
		return nil, errors.New("request auth was nil")
	}

	// We verify if the users credentials are still valid, usually JWT, Kubernetes plugins just verify if the role still exists during renewal process
	secretValueRoleName, ok := req.Auth.InternalData["team_role"].(string)
	if !ok {
		b.Logger().Trace("renew operation expected string for team_role")
		return nil, logical.ErrPermissionDenied
	}
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
