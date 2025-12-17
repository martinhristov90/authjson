package authjson

import (
	"context"
	"errors"
	"fmt"
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
	secretValueRoleName := req.Auth.InternalData["team_role"].(string)
	role, err := b.role(ctx, req.Storage, secretValueRoleName)
	if err != nil {
		return nil, fmt.Errorf("Cannot renew, the role does not exist")
	}
	a := framework.LeaseExtend(role.TokenTTL, role.TokenMaxTTL, b.System())
	b.Logger().Trace("auth renew succeeded")
	return a(ctx, req, d)
}
