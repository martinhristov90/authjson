package authjson

import (
	"context"
	"fmt"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/martinhristov90/authjson/internal/jsonauthhelper"
)

func (b *backend) PathLogin() *framework.Path {
	return &framework.Path{
		Pattern: "login",
		Fields: map[string]*framework.FieldSchema{
			"password": {
				Type: framework.TypeString,
			},
			"username": {
				Type: framework.TypeString,
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathAuthLogin,
		},
	}
}

func (b *backend) pathAuthLogin(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.Logger().Debug("login requested")

	// Extract username and password from the request data hence those are present in the Fields map schema
	username := d.Get("username").(string)
	password := d.Get("password").(string)

	// Read the configuration from storage, error if we fail to read it
	entry, err := req.Storage.Get(ctx, configPath)
	if err != nil {
		b.Logger().Error("failed to read configuration from storage", "err", err.Error())
		return nil, logical.ErrPermissionDenied
	}
	// If configuration is not found we do not allow login, this is printed in operational logs of Vault at ERROR level
	if entry == nil {
		b.Logger().Error("configuration not found in storage")
		return nil, logical.ErrPermissionDenied
	}

	// The configuration would be stored here, we re-read it at every login, might not be the best approach though
	var config jsonAuthConfig

	// Decode the configuration, bail out if we fail
	if err := entry.DecodeJSON(&config); err != nil {
		b.Logger().Error("failed to decode configuration", "err", err.Error())
		return nil, logical.ErrPermissionDenied
	}

	// Load users from the JSON file specified in the configuration
	users, err := jsonauthhelper.LoadUsersFromFile(config.UsersFilePath)
	if err != nil {
		b.Logger().Error("failed to load users", "err", err.Error())
		return nil, logical.ErrPermissionDenied
	}

	// Log loaded users at trace level
	if b.Logger().IsTrace() {
		for _, user := range users {
			b.Logger().Log(hclog.Trace, "loaded user", "user_id", user.UserID, "email", user.Email)
		}
	}

	user := jsonauthhelper.Authenticate(username, password, users)
	if user == nil {
		b.Logger().Debug("login failed", "err", logical.ErrPermissionDenied.Error())
		return nil, logical.ErrPermissionDenied
	}

	b.Logger().Trace("login succeeded")

	userRole, err := b.checkRoleAssignment(ctx, req.Storage, user.TeamRole)
	if err != nil {
		b.Logger().Error("error while checking role assignment")
		return nil, logical.ErrPermissionDenied
	}

	// Login successful, create and return the auth response
	return &logical.Response{
		Auth: &logical.Auth{
			DisplayName: fmt.Sprintf("%s %s", user.GivenName, user.FamilyName),
			//Internal data is not visible to the user, usually used during renew operations
			InternalData: map[string]interface{}{
				"team_role": user.TeamRole,
			},
			Policies: userRole.TokenPolicies,
			Metadata: map[string]string{
				"team_role":   user.TeamRole,
				"nickname":    user.Nickname,
				"given_name":  user.GivenName,
				"family_name": user.FamilyName,
			},
			LeaseOptions: logical.LeaseOptions{
				TTL:       userRole.TokenTTL,
				MaxTTL:    userRole.TokenMaxTTL,
				Renewable: true,
			},
		},
	}, nil
}
