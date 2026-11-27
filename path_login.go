package authjson

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/cidrutil"
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
			logical.UpdateOperation:         b.pathAuthLogin,
			logical.AliasLookaheadOperation: b.pathAuthLoginAliasLookahead,
		},
	}
}

func (b *backend) pathAuthLogin(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.Logger().Debug("login requested")

	// Extract username and password from the request data hence those are present in the Fields map schema
	username := d.Get("username").(string)
	password := d.Get("password").(string)

	// Load the users from the file specified in the configuration, we re-read it at every login, might not be the best approach though
	// If the configuration or the file is not usable we do not allow login, this is printed in operational logs of Vault at ERROR level
	users, err := b.loadUsers(ctx, req.Storage)
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

	// Enforce the role's bound CIDRs against the client address, no CIDRs configured means no restriction
	var remoteAddr string
	if req.Connection != nil {
		remoteAddr = req.Connection.RemoteAddr
	}

	if !cidrutil.RemoteAddrIsOk(remoteAddr, userRole.TokenBoundCIDRs) {
		b.Logger().Debug("login failed - client address not in the role's bound CIDRs", "remote_addr", remoteAddr)
		return nil, logical.ErrPermissionDenied
	}

	// Login successful, create and return the auth response
	authResponse := &logical.Auth{
		DisplayName: fmt.Sprintf("%s %s", user.GivenName, user.FamilyName),
		// The alias links the login to a Vault identity entity, the user_id is unique in the users file and does not change
		Alias: &logical.Alias{
			Name: user.UserID,
			// Visible on the entity alias, usable in templated policies
			Metadata: map[string]string{
				"team_role": user.TeamRole,
			},
		},
		// Adds the entity to the external group that has a group alias with this name on this mount.
		// Vault ignores a name for which no external group and group alias exist.
		GroupAliases: []*logical.Alias{{Name: user.TeamRole}},
		//Internal data is not visible to the user, usually used during renew operations
		InternalData: map[string]interface{}{
			"team_role": user.TeamRole,
			"user_id":   user.UserID,
		},
		Policies: userRole.TokenPolicies,
		Metadata: map[string]string{
			"team_role":   user.TeamRole,
			"nickname":    user.Nickname,
			"given_name":  user.GivenName,
			"family_name": user.FamilyName,
		},
	}
	// Apply all token settings of the role: policies, TTLs, period, num_uses, type, bound CIDRs, etc.
	userRole.PopulateTokenAuth(authResponse)

	// Login successful
	return &logical.Response{Auth: authResponse}, nil
}

// pathAuthLoginAliasLookahead tells Vault which alias a login request would get, before the credentials are checked.
// Vault uses it for features that need to know the user up front, such as user lockout and login MFA.
// It must not authenticate anything, it only echoes the username as the alias name, the same one that pathAuthLogin returns.
func (b *backend) pathAuthLoginAliasLookahead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	username := d.Get("username").(string)
	if username == "" {
		return nil, logical.ErrInvalidRequest
	}

	return &logical.Response{
		Auth: &logical.Auth{
			Alias: &logical.Alias{Name: username},
		},
	}, nil
}

// loadUsers reads the configuration from storage and loads the users from the file it points to
func (b *backend) loadUsers(ctx context.Context, s logical.Storage) ([]jsonauthhelper.User, error) {
	entry, err := s.Get(ctx, configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read configuration from storage: %w", err)
	}
	if entry == nil {
		return nil, errors.New("configuration not found in storage")
	}

	var config jsonAuthConfig
	if err := entry.DecodeJSON(&config); err != nil {
		return nil, fmt.Errorf("failed to decode configuration: %w", err)
	}

	users, err := jsonauthhelper.LoadUsersFromFile(config.UsersFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to load users file: %w", err)
	}
	return users, nil
}
