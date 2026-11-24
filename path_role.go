package authjson

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/hashicorp/go-sockaddr"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/policyutil"
	"github.com/hashicorp/vault/sdk/helper/tokenutil"
	"github.com/hashicorp/vault/sdk/logical"
	"strings"
	"time"
)

const (
	rolePrefix = "role/"
)

// This struct holds all fields that can be stored in StorageEntry
type roleStorageEntry struct {
	// including all fields of TokenParams struct to our roleStorageEntry struct
	tokenutil.TokenParams
	// Deprecated by TokenParams
	Policies   []string                      `json:"policies" structs:"policies" mapstructure:"policies"`
	NumUses    int                           `json:"num_uses" mapstructure:"num_uses" structs:"num_uses"`
	TTL        time.Duration                 `json:"ttl" structs:"ttl" mapstructure:"ttl"`
	MaxTTL     time.Duration                 `json:"max_ttl" structs:"max_ttl" mapstructure:"max_ttl"`
	Period     time.Duration                 `json:"period" mapstructure:"period" structs:"period"`
	BoundCIDRs []*sockaddr.SockAddrMarshaler `json:"bound_cidrs" structs:"bound_cidrs" mapstructure:"bound_cidrs"`
}

// Returns a StorageEntry for given Storage and role name. The Storage object is part of logical.Request objects being given to the backend
func (b *backend) role(ctx context.Context, s logical.Storage, name string) (*roleStorageEntry, error) {
	raw, err := s.Get(ctx, fmt.Sprintf("%s%s", rolePrefix, strings.ToLower(name)))
	if err != nil {
		return nil, err
	}
	// Returning nil if the entry does not exists, it will be used in CreateUpdate method
	if raw == nil {
		return nil, nil
	}

	role := &roleStorageEntry{}

	if err := json.Unmarshal(raw.Value, role); err != nil {
		return nil, err
	}

	return role, nil
}

func (b *backend) PathsRoleList() *framework.Path {
	pathList := &framework.Path{
		Pattern: "role/?",
		// No Fields, hence we are just listing the roles
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: b.pathRoleList,
		},
		DisplayAttrs: &framework.DisplayAttributes{
			// Those fields are mostly related to UI
			OperationPrefix: "jsonauth",
		},
	}
	// Return the path for List operation
	return pathList
}

func (b *backend) PathRoleCRUD() *framework.Path {
	pathRole := &framework.Path{
		// Copied from docs
		// Helper which returns a generic regex string for creating endpoint patterns
		// that are identified by the given name in the backends
		Pattern: "role/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the role",
			},
			"policies": {
				Type:        framework.TypeCommaStringSlice,
				Description: tokenutil.DeprecationText("token_policies"),
				Deprecated:  true,
			},
			"num_uses": {
				Type:        framework.TypeInt,
				Description: tokenutil.DeprecationText("token_num_uses"),
				Deprecated:  true,
			},
			"ttl": {
				Type:        framework.TypeDurationSecond,
				Description: tokenutil.DeprecationText("token_ttl"),
				Deprecated:  true,
			},
			"max_ttl": {
				Type:        framework.TypeDurationSecond,
				Description: tokenutil.DeprecationText("token_max_ttl"),
				Deprecated:  true,
			},
			"period": {
				Type:        framework.TypeDurationSecond,
				Description: tokenutil.DeprecationText("token_period"),
				Deprecated:  true,
			},
			"bound_cidrs": {
				Type:        framework.TypeCommaStringSlice,
				Description: tokenutil.DeprecationText("token_bound_cidrs"),
				Deprecated:  true,
			},
		},
		ExistenceCheck: b.pathRoleExistenceCheck,
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.CreateOperation: b.pathRoleCreateUpdate,
			logical.UpdateOperation: b.pathRoleCreateUpdate,
			logical.ReadOperation:   b.pathRoleRead,
			logical.DeleteOperation: b.pathRoleDelete,
		},
	}
	// Adding "usual" token fields from the tokenutil package. The one that are mentioned above are explictly depricated
	// For example period(old)=token_period(new)
	tokenutil.AddTokenFields(pathRole.Fields)
	// Returning CRUD paths for Role
	return pathRole
}

func (b *backend) pathRoleList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.Logger().Debug("reading role list")

	// Readers don't have to wait for each other. They only have to wait for writers that are holding the lock.
	// If a write request is being executed when we list the roles, we should wait for it
	b.l.RLock()
	defer b.l.RUnlock()

	roles, err := req.Storage.List(ctx, "role/")
	if err != nil {
		b.Logger().Error("failure to list roles %v", err)
		return nil, err
	}

	return logical.ListResponse(roles), nil
}

func (b *backend) pathRoleRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	roleName := d.Get("name")
	// If role name is empty we return an error
	if roleName == "" {
		return logical.ErrorResponse("missing role name"), nil
	}

	// If a write request is being executed when we read a role, we should wait for it
	b.l.RLock()
	defer b.l.RUnlock()

	role, err := b.role(ctx, req.Storage, roleName.(string))
	if err != nil {
		return nil, err
	}

	if role == nil {
		return nil, nil
	}

	// Empty map of interfaces, we are just populating the token data
	resp := map[string]interface{}{}

	role.PopulateTokenData(resp)

	return &logical.Response{Data: resp}, nil
}

func (b *backend) pathRoleCreateUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName := d.Get("name").(string)
	// If role name is empty we return an error
	if roleName == "" {
		return logical.ErrorResponse("missing role name"), nil
	}

	b.l.RLock()
	defer b.l.RUnlock()

	// Checking if the role already exists, if it does it is stored to role, so it can be updated later
	role, err := b.role(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	// if b.role return nil for role, that means the storage entry is empty (it does not exists)
	if role == nil && req.Operation == logical.CreateOperation {
		// We get here only if operation is create. To this path are routed only Create and Update operations
		// Creating an empty role, so we can fill out the data from FieldData to it
		role = &roleStorageEntry{}
	} else if role == nil {
		return nil, fmt.Errorf("trying to update a role that does not exists")
	}

	if err := role.ParseTokenFields(req, d); err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	var resp *logical.Response

	{
		if err := tokenutil.UpgradeValue(d, "policies", "token_policies", &role.Policies, &role.TokenPolicies); err != nil {
			return logical.ErrorResponse(err.Error()), nil
		}

		if err := tokenutil.UpgradeValue(d, "bound_cidrs", "token_bound_cidrs", &role.BoundCIDRs, &role.TokenBoundCIDRs); err != nil {
			return logical.ErrorResponse(err.Error()), nil
		}

		if err := tokenutil.UpgradeValue(d, "num_uses", "token_num_uses", &role.NumUses, &role.TokenNumUses); err != nil {
			return logical.ErrorResponse(err.Error()), nil
		}

		if err := tokenutil.UpgradeValue(d, "ttl", "token_ttl", &role.TTL, &role.TokenTTL); err != nil {
			return logical.ErrorResponse(err.Error()), nil
		}

		if err := tokenutil.UpgradeValue(d, "max_ttl", "token_max_ttl", &role.MaxTTL, &role.TokenMaxTTL); err != nil {
			return logical.ErrorResponse(err.Error()), nil
		}

		if err := tokenutil.UpgradeValue(d, "period", "token_period", &role.Period, &role.TokenPeriod); err != nil {
			return logical.ErrorResponse(err.Error()), nil
		}
	}

	// removing duplicate policies
	role.TokenPolicies = policyutil.ParsePolicies(role.TokenPolicies)

	// Store the entry.
	entry, err := logical.StorageEntryJSON(rolePrefix+strings.ToLower(roleName), role)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, fmt.Errorf("failed to create storage entry for role %s", roleName)
	}
	if err = req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return resp, nil

}

func (b *backend) pathRoleDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing role name"), nil
	}

	// Acquire the lock before deleting the role.
	b.l.Lock()
	defer b.l.Unlock()

	// Delete the role itself
	if err := req.Storage.Delete(ctx, rolePrefix+strings.ToLower(roleName)); err != nil {
		return nil, err
	}

	return nil, nil
}

// pathRoleExistenceCheck returns whether the role with the given name exists or not.
func (b *backend) pathRoleExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	b.l.RLock()
	defer b.l.RUnlock()

	role, err := b.role(ctx, req.Storage, data.Get("name").(string))
	if err != nil {
		return false, err
	}
	// role != nil evaluates to boolean expression, if role exists should be true
	return role != nil, nil
}

func (b *backend) checkRoleAssignment(ctx context.Context, stor logical.Storage, roleName string) (*roleStorageEntry, error) {

	b.l.RLock()
	defer b.l.RUnlock()

	role, err := b.role(ctx, stor, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, fmt.Errorf("The role does not exists")
	}

	return role, nil
}
