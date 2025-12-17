package authjson

import (
	"context"
	"sync"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/martinhristov90/authjson/internal/version"
)

func Factory(ctx context.Context, c *logical.BackendConfig) (logical.Backend, error) {
	b := Backend(c) // Create a new backend instance
	if err := b.Setup(ctx, c); err != nil {
		return nil, err
	}
	return b, nil // Returning the initialized backend
}

type backend struct {
	*framework.Backend // Embedding the framework.Backend to leverage its functionalities
	l                  sync.RWMutex
}

func Backend(c *logical.BackendConfig) *backend {
	var b backend
	// Initialize the backend structure and set its type to Credential
	b.Backend = &framework.Backend{
		BackendType: logical.TypeCredential, // This is an authentication backend
		AuthRenew:   b.PathAuthRenew,        // Registering the renew function
		PathsSpecial: &logical.Paths{ // Special paths configuration
			// We need this to allow unauthenticated access to the login path, otherwise Vault will block it
			Unauthenticated: []string{"login"}, // Allowing unauthenticated access to the login path
			// In case the Seal allows wrapping, we wrap the configuration of the plugin
			SealWrapStorage: []string{configPath}, // Allowing seal wrapping for the config path
		},
		Paths:          []*framework.Path{b.PathLogin(), b.PathConfig(), b.PathsRoleList(), b.PathRoleCRUD()}, // Registering the paths, Renew is registered separately
		RunningVersion: "v" + version.Version,                                                                 // Setting the running version of the plugin
	}

	return &b // Returning the initialized backend
}
