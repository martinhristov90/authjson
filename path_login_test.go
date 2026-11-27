package authjson

import (
	"context"
	"os"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

func TestPathLogin(t *testing.T) {
	// Get the test backend and storage instance, this is in-memory for testing purposes
	b, storage := getTestBackend(t)
	// Prepare the data for the write operation

	// First, we need to set up the configuration so that the login can succeed
	configData := map[string]interface{}{
		// we use a test JSON file with predefined users for integration testing
		// If this is run in the Docker container it should be /example/integration_test_data/users.json
		"users_file_path": "./integration_test_data/users.json",
	}

	// Preparing a request to write to the storage
	configReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data:      configData,
	}

	// user-marti is part of backline team, login should be successful, the role is just empty with default values for polices, ttl and max_ttl
	RoleCreateReq := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/backline",
		Storage:   storage,
		Data:      map[string]interface{}{},
	}

	resp, err := b.HandleRequest(context.Background(), RoleCreateReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	// Set the configuration
	_, err = b.HandleRequest(context.Background(), configReq)
	if err != nil {
		t.Fatalf("failed to set configuration: %s", err)
	}

	// Prepare the data for the login operation
	data := map[string]interface{}{
		"username": "user-martin",
		"password": "hashed_password_here",
	}

	// Create a logical request for the login operation
	req := new(logical.Request)
	req.Operation = logical.UpdateOperation
	req.Storage = storage
	req.Path = "login"
	req.Data = data

	// Perform the login operation
	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("err: %s resp: %#v\n", err, resp)
	}

	// Verify that the response contains a valid auth object
	if resp.Auth == nil {
		t.Fatalf("expected auth object in response, got nil")
	}

	// Create a logical request for the login operation with wrong password
	data = map[string]interface{}{
		"username": "user-marti",
		"password": "wrong_password",
	}

	// Create a logical request for the login operation
	req = new(logical.Request)
	req.Operation = logical.UpdateOperation
	req.Storage = storage
	req.Path = "login"
	req.Data = data

	// Perform the login operation with wrong password
	resp, err = b.HandleRequest(context.Background(), req)
	if err == logical.ErrPermissionDenied {
		// Expected error, test passes
		return
	} else {
		// Unexpected result, test fails
		t.Fatalf("expected permission denied error, got err: %s resp: %#v\n", err, resp)
	}

}

// A users file that was changed to plaintext passwords after the configuration was written must not allow logins
func TestPathLogin_PlaintextPasswordsInFile(t *testing.T) {
	b, storage, usersFile, _ := setupRenewBackend(t)

	plaintext := `[{"user_id":"user-martin","password":"pw","team_role":"backline"}]`
	require.NoError(t, os.WriteFile(usersFile, []byte(plaintext), 0o600))

	// Neither the plaintext value nor its hash matches, the file is not usable at all
	for _, password := range []string{"pw", ""} {
		_, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "login",
			Storage:   storage,
			Data:      map[string]interface{}{"username": "user-martin", "password": password},
		})
		require.Equal(t, logical.ErrPermissionDenied, err)
	}
}

// The alias links the login to an identity entity, its name is the user_id and it stays the same on renew
func TestPathLogin_Alias(t *testing.T) {
	b, storage, _, auth := setupRenewBackend(t)

	require.NotNil(t, auth.Alias)
	require.Equal(t, "user-martin", auth.Alias.Name)

	resp, err := renew(b, storage, auth)
	require.NoError(t, err)
	require.NotNil(t, resp.Auth.Alias)
	require.Equal(t, "user-martin", resp.Auth.Alias.Name)

	// Another user gets another alias
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   storage,
		Data:      map[string]interface{}{"username": "user-other", "password": "pw"},
	})
	require.NoError(t, err)
	require.Equal(t, "user-other", resp.Auth.Alias.Name)
}

func aliasLookahead(b logical.Backend, storage logical.Storage, data map[string]interface{}) (*logical.Response, error) {
	return b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.AliasLookaheadOperation,
		Path:      "login",
		Storage:   storage,
		Data:      data,
	})
}

// Vault asks for the alias before the credentials are checked, the answer is the username and nothing else
func TestPathLogin_AliasLookahead(t *testing.T) {
	b, storage, _, auth := setupRenewBackend(t)

	t.Run("returns the username as the alias name", func(t *testing.T) {
		resp, err := aliasLookahead(b, storage, map[string]interface{}{"username": "user-martin"})
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.NotNil(t, resp.Auth)
		require.NotNil(t, resp.Auth.Alias)
		require.Equal(t, "user-martin", resp.Auth.Alias.Name)
	})

	t.Run("is the same alias as the one of the login", func(t *testing.T) {
		resp, err := aliasLookahead(b, storage, map[string]interface{}{"username": "user-martin"})
		require.NoError(t, err)
		require.Equal(t, auth.Alias.Name, resp.Auth.Alias.Name)
	})

	t.Run("does not check the password or the user", func(t *testing.T) {
		resp, err := aliasLookahead(b, storage, map[string]interface{}{"username": "no-such-user", "password": "wrong"})
		require.NoError(t, err)
		require.Equal(t, "no-such-user", resp.Auth.Alias.Name)
	})

	t.Run("grants nothing", func(t *testing.T) {
		resp, err := aliasLookahead(b, storage, map[string]interface{}{"username": "user-martin", "password": "pw"})
		require.NoError(t, err)
		require.Empty(t, resp.Auth.Policies)
		require.Empty(t, resp.Auth.InternalData)
		require.Empty(t, resp.Auth.ClientToken)
		require.Nil(t, resp.Data)
	})

	t.Run("a missing username is an invalid request", func(t *testing.T) {
		_, err := aliasLookahead(b, storage, map[string]interface{}{})
		require.ErrorIs(t, err, logical.ErrInvalidRequest)
		_, err = aliasLookahead(b, storage, map[string]interface{}{"username": ""})
		require.ErrorIs(t, err, logical.ErrInvalidRequest)
	})

	t.Run("works without any configuration", func(t *testing.T) {
		emptyBackend, emptyStorage := getTestBackend(t)
		resp, err := aliasLookahead(emptyBackend, emptyStorage, map[string]interface{}{"username": "user-martin"})
		require.NoError(t, err)
		require.Equal(t, "user-martin", resp.Auth.Alias.Name)
	})
}

// The team of the user is reported as the group alias, Vault adds the entity to the external group with that name
func TestPathLogin_GroupAliases(t *testing.T) {
	b, storage, usersFile, auth := setupRenewBackend(t)

	t.Run("login reports the team as the group alias", func(t *testing.T) {
		require.Len(t, auth.GroupAliases, 1)
		require.Equal(t, "backline", auth.GroupAliases[0].Name)
	})

	t.Run("the entity alias carries the team role", func(t *testing.T) {
		require.Equal(t, "backline", auth.Alias.Metadata["team_role"])
	})

	t.Run("renew keeps the group alias", func(t *testing.T) {
		resp, err := renew(b, storage, auth)
		require.NoError(t, err)
		require.Len(t, resp.Auth.GroupAliases, 1)
		require.Equal(t, "backline", resp.Auth.GroupAliases[0].Name)
	})

	t.Run("a user in another team gets another group alias", func(t *testing.T) {
		users := `[{"user_id":"user-martin","password":"HASH","team_role":"manager"}]`
		require.NoError(t, os.WriteFile(usersFile, withHash(users), 0o600))
		mustRoleRequest(t, b, storage, logical.CreateOperation, "role/manager", nil)

		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "login",
			Storage:   storage,
			Data:      map[string]interface{}{"username": "user-martin", "password": "pw"},
		})
		require.NoError(t, err)
		require.Len(t, resp.Auth.GroupAliases, 1)
		require.Equal(t, "manager", resp.Auth.GroupAliases[0].Name)
		require.Equal(t, "manager", resp.Auth.Alias.Metadata["team_role"])
	})
}
