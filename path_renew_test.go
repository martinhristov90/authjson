package authjson

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/martinhristov90/authjson/internal/jsonauthhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func TestPathRenew(t *testing.T) {
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

	// Testing if login operation can be renewed
	renewReq := &logical.Request{
		Operation: logical.RenewOperation,
		Storage:   storage,
		Auth:      resp.Auth,
	}
	// Perform the renew operation
	resp, err = b.HandleRequest(context.Background(), renewReq)
	if err != nil {
		t.Fatalf("err: %s resp: %#v\n", err, resp)
	}
}

// The hash of the password "pw", with the lowest cost to keep the tests fast
var renewTestHash = func() string {
	hash, err := jsonauthhelper.HashPassword("pw", bcrypt.MinCost)
	if err != nil {
		panic(err)
	}
	return hash
}()

// withHash replaces the HASH placeholder of the test users files with the bcrypt hash of "pw"
func withHash(content string) []byte {
	return []byte(strings.ReplaceAll(content, "HASH", renewTestHash))
}

const renewTestUsers = `[
{"user_id":"user-martin","email":"m@example.com","password":"HASH","given_name":"Martin","family_name":"H","nickname":"M","team_role":"backline"},
{"user_id":"user-other","email":"o@example.com","password":"HASH","given_name":"Other","family_name":"U","nickname":"O","team_role":"backline"}
]`

// setupRenewBackend configures a backend that uses a users file we are able to modify, and logs user-martin in
func setupRenewBackend(t *testing.T) (logical.Backend, logical.Storage, string, *logical.Auth) {
	t.Helper()
	b, storage := getTestBackend(t)

	usersFile := filepath.Join(t.TempDir(), "users.json")
	require.NoError(t, os.WriteFile(usersFile, withHash(renewTestUsers), 0o600))

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/backline",
		Storage:   storage,
		Data:      map[string]interface{}{},
	})
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "role creation failed: %#v", resp)

	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data:      map[string]interface{}{"users_file_path": usersFile},
	})
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "config failed: %#v", resp)

	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   storage,
		Data:      map[string]interface{}{"username": "user-martin", "password": "pw"},
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotNil(t, resp.Auth)

	return b, storage, usersFile, resp.Auth
}

func renew(b logical.Backend, storage logical.Storage, auth *logical.Auth) (*logical.Response, error) {
	return b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.RenewOperation,
		Storage:   storage,
		Auth:      auth,
	})
}

func TestPathRenew_UserStillPresent(t *testing.T) {
	b, storage, _, auth := setupRenewBackend(t)

	resp, err := renew(b, storage, auth)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotNil(t, resp.Auth)
}

func TestPathRenew_UserRemovedFromFile(t *testing.T) {
	b, storage, usersFile, auth := setupRenewBackend(t)

	// Only the other user is left in the file
	remaining := `[{"user_id":"user-other","password":"HASH","team_role":"backline"}]`
	require.NoError(t, os.WriteFile(usersFile, withHash(remaining), 0o600))

	_, err := renew(b, storage, auth)
	assert.Equal(t, logical.ErrPermissionDenied, err)
}

func TestPathRenew_UserChangedTeam(t *testing.T) {
	b, storage, usersFile, auth := setupRenewBackend(t)

	moved := `[{"user_id":"user-martin","password":"HASH","team_role":"manager"}]`
	require.NoError(t, os.WriteFile(usersFile, withHash(moved), 0o600))

	_, err := renew(b, storage, auth)
	assert.Equal(t, logical.ErrPermissionDenied, err)
}

func TestPathRenew_UsersFileUnreadable(t *testing.T) {
	b, storage, usersFile, auth := setupRenewBackend(t)

	require.NoError(t, os.Remove(usersFile))

	_, err := renew(b, storage, auth)
	assert.Equal(t, logical.ErrPermissionDenied, err)
}

func TestPathRenew_MissingInternalData(t *testing.T) {
	b, storage, _, auth := setupRenewBackend(t)

	// Tokens issued before user_id was stored cannot be renewed
	delete(auth.InternalData, "user_id")
	_, err := renew(b, storage, auth)
	assert.Equal(t, logical.ErrPermissionDenied, err)

	auth.InternalData = map[string]interface{}{}
	_, err = renew(b, storage, auth)
	assert.Equal(t, logical.ErrPermissionDenied, err)
}

func TestPathRenew_RoleDeleted(t *testing.T) {
	b, storage, _, auth := setupRenewBackend(t)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "role/backline",
		Storage:   storage,
	})
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError())

	_, err = renew(b, storage, auth)
	assert.Equal(t, logical.ErrPermissionDenied, err)
}
