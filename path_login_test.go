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
