package authjson

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	userConfigPath      = "./integration_test_data/users.json"
	userConfigPathWrong = "./integration_test_data/usersWrongPath.json"
	userConfigPathEmpty = ""
)

func TestPathConfigReadWrite(t *testing.T) {
	// Get the test backend and storage instance, this is in-memory for testing purposes
	b, storage := getTestBackend(t) // getTestBackend is defined in backend_test.go
	// Prepare the data for the write operation
	data := map[string]interface{}{
		"users_file_path": userConfigPath,
	}
	// Create a request for the write operation
	req := new(logical.Request)
	req.Operation = logical.UpdateOperation
	req.Storage = storage
	req.Path = configPath
	req.Data = data
	// Perform the write operation
	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "write failed: %#v", resp)

	// Create a request for the read operation
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Storage:   storage,
		Path:      configPath,
		Data:      nil,
	}

	// Perform the read operation to verify the write
	// HandleRequest just handles whatever request if thrown at the backed, if it supports it of course
	resp, err = b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.False(t, resp.IsError(), "read failed %#v", resp)

	// Verify that the read response contains the correct users_file_path
	// We are just checking that the value we wrote is the same as the one we read
	assert.Equal(t, userConfigPath, resp.Data["users_file_path"])
}

func TestPathConfigReadWriteInvalidPath(t *testing.T) {
	tests := []struct{ name, path, wantErr string }{
		{"empty", userConfigPathEmpty, "users_file_path is required"},
		{"missing file", userConfigPathWrong, "cannot load users from"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Get the test backend and storage instance, this is in-memory for testing purposes
			// getTestBackend is defined in backend_test.go
			b, storage := getTestBackend(t)
			// Prepare the data for the write operation
			data := map[string]interface{}{
				"users_file_path": tt.path,
			}

			// Create a request for the write operation
			req := new(logical.Request)
			req.Operation = logical.UpdateOperation
			req.Storage = storage
			req.Path = configPath
			req.Data = data

			// The write must be rejected with an error response and no Go error
			resp, err := b.HandleRequest(context.Background(), req)
			require.NoError(t, err)
			require.NotNil(t, resp)
			require.True(t, resp.IsError(), "expected error response, got %#v", resp)
			require.Contains(t, resp.Error().Error(), tt.wantErr)

			// Create a request for the read operation
			req = &logical.Request{
				Operation: logical.ReadOperation,
				Storage:   storage,
				Path:      configPath,
			}

			// Nothing must have been stored, so reading the configuration fails
			resp, err = b.HandleRequest(context.Background(), req)
			require.NoError(t, err)
			require.NotNil(t, resp)
			require.True(t, resp.IsError())
			assert.Contains(t, resp.Error().Error(), "configuration not found")
		})
	}
}

// A users file that is malformed or fails validation is rejected when the configuration is written.
// The individual validation rules are tested in the jsonauthhelper package, here we only check that
// a failure of the loader results in an error response and that nothing is stored.
func TestPathConfigWriteInvalidUsersFile(t *testing.T) {
	tests := []struct{ name, content string }{
		{"fails validation", `[{"user_id":"a","password":"p","team_role":"r"},{"user_id":"a","password":"q","team_role":"r"}]`},
		{"malformed JSON", `[{"user_id":"a"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, storage := getTestBackend(t)

			usersFile := filepath.Join(t.TempDir(), "users.json")
			require.NoError(t, os.WriteFile(usersFile, []byte(tt.content), 0o600))

			resp, err := b.HandleRequest(context.Background(), &logical.Request{
				Operation: logical.UpdateOperation,
				Storage:   storage,
				Path:      configPath,
				Data:      map[string]interface{}{"users_file_path": usersFile},
			})
			require.NoError(t, err)
			require.NotNil(t, resp)
			require.True(t, resp.IsError(), "expected error response, got %#v", resp)
			require.Contains(t, resp.Error().Error(), "cannot load users from")
			require.Contains(t, resp.Error().Error(), usersFile)

			// Nothing must have been stored
			resp, err = b.HandleRequest(context.Background(), &logical.Request{
				Operation: logical.ReadOperation,
				Storage:   storage,
				Path:      configPath,
			})
			require.NoError(t, err)
			require.NotNil(t, resp)
			require.True(t, resp.IsError())
			assert.Contains(t, resp.Error().Error(), "configuration not found")
		})
	}
}
