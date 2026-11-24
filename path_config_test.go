package authjson

import (
	"context"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

const (
	userConfigPath      = "./integration_test_data/users.json"
	userConfigPathWrong = "./integration_test_data/usersWrongPath.json"
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

func TestPathConfigReadWriteWrongPath(t *testing.T) {
	// Get the test backend and storage instance, this is in-memory for testing purposes
	b, storage := getTestBackend(t) // getTestBackend is defined in backend_test.go
	// Prepare the data for the write operation
	data := map[string]interface{}{
		"users_file_path": userConfigPathWrong,
	}
	// Create a request for the write operation
	req := new(logical.Request)
	req.Operation = logical.UpdateOperation
	req.Storage = storage
	req.Path = configPath
	req.Data = data
	// The write must be rejected with an error response and no Go error, because the file does not exist
	resp, err := b.HandleRequest(context.Background(), req)
	assert.NoError(t, err)
	if assert.NotNil(t, resp) {
		assert.True(t, resp.IsError(), "expected error response, got %#v", resp)
		assert.Contains(t, resp.Error().Error(), "cannot load users from")
		assert.Contains(t, resp.Error().Error(), userConfigPathWrong)
	}
	// Create a request for the read operation
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Storage:   storage,
		Path:      configPath,
	}

	// Nothing must have been stored, so reading the configuration fails
	resp, err = b.HandleRequest(context.Background(), req)
	assert.Equal(t, logical.ErrInvalidRequest, err)
	if assert.NotNil(t, resp) {
		assert.True(t, resp.IsError())
	}
}
