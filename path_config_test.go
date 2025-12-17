package authjson

import (
	"context"
	"github.com/hashicorp/vault/sdk/logical"
	"testing"
)

const (
	userConfigPath = "/path/to/users.json"
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
	if err != nil {
		t.Fatalf("err: %s resp: %#v\n", err, resp)
	}

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
	if err != nil {
		t.Fatalf("err: %s resp: %#v\n", err, resp)
	}

	// Verify that the read response contains the correct users_file_path
	// We are just checking that the value we wrote is the same as the one we read
	if resp.Data["users_file_path"] != userConfigPath {
		t.Fatalf("expected users_file_path to be %s, got %s", userConfigPath, resp.Data["users_file_path"])
	}

}
