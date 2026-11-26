package authjson

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

// roleRequest sends a request to the role paths of the backend
func roleRequest(t *testing.T, b logical.Backend, storage logical.Storage, op logical.Operation, path string, data map[string]interface{}) (*logical.Response, error) {
	t.Helper()
	return b.HandleRequest(context.Background(), &logical.Request{
		Operation: op,
		Path:      path,
		Storage:   storage,
		Data:      data,
	})
}

func mustRoleRequest(t *testing.T, b logical.Backend, storage logical.Storage, op logical.Operation, path string, data map[string]interface{}) *logical.Response {
	t.Helper()
	resp, err := roleRequest(t, b, storage, op, path, data)
	require.NoError(t, err)
	if resp != nil {
		require.False(t, resp.IsError(), "unexpected error response: %v", resp.Error())
	}
	return resp
}

func TestPathRole_CreateReadUpdateDelete(t *testing.T) {
	b, storage := getTestBackend(t)

	mustRoleRequest(t, b, storage, logical.CreateOperation, "role/backline", map[string]interface{}{
		"token_policies": "p2,p1,p2",
		"token_ttl":      "1h",
		"token_max_ttl":  "3h",
	})

	resp := mustRoleRequest(t, b, storage, logical.ReadOperation, "role/backline", nil)
	require.NotNil(t, resp)
	require.Equal(t, []string{"p1", "p2"}, resp.Data["token_policies"], "policies are sorted and deduplicated")
	require.EqualValues(t, 3600, resp.Data["token_ttl"])
	require.EqualValues(t, 3*3600, resp.Data["token_max_ttl"])

	// An update changes only what is given
	mustRoleRequest(t, b, storage, logical.UpdateOperation, "role/backline", map[string]interface{}{"token_ttl": "30m"})
	resp = mustRoleRequest(t, b, storage, logical.ReadOperation, "role/backline", nil)
	require.EqualValues(t, 1800, resp.Data["token_ttl"])
	require.EqualValues(t, 3*3600, resp.Data["token_max_ttl"])
	require.Equal(t, []string{"p1", "p2"}, resp.Data["token_policies"])

	mustRoleRequest(t, b, storage, logical.DeleteOperation, "role/backline", nil)
	resp = mustRoleRequest(t, b, storage, logical.ReadOperation, "role/backline", nil)
	require.Nil(t, resp, "a deleted role is not found")
}

func TestPathRole_ReadMissing(t *testing.T) {
	b, storage := getTestBackend(t)
	resp := mustRoleRequest(t, b, storage, logical.ReadOperation, "role/nope", nil)
	require.Nil(t, resp)
}

func TestPathRole_DeleteMissingIsNotAnError(t *testing.T) {
	b, storage := getTestBackend(t)
	mustRoleRequest(t, b, storage, logical.DeleteOperation, "role/nope", nil)
}

func TestPathRole_UpdateMissingFails(t *testing.T) {
	b, storage := getTestBackend(t)
	_, err := roleRequest(t, b, storage, logical.UpdateOperation, "role/nope", map[string]interface{}{"token_ttl": "1h"})
	require.ErrorContains(t, err, "does not exists")

	resp := mustRoleRequest(t, b, storage, logical.ReadOperation, "role/nope", nil)
	require.Nil(t, resp, "a failed update must not create the role")
}

func TestPathRole_NamesAreCaseInsensitive(t *testing.T) {
	b, storage := getTestBackend(t)
	mustRoleRequest(t, b, storage, logical.CreateOperation, "role/Core", map[string]interface{}{"token_policies": "p"})

	resp := mustRoleRequest(t, b, storage, logical.ReadOperation, "role/core", nil)
	require.NotNil(t, resp)
	resp = mustRoleRequest(t, b, storage, logical.ReadOperation, "role/CORE", nil)
	require.NotNil(t, resp)

	mustRoleRequest(t, b, storage, logical.DeleteOperation, "role/cORE", nil)
	resp = mustRoleRequest(t, b, storage, logical.ReadOperation, "role/core", nil)
	require.Nil(t, resp)
}

func TestPathRole_DeprecatedFieldsAreUpgraded(t *testing.T) {
	b, storage := getTestBackend(t)
	mustRoleRequest(t, b, storage, logical.CreateOperation, "role/old", map[string]interface{}{
		"policies": "p1",
		"ttl":      "10m",
		"max_ttl":  "20m",
	})

	resp := mustRoleRequest(t, b, storage, logical.ReadOperation, "role/old", nil)
	require.Equal(t, []string{"p1"}, resp.Data["token_policies"])
	require.EqualValues(t, 600, resp.Data["token_ttl"])
	require.EqualValues(t, 1200, resp.Data["token_max_ttl"])
}

func TestPathRole_InvalidTokenFieldsAreRejected(t *testing.T) {
	b, storage := getTestBackend(t)

	// token_ttl above token_max_ttl
	_, err := roleRequest(t, b, storage, logical.CreateOperation, "role/bad", map[string]interface{}{
		"token_ttl":     "2h",
		"token_max_ttl": "1h",
	})
	require.Error(t, err)

	// not a CIDR
	_, err = roleRequest(t, b, storage, logical.CreateOperation, "role/bad", map[string]interface{}{
		"token_bound_cidrs": "not-a-cidr",
	})
	require.Error(t, err)

	resp := mustRoleRequest(t, b, storage, logical.ReadOperation, "role/bad", nil)
	require.Nil(t, resp, "a rejected role is not stored")
}

func TestPathRole_List(t *testing.T) {
	b, storage := getTestBackend(t)

	resp := mustRoleRequest(t, b, storage, logical.ListOperation, "role/", nil)
	require.Empty(t, resp.Data["keys"])

	for _, name := range []string{"manager", "core", "backline"} {
		mustRoleRequest(t, b, storage, logical.CreateOperation, "role/"+name, nil)
	}

	resp = mustRoleRequest(t, b, storage, logical.ListOperation, "role/", nil)
	require.Equal(t, []string{"backline", "core", "manager"}, resp.Data["keys"])

	mustRoleRequest(t, b, storage, logical.DeleteOperation, "role/core", nil)
	resp = mustRoleRequest(t, b, storage, logical.ListOperation, "role/", nil)
	require.Equal(t, []string{"backline", "manager"}, resp.Data["keys"])
}

func TestPathRole_ExistenceCheck(t *testing.T) {
	b, storage := getTestBackend(t)
	check := func() bool {
		t.Helper()
		_, exists, err := b.HandleExistenceCheck(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "role/core",
			Storage:   storage,
		})
		require.NoError(t, err)
		return exists
	}

	require.False(t, check())
	mustRoleRequest(t, b, storage, logical.CreateOperation, "role/core", nil)
	require.True(t, check())
	mustRoleRequest(t, b, storage, logical.DeleteOperation, "role/core", nil)
	require.False(t, check())
}

// Run with -race, the updates of the same role must be serialised by the backend lock
func TestPathRole_ConcurrentUpdates(t *testing.T) {
	b, storage := getTestBackend(t)
	mustRoleRequest(t, b, storage, logical.CreateOperation, "role/busy", map[string]interface{}{
		"token_policies": "p",
		"token_max_ttl":  "100h",
	})

	const workers = 20
	var wg sync.WaitGroup
	errs := make(chan error, workers*2)
	for i := 1; i <= workers; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			_, err := roleRequest(t, b, storage, logical.UpdateOperation, "role/busy", map[string]interface{}{
				"token_ttl": fmt.Sprintf("%ds", i*60),
			})
			errs <- err
		}(i)
		go func() {
			defer wg.Done()
			_, err := roleRequest(t, b, storage, logical.ReadOperation, "role/busy", nil)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}

	// The final value is one of the written ones, and the rest of the role is intact
	resp := mustRoleRequest(t, b, storage, logical.ReadOperation, "role/busy", nil)
	ttl, ok := resp.Data["token_ttl"].(int64)
	require.True(t, ok, "token_ttl has type %T", resp.Data["token_ttl"])
	require.Zero(t, ttl%60)
	require.GreaterOrEqual(t, ttl, int64(60))
	require.LessOrEqual(t, ttl, int64(workers*60))
	require.Equal(t, []string{"p"}, resp.Data["token_policies"])
}
