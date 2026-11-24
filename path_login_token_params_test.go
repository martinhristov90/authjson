package authjson

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

// setupLoginBackend configures the plugin and creates the backline role with the given data
func setupLoginBackend(t *testing.T, roleData map[string]interface{}) (logical.Backend, logical.Storage) {
	t.Helper()
	b, storage := getTestBackend(t)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/backline",
		Storage:   storage,
		Data:      roleData,
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	_, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data:      map[string]interface{}{"users_file_path": "./integration_test_data/users.json"},
	})
	if err != nil {
		t.Fatalf("failed to set configuration: %s", err)
	}
	return b, storage
}

func loginRequest(storage logical.Storage, remoteAddr string) *logical.Request {
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   storage,
		Data: map[string]interface{}{
			"username": "user-martin",
			"password": "hashed_password_here",
		},
	}
	if remoteAddr != "" {
		req.Connection = &logical.Connection{RemoteAddr: remoteAddr}
	}
	return req
}

func TestPathLogin_BoundCIDRs(t *testing.T) {
	for _, field := range []string{"token_bound_cidrs", "bound_cidrs"} {
		t.Run(field, func(t *testing.T) {
			b, storage := setupLoginBackend(t, map[string]interface{}{field: "10.0.0.0/8"})

			resp, err := b.HandleRequest(context.Background(), loginRequest(storage, "10.1.2.3"))
			if err != nil || resp == nil || resp.Auth == nil {
				t.Fatalf("expected login from allowed address to succeed, err: %v resp: %#v", err, resp)
			}
			if len(resp.Auth.BoundCIDRs) != 1 {
				t.Fatalf("expected bound CIDRs on auth, got %v", resp.Auth.BoundCIDRs)
			}

			_, err = b.HandleRequest(context.Background(), loginRequest(storage, "192.168.1.1"))
			if err != logical.ErrPermissionDenied {
				t.Fatalf("expected permission denied from disallowed address, got %v", err)
			}

			_, err = b.HandleRequest(context.Background(), loginRequest(storage, ""))
			if err != logical.ErrPermissionDenied {
				t.Fatalf("expected permission denied without a remote address, got %v", err)
			}
		})
	}
}

func TestPathLogin_TokenParamsApplied(t *testing.T) {
	b, storage := setupLoginBackend(t, map[string]interface{}{
		"token_policies": "p1",
		"token_num_uses": 3,
		"token_period":   "1h",
		"token_type":     "service",
	})

	resp, err := b.HandleRequest(context.Background(), loginRequest(storage, ""))
	if err != nil || resp == nil || resp.Auth == nil {
		t.Fatalf("err: %v resp: %#v", err, resp)
	}
	if resp.Auth.NumUses != 3 {
		t.Fatalf("expected num_uses 3, got %d", resp.Auth.NumUses)
	}
	if resp.Auth.Period.Hours() != 1 {
		t.Fatalf("expected period 1h, got %s", resp.Auth.Period)
	}
	if resp.Auth.TokenType != logical.TokenTypeService {
		t.Fatalf("expected service token type, got %s", resp.Auth.TokenType)
	}
	if !resp.Auth.Renewable {
		t.Fatal("expected renewable auth")
	}
}

func TestPathRenew_KeepsPeriod(t *testing.T) {
	b, storage := setupLoginBackend(t, map[string]interface{}{"token_period": "1h"})

	resp, err := b.HandleRequest(context.Background(), loginRequest(storage, ""))
	if err != nil || resp == nil || resp.Auth == nil {
		t.Fatalf("err: %v resp: %#v", err, resp)
	}

	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.RenewOperation,
		Storage:   storage,
		Auth:      resp.Auth,
	})
	if err != nil || resp == nil || resp.Auth == nil {
		t.Fatalf("err: %v resp: %#v", err, resp)
	}
	if resp.Auth.Period.Hours() != 1 {
		t.Fatalf("expected period 1h after renew, got %s", resp.Auth.Period)
	}
}
