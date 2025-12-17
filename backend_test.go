package authjson

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

func getTestBackend(t *testing.T) (logical.Backend, logical.Storage) {
	defaultLeaseTTLVal := time.Hour * 12
	maxLeaseTTLVal := time.Hour * 24

	config := &logical.BackendConfig{
		Logger: nil,
		System: &logical.StaticSystemView{
			DefaultLeaseTTLVal: defaultLeaseTTLVal,
			MaxLeaseTTLVal:     maxLeaseTTLVal,
		},
		StorageView: &logical.InmemStorage{},
	}

	b := Backend(config)
	if err := b.Setup(context.Background(), config); err != nil {
		t.Fatalf("unable to create backend: %v", err)
	}

	return b, config.StorageView
}
