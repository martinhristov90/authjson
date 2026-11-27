package authjson

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/martinhristov90/authjson/internal/jsonauthhelper"
	"github.com/martinhristov90/authjson/internal/version"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

const (
	// hashPlaceholder is the value of every password in users.example.json
	hashPlaceholder = "REPLACE_WITH_BCRYPT_HASH"
	// testPassword is the password of every user of the generated test users file
	testPassword  = "hashed_password_here"
	testUsersFile = "integration_test_data/users.json"
)

// TestMain generates integration_test_data/users.json from users.example.json, so no hashes are committed.
// The generated file is git-ignored and removed when the tests finish.
func TestMain(m *testing.M) {
	cleanup, err := writeTestUsersFile()
	if err != nil {
		fmt.Fprintln(os.Stderr, "unable to generate the test users file:", err)
		os.Exit(1)
	}
	code := m.Run()
	cleanup()
	os.Exit(code)
}

func writeTestUsersFile() (func(), error) {
	template, err := os.ReadFile("users.example.json")
	if err != nil {
		return nil, err
	}
	// bcrypt.MinCost keeps the tests fast
	hash, err := jsonauthhelper.HashPassword(testPassword, bcrypt.MinCost)
	if err != nil {
		return nil, err
	}
	content := strings.ReplaceAll(string(template), hashPlaceholder, hash)
	if err := os.MkdirAll(filepath.Dir(testUsersFile), 0o755); err != nil {
		return nil, err
	}
	if err := os.WriteFile(testUsersFile, []byte(content), 0o600); err != nil {
		return nil, err
	}
	return func() { _ = os.Remove(testUsersFile) }, nil
}

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

func TestFactory(t *testing.T) {
	config := &logical.BackendConfig{
		System: &logical.StaticSystemView{
			DefaultLeaseTTLVal: time.Hour,
			MaxLeaseTTLVal:     2 * time.Hour,
		},
		StorageView: &logical.InmemStorage{},
	}

	b, err := Factory(context.Background(), config)
	require.NoError(t, err)
	require.NotNil(t, b)

	require.Equal(t, logical.TypeCredential, b.Type())
	require.Equal(t, []string{"login"}, b.SpecialPaths().Unauthenticated, "only login is open to unauthenticated requests")
	require.Equal(t, []string{configPath}, b.SpecialPaths().SealWrapStorage)

	versioner, ok := b.(logical.PluginVersioner)
	require.True(t, ok, "the backend reports its version")
	require.Equal(t, "v"+version.Version, versioner.PluginVersion().Version)

	// The paths that are routed to the backend
	for _, path := range []string{"login", "config", "role/", "role/core"} {
		require.True(t, pathIsRouted(t, b, path), "path %q is not routed", path)
	}
	require.False(t, pathIsRouted(t, b, "unknown"))
}

// pathIsRouted tells if the backend knows the path, an unknown path gives an unsupported path error
func pathIsRouted(t *testing.T, b logical.Backend, path string) bool {
	t.Helper()
	_, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.HelpOperation,
		Path:      path,
		Storage:   &logical.InmemStorage{},
	})
	return !errors.Is(err, logical.ErrUnsupportedPath)
}
