#!/usr/bin/env bash

set -ex

if ! command -v docker >/dev/null 2>&1 && command -v podman >/dev/null 2>&1; then
    docker() {
        podman "$@"
    }
fi

# Same version as the one of the git tag, see the Makefile
VERSION=$(make -s version)
make dev OUTPUT=./bin/vault-auth-jsonauth VERSION="$VERSION"

# Generate the users file from the template (bcrypt hashes are not committed)
DEMO_PASSWORD="hashed_password_here"
HASH=$(printf '%s' "$DEMO_PASSWORD" | go run ./cmd/hashpw -cost 10)
sed "s|REPLACE_WITH_BCRYPT_HASH|$HASH|" users.example.json > ./bin/users.json

# Killing te container if it existed, otherwise true
docker kill vaultplg 2>/dev/null || true

# Creating storage for files of Vault
tmpdir=$(mktemp -d vaultplgXXXXXX)
mkdir "$tmpdir/data"


docker pull hashicorp/vault
docker run --rm -d -p 8200:8200 --name vaultplg -v "$(pwd)/$tmpdir/data":/data -v $(pwd):/example --cap-add=IPC_LOCK -e 'VAULT_LOCAL_CONFIG=
{
  "backend": {"file": {"path": "/data"}},
  "listener": [{"tcp": {"address": "0.0.0.0:8200", "tls_disable": true}}],
  "plugin_directory": "/example/bin",
  "log_level": "debug",
  "disable_mlock": true,
  "api_addr": "http://localhost:8200"
}
' hashicorp/vault server
sleep 1

export VAULT_ADDR=http://localhost:8200

initoutput=$(vault operator init -key-shares=1 -key-threshold=1 -format=json)
vault operator unseal $(echo "$initoutput" | jq -r .unseal_keys_hex[0])

export VAULT_TOKEN=$(echo "$initoutput" | jq -r .root_token)

vault write sys/plugins/catalog/auth/vault-auth-jsonauth \
    sha_256=$(shasum -a 256 ./bin/vault-auth-jsonauth | cut -d' ' -f1) \
    command="vault-auth-jsonauth" \
    version="v$VERSION"

vault auth enable \
    -path="jsonauth" \
    -plugin-name="vault-auth-jsonauth" \
    -plugin-version="v$VERSION" \
    plugin

vault read -field=plugin_version sys/auth/jsonauth/tune

vault write auth/jsonauth/config \
    users_file_path="/example/bin/users.json"



vault write auth/jsonauth/role/core token_policies=core_policy token_max_ttl=12h token_ttl=1h
vault write auth/jsonauth/role/backline token_policies=backline_policy token_max_ttl=3h token_ttl=1h
vault write auth/jsonauth/role/manager token_policies=manager_policy token_max_ttl=36h token_ttl=1h

# Test for backline
VAULT_TOKEN=  vault write auth/jsonauth/login password="$DEMO_PASSWORD" username="user-martin"

# Test for core
VAULT_TOKEN=  vault write auth/jsonauth/login password="$DEMO_PASSWORD" username="user-khai"

# Test for manager
VAULT_TOKEN=  vault write auth/jsonauth/login password="$DEMO_PASSWORD" username="user-alex"