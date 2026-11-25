
GOOS ?= 'linux'
OUTPUT ?= vault-auth-jsonauth
# Version comes from the nearest git tag (a leading "v" is dropped), Vault requires a valid semver.
# Without a tag it falls back to 0.0.0-dev-<commit>
VERSION ?= $(shell v=$$(git describe --tags --always --dirty 2>/dev/null | sed 's/^v//'); echo "$$v" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+' && echo "$$v" || echo "0.0.0-dev-$$v")
COMMIT  ?= $(shell git rev-parse --short HEAD)
PKG      = github.com/martinhristov90/authjson/internal/version
LDFLAGS  = -X $(PKG).Version=$(VERSION) -X $(PKG).GitCommit=$(COMMIT)

.PHONY: default
default: dev

.PHONY: dev
dev:
	# CGO_ENABLED disables usage of C libraries
	CGO_ENABLED=0 GOOS=$(GOOS) go build -ldflags "${LDFLAGS}" -o $(OUTPUT) cmd/jsonauth/main.go

.PHONY: version
version:
	@echo $(VERSION)

.PHONY: setup-intergration-test
setup-intergration-test: 
	./docker-test.sh
