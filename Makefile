
GOOS ?= 'linux'

.PHONY: default
default: dev

.PHONY: dev
dev:
	# CGO_ENABLED disables usage of C libraries
	CGO_ENABLED=0 GOOS=$(GOOS) go build -o vault-auth-jsonauth cmd/jsonauth/main.go

.PHONY: setup-intergration-test
setup-intergration-test: 
	./docker-test.sh