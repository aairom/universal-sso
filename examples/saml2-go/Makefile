# SAML 2.0 in Go. Run `make help`.
-include .env
export

.PHONY: help build test run check login login-mock clean

help:
	@echo "targets: build test check login login-mock clean"

build:
	go build -o bin/saml2-go .

test:
	go vet ./... && go test -race -cover ./...

check:
	go run . check

login:
	go run . login

login-mock:
	SSO_PROVIDER=mock go run . login -follow

clean:
	rm -rf bin
