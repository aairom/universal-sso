.PHONY: build test start stop restart clean google-check google-url google-exchange

build:
	go build -o .run/ssod ./cmd/ssod

test:
	go vet ./... && go test -race -cover ./...

start:
	scripts/start.sh

stop:
	scripts/stop.sh

restart: stop start

clean:
	scripts/cleanup.sh

# Google setup helpers (see Docs/Google-SSO-Setup.md, "Start here").
google-check:
	go run ./cmd/ssoctl google check

google-url:
	go run ./cmd/ssoctl google url

# Usage: make google-exchange CODE='<full redirected URL or bare code>'
google-exchange:
	@test -n "$(CODE)" || { echo "usage: make google-exchange CODE='<full redirected URL>'"; exit 2; }
	go run ./cmd/ssoctl google exchange "$(CODE)"
