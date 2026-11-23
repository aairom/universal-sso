.PHONY: build test test-examples test-e2e test-scripts provider-check run-example audit-dashboard start stop restart clean google-check google-url google-exchange

build:
	go build -o .run/ssod ./cmd/ssod

test:
	go vet ./... && go test -race -cover ./...

# Root tests plus every example's own suite (see Docs/Examples.md).
test-examples:
	bash tests/run_tests.sh

test-e2e:
	bash tests/e2e.sh

test-scripts:
	bash tests/scripts_test.sh

# Usage: make provider-check P=okta|auth0|azure|oauth2
provider-check:
	@test -n "$(P)" || { echo "usage: make provider-check P=okta|auth0|azure|oauth2"; exit 2; }
	scripts/provider-check.sh $(P)

# Usage: make run-example EX=rust|go|python|java|csharp [MODE=mock|e2e|real] [PROVIDER=id]
run-example:
	@test -n "$(EX)" || { echo "usage: make run-example EX=rust|go|python|java|csharp [MODE=mock|e2e|real] [PROVIDER=id]"; exit 2; }
	scripts/run-example.sh $(EX) --mode $(or $(MODE),mock) $(if $(PROVIDER),--provider $(PROVIDER))

audit-dashboard:
	python3 scripts/build_audit_dashboard.py

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
