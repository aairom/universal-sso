# Auth0 in Python. Run `make help`.
-include .env
export

.PHONY: help build test run check login login-mock clean

help:
	@echo "targets: build test check login login-mock clean"

build:
	(nothing to build)

test:
	python3 -m unittest discover -s tests

check:
	python3 -m sso_client.cli check

login:
	python3 -m sso_client.cli login

login-mock:
	SSO_PROVIDER=mock python3 -m sso_client.cli login --follow

clean:
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
