# Generic OAuth 2.0 in Rust. Run `make help`.
-include .env
export

.PHONY: help build test run check login login-mock clean

help:
	@echo "targets: build test check login login-mock clean"

build:
	cargo build --release

test:
	cargo clippy --all-targets -- -D warnings && cargo test

check:
	cargo run --quiet -- check

login:
	cargo run --quiet -- login

login-mock:
	SSO_PROVIDER=mock cargo run --quiet -- login --follow

clean:
	cargo clean
