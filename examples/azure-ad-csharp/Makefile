export DOTNET_CLI_TELEMETRY_OPTOUT=1
export DOTNET_NOLOGO=1
# Azure AD / Microsoft Entra ID in C#. Run `make help`.
-include .env
export

.PHONY: help build test run check login login-mock clean

help:
	@echo "targets: build test check login login-mock clean"

build:
	dotnet build -c Release src

test:
	dotnet test tests

check:
	dotnet run --project src -- check

login:
	dotnet run --project src -- login

login-mock:
	SSO_PROVIDER=mock dotnet run --project src -- login --follow

clean:
	rm -rf src/bin src/obj tests/bin tests/obj
