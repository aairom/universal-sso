# Okta in Java. Run `make help`.
-include .env
export

.PHONY: help build test run check login login-mock clean

help:
	@echo "targets: build test check login login-mock clean"

build:
	mvn -q -B package -DskipTests

test:
	mvn -B test

check:
	mvn -q -B package -DskipTests && java -cp "target/classes:target/lib/*" com.universalsso.client.Main check

login:
	mvn -q -B package -DskipTests && java -cp "target/classes:target/lib/*" com.universalsso.client.Main login

login-mock:
	SSO_PROVIDER=mock mvn -q -B package -DskipTests && java -cp "target/classes:target/lib/*" com.universalsso.client.Main login --follow

clean:
	mvn -q -B clean
