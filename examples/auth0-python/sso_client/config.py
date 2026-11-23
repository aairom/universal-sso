"""Configuration read from the environment (see ``.env.example``)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Optional
from urllib.parse import urlsplit, urlunsplit

from .errors import ConfigError

DEFAULT_GATEWAY_URL = "http://localhost:8080"
_PROVIDER_RE = re.compile(r"^[a-z0-9_-]{1,64}$")
_LOOPBACK = {"localhost", "127.0.0.1", "::1"}

Getenv = Callable[[str], Optional[str]]


@dataclass(frozen=True)
class Config:
    """Settings for talking to the Universal SSO gateway (``ssod``).

    Attributes:
        gateway_url: Base URL of ``ssod`` without a trailing slash. Plain
            ``http`` is accepted only for loopback hosts.
        provider: Provider id registered in the gateway (``auth0`` by default).
        expected_idp_host: When set, the login redirect must go to this host or
            one of its subdomains.
        timeout: Seconds bound for every HTTP request.
    """

    gateway_url: str
    provider: str
    expected_idp_host: Optional[str]
    timeout: float

    @staticmethod
    def from_lookup(getenv: Getenv, default_provider: str = "auth0") -> "Config":
        """Build a Config from ``getenv`` (testable without the real environment)."""

        def get(key: str) -> Optional[str]:
            value = getenv(key)
            value = value.strip() if value else ""
            return value or None

        raw = get("SSO_GATEWAY_URL") or DEFAULT_GATEWAY_URL
        parts = urlsplit(raw)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ConfigError("SSO_GATEWAY_URL must be an http(s) URL with a host")
        if parts.scheme == "http" and parts.hostname not in _LOOPBACK:
            raise ConfigError("SSO_GATEWAY_URL uses plain http for a non-loopback host: use https")
        gateway_url = urlunsplit((parts.scheme, parts.netloc, parts.path.rstrip("/"), "", ""))

        provider = get("SSO_PROVIDER") or default_provider
        if not _PROVIDER_RE.match(provider):
            raise ConfigError(f"SSO_PROVIDER {provider!r} must match [a-z0-9_-]{{1,64}}")

        timeout_raw = get("SSO_HTTP_TIMEOUT_SECONDS")
        timeout = 10.0
        if timeout_raw is not None:
            if not timeout_raw.isdigit() or not 1 <= int(timeout_raw) <= 300:
                raise ConfigError("SSO_HTTP_TIMEOUT_SECONDS must be an integer from 1 to 300")
            timeout = float(int(timeout_raw))

        host = get("SSO_EXPECTED_IDP_HOST")
        return Config(gateway_url, provider, host.lower() if host else None, timeout)

    def endpoint(self, path: str) -> str:
        """Absolute URL for a gateway path such as ``/healthz``."""
        return self.gateway_url + path
