"""Exception types for the gateway client."""

from __future__ import annotations


class SSOClientError(Exception):
    """Base class for every error raised by this package."""


class ConfigError(SSOClientError):
    """A configuration value is missing or invalid."""


class TransportError(SSOClientError):
    """The gateway or network could not be reached, or the reply was unusable."""


class PolicyError(SSOClientError):
    """The login redirect failed the client-side safety policy."""


class LeavesGatewayError(SSOClientError):
    """The flow needs a browser because a redirect leaves the gateway host."""


class APIError(SSOClientError):
    """The gateway answered with its structured error body.

    Attributes:
        status: HTTP status code.
        code: Machine-readable code such as ``PROVIDER_NOT_FOUND``.
        message: Human-readable message.
    """

    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(f"gateway error {status} [{code}]: {message}")
        self.status = status
        self.code = code
        self.message = message
