"""Python client for the Universal SSO gateway, used here with the Auth0 provider."""

from .client import Client, Login, Profile, User
from .config import Config
from .errors import (
    APIError,
    ConfigError,
    LeavesGatewayError,
    PolicyError,
    SSOClientError,
    TransportError,
)

__all__ = [
    "APIError",
    "Client",
    "Config",
    "ConfigError",
    "LeavesGatewayError",
    "Login",
    "PolicyError",
    "Profile",
    "SSOClientError",
    "TransportError",
    "User",
]
