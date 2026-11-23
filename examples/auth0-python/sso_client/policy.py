"""Client-side safety policy for the authorization redirect.

The gateway owns the signed state, the PKCE verifier and the client secret.
This client only checks that the redirect it is about to hand to a browser is
sane for an OAuth 2.0 / OIDC authorization-code flow (Auth0 uses one).
"""

from __future__ import annotations

from typing import Optional
from urllib.parse import parse_qs, urlsplit

from .errors import PolicyError


def check_authorize_url(redirect: str, gateway_url: str, expected_host: Optional[str] = None) -> str:
    """Verify ``redirect`` and return the ``state`` value it carries.

    Rules:
        * the scheme is ``http`` or ``https``, and ``https`` is required unless
          the redirect stays on the gateway's own host (the mock provider);
        * when ``expected_host`` is set, the host equals it or is a subdomain;
        * ``state`` is present and non-empty;
        * PKCE is in use: ``code_challenge`` present and
          ``code_challenge_method`` is ``S256``.

    Raises:
        PolicyError: when any rule is violated.
    """
    u = urlsplit(redirect)
    if u.scheme not in ("http", "https"):
        raise PolicyError(f"scheme {u.scheme!r} is not http or https")
    if u.netloc != urlsplit(gateway_url).netloc and u.scheme != "https":
        raise PolicyError("external identity provider must use https")
    if expected_host:
        host = (u.hostname or "").lower()
        if host != expected_host and not host.endswith("." + expected_host):
            raise PolicyError(f"host {host!r} is not {expected_host!r} or a subdomain")
    q = parse_qs(u.query)

    def first(name: str) -> str:
        return (q.get(name) or [""])[0]

    state = first("state")
    if not state:
        raise PolicyError("redirect has no state parameter")
    if not first("code_challenge") or first("code_challenge_method") != "S256":
        raise PolicyError("redirect does not use PKCE with S256")
    return state
