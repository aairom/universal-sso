"""HTTP client for the Universal SSO gateway (standard library only).

Contract (see ``cmd/ssod/handler.go``)::

    GET /healthz                   -> 200 {"status":"ok"}
    GET /providers                 -> 200 {"providers":[...]}
    GET /auth/{provider}/login     -> 302 Location: <IdP authorization URL>
    GET /auth/{provider}/callback  -> 200 {"provider_id":"...","user":{...}}
    any error                      -> {"code":"...","message":"..."}
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, List, Optional, Tuple

from .config import Config
from .errors import APIError, LeavesGatewayError, TransportError
from .policy import check_authorize_url

log = logging.getLogger("sso_client")

MAX_BODY = 1 << 20
MAX_HOPS = 5


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Stop urllib from following redirects so every hop can be checked."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:  # noqa: D401
        return None


@dataclass(frozen=True)
class User:
    """Normalized user profile returned by the gateway callback."""

    id: str
    email: str = ""
    email_verified: bool = False
    display_name: str = ""
    roles: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class Profile:
    """Body of a successful callback."""

    provider_id: str
    user: User


@dataclass(frozen=True)
class Login:
    """A started sign-in: where the browser must go and the gateway's state."""

    authorize_url: str
    state: str


class Client:
    """Gateway client. Create one per configuration; it is thread-safe."""

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self._opener = urllib.request.build_opener(_NoRedirect)

    def _get(self, url: str) -> Tuple[int, Optional[str], bytes]:
        """GET ``url`` and return (status, Location header, body)."""
        req = urllib.request.Request(url, headers={"Accept": "application/json"}, method="GET")
        try:
            resp = self._opener.open(req, timeout=self.cfg.timeout)
        except urllib.error.HTTPError as e:  # 3xx (not followed) and 4xx/5xx land here
            resp = e
        except (urllib.error.URLError, OSError, ValueError) as e:
            raise TransportError(f"request failed: {e}") from e
        try:
            body = resp.read(MAX_BODY)
            return resp.status, resp.headers.get("Location"), body
        finally:
            resp.close()

    @staticmethod
    def _api_error(status: int, body: bytes) -> APIError:
        try:
            data = json.loads(body)
            code, message = str(data["code"]), str(data.get("message", ""))
        except (ValueError, KeyError, TypeError):
            code, message = "UNKNOWN", body.decode("utf-8", "replace").strip()[:200]
        return APIError(status, code, message)

    def health(self) -> None:
        """Return normally when the gateway reports ``{"status":"ok"}``."""
        status, _, body = self._get(self.cfg.endpoint("/healthz"))
        try:
            ok = status == 200 and json.loads(body).get("status") == "ok"
        except (ValueError, AttributeError):
            ok = False
        if not ok:
            raise TransportError(f"gateway not healthy: HTTP {status}")

    def providers(self) -> List[str]:
        """List the provider ids registered in the gateway."""
        status, _, body = self._get(self.cfg.endpoint("/providers"))
        if status != 200:
            raise self._api_error(status, body)
        try:
            return [str(p) for p in json.loads(body)["providers"]]
        except (ValueError, KeyError, TypeError) as e:
            raise TransportError(f"decode providers: {e}") from e

    def start_login(self) -> Login:
        """Ask the gateway to begin a sign-in and validate the redirect.

        Raises:
            APIError: the gateway refused (for example ``PROVIDER_NOT_FOUND``).
            PolicyError: the redirect failed the safety policy.
        """
        path = "/auth/" + urllib.parse.quote(self.cfg.provider, safe="") + "/login"
        status, location, body = self._get(self.cfg.endpoint(path))
        if status not in (302, 303):
            raise self._api_error(status, body)
        if not location:
            raise TransportError("gateway redirect has no Location header")
        target = urllib.parse.urljoin(self.cfg.gateway_url + "/", location)
        state = check_authorize_url(target, self.cfg.gateway_url, self.cfg.expected_idp_host)
        log.info("login started provider=%s idp_host=%s", self.cfg.provider, urllib.parse.urlsplit(target).netloc)
        return Login(target, state)

    def _same_host(self, url: str) -> bool:
        return urllib.parse.urlsplit(url).netloc == urllib.parse.urlsplit(self.cfg.gateway_url).netloc

    def follow_local(self, login: Login) -> Profile:
        """Complete a sign-in without a browser while redirects stay on the gateway host.

        That holds for the mock provider, which is why it is used for tests and
        demos. A real identity provider needs a person at a browser.

        Raises:
            LeavesGatewayError: a redirect points at another host.
        """
        nxt = login.authorize_url
        if not self._same_host(nxt):
            raise LeavesGatewayError("redirect leaves the gateway host: open the URL in a browser")
        for _ in range(MAX_HOPS):
            status, location, body = self._get(nxt)
            if status == 200:
                try:
                    data = json.loads(body)
                    u = data["user"]
                    if not u.get("id"):
                        raise KeyError("id")
                    user = User(
                        id=str(u["id"]),
                        email=str(u.get("email", "")),
                        email_verified=bool(u.get("email_verified", False)),
                        display_name=str(u.get("display_name", "")),
                        roles=[str(r) for r in u.get("roles", [])],
                    )
                    return Profile(str(data["provider_id"]), user)
                except (ValueError, KeyError, TypeError, AttributeError) as e:
                    raise TransportError("callback response is not a profile") from e
            if status != 302 or not location:
                raise self._api_error(status, body)
            nxt = urllib.parse.urljoin(nxt, location)
            if not self._same_host(nxt):
                raise LeavesGatewayError("redirect leaves the gateway host: open the URL in a browser")
        raise TransportError("too many redirects")
