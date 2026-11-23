import unittest

from conftest import fake_gateway
from sso_client.client import Client
from sso_client.config import Config
from sso_client.errors import APIError, LeavesGatewayError, PolicyError, TransportError


def client(base: str, provider: str) -> Client:
    env = {"SSO_GATEWAY_URL": base, "SSO_PROVIDER": provider}
    return Client(Config.from_lookup(env.get))


class ClientTest(unittest.TestCase):
    def test_health_and_providers(self) -> None:
        with fake_gateway() as base:
            c = client(base, "mock")
            c.health()
            self.assertEqual(c.providers(), ["mock", "auth0"])

    def test_mock_flow_completes_without_browser(self) -> None:
        with fake_gateway() as base:
            c = client(base, "mock")
            login = c.start_login()
            self.assertEqual(login.state, "s1")
            profile = c.follow_local(login)
            self.assertEqual(profile.provider_id, "mock")
            self.assertEqual(profile.user.email, "a@b.test")

    def test_external_idp_needs_a_browser(self) -> None:
        with fake_gateway() as base:
            c = client(base, "auth0")
            login = c.start_login()
            self.assertEqual(login.state, "s2")
            with self.assertRaises(LeavesGatewayError):
                c.follow_local(login)

    def test_missing_provider_is_structured_error(self) -> None:
        with fake_gateway() as base, self.assertRaises(APIError) as ctx:
            client(base, "missing").start_login()
        self.assertEqual((ctx.exception.status, ctx.exception.code), (404, "PROVIDER_NOT_FOUND"))

    def test_redirect_without_pkce_is_refused(self) -> None:
        with fake_gateway() as base, self.assertRaises(PolicyError):
            client(base, "weak").start_login()

    def test_non_json_error_body(self) -> None:
        with fake_gateway() as base, self.assertRaises(APIError) as ctx:
            client(base, "other").start_login()
        self.assertEqual((ctx.exception.code, ctx.exception.message), ("UNKNOWN", "boom"))

    def test_unreachable_gateway(self) -> None:
        with self.assertRaises(TransportError):
            client("http://127.0.0.1:1", "mock").health()

    def test_unhealthy_gateway(self) -> None:
        with fake_gateway() as base:
            bad = Client(Config.from_lookup({"SSO_GATEWAY_URL": base + "/nope"}.get))
            with self.assertRaises(TransportError):
                bad.health()


if __name__ == "__main__":
    unittest.main()
