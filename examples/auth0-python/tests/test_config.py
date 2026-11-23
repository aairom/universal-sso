import unittest

from sso_client.config import Config
from sso_client.errors import ConfigError


def lookup(**kw: str):
    return lambda k: kw.get(k)


class ConfigTest(unittest.TestCase):
    def test_defaults(self) -> None:
        c = Config.from_lookup(lookup())
        self.assertEqual(c.gateway_url, "http://localhost:8080")
        self.assertEqual(c.provider, "auth0")
        self.assertEqual(c.timeout, 10.0)
        self.assertIsNone(c.expected_idp_host)
        self.assertEqual(c.endpoint("/healthz"), "http://localhost:8080/healthz")

    def test_invalid_values(self) -> None:
        for env in (
            {"SSO_GATEWAY_URL": "ftp://x"},
            {"SSO_GATEWAY_URL": "http://gateway.example.test"},
            {"SSO_PROVIDER": "Bad Provider"},
            {"SSO_HTTP_TIMEOUT_SECONDS": "0"},
            {"SSO_HTTP_TIMEOUT_SECONDS": "abc"},
            {"SSO_HTTP_TIMEOUT_SECONDS": "301"},
        ):
            with self.subTest(env=env), self.assertRaises(ConfigError):
                Config.from_lookup(lookup(**env))

    def test_normalization(self) -> None:
        c = Config.from_lookup(
            lookup(SSO_GATEWAY_URL="https://sso.example.test/base/?x=1", SSO_EXPECTED_IDP_HOST=" IdP.Example.Test ", SSO_PROVIDER="okta")
        )
        self.assertEqual(c.gateway_url, "https://sso.example.test/base")
        self.assertEqual(c.expected_idp_host, "idp.example.test")
        self.assertEqual(c.provider, "okta")


if __name__ == "__main__":
    unittest.main()
