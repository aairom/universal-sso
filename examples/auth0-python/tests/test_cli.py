import io
import unittest

from conftest import fake_gateway
from sso_client.cli import run


def call(args, base="http://127.0.0.1:1", provider="mock"):
    env = {"SSO_GATEWAY_URL": base, "SSO_PROVIDER": provider}
    out, err = io.StringIO(), io.StringIO()
    code = run(args, env.get, out, err)
    return code, out.getvalue(), err.getvalue()


class CliTest(unittest.TestCase):
    def test_usage_and_bad_input(self) -> None:
        self.assertEqual(call([])[0], 2)
        self.assertEqual(call(["bogus"])[0], 2)
        self.assertEqual(call(["login", "--nope"])[0], 2)
        self.assertEqual(call(["check"], base="ftp://x")[0], 2)

    def test_check(self) -> None:
        with fake_gateway() as base:
            code, out, _ = call(["check"], base)
            self.assertEqual(code, 0)
            self.assertIn("providers: mock, auth0", out)
            code, _, err = call(["check"], base, provider="saml")
            self.assertEqual(code, 1)
            self.assertIn("not registered", err)
        self.assertEqual(call(["check"])[0], 1)

    def test_login(self) -> None:
        with fake_gateway() as base:
            code, out, _ = call(["login"], base, "auth0")
            self.assertEqual(code, 0)
            self.assertIn("https://tenant.example.test/authorize", out)
            code, out, _ = call(["login", "--follow"], base, "mock")
            self.assertEqual(code, 0)
            self.assertIn("signed in via mock as Mock User", out)
            code, _, err = call(["login", "--follow"], base, "auth0")
            self.assertEqual(code, 1)
            self.assertIn("open the URL in a browser", err)
            code, _, err = call(["login"], base, "missing")
            self.assertEqual(code, 1)
            self.assertIn("no such provider", err)
            code, _, err = call(["login"], base, "weak")
            self.assertEqual(code, 1)
            self.assertIn("refused to continue", err)
            code, _, err = call(["login"], base, "other")
            self.assertEqual(code, 1)
            self.assertIn("login failed", err)


if __name__ == "__main__":
    unittest.main()
