import unittest

from sso_client.errors import PolicyError
from sso_client.policy import check_authorize_url

GW = "http://localhost:8080"
GOOD = "https://tenant.example.test/authorize?state=abc&code_challenge=x&code_challenge_method=S256"


class PolicyTest(unittest.TestCase):
    def test_accepts_good_redirect(self) -> None:
        self.assertEqual(check_authorize_url(GOOD, GW, "example.test"), "abc")

    def test_accepts_gateway_local_http(self) -> None:
        local = "http://localhost:8080/mock/authorize?state=a&code_challenge=x&code_challenge_method=S256"
        self.assertEqual(check_authorize_url(local, GW), "a")

    def test_refuses_unsafe_redirects(self) -> None:
        cases = {
            "scheme": "javascript:alert(1)",
            "plain http": "http://tenant.example.test/a?state=a&code_challenge=x&code_challenge_method=S256",
            "wrong host": "https://evil.test/a?state=a&code_challenge=x&code_challenge_method=S256",
            "look-alike": "https://notexample.test/a?state=a&code_challenge=x&code_challenge_method=S256",
            "no state": "https://tenant.example.test/a?code_challenge=x&code_challenge_method=S256",
            "no pkce": "https://tenant.example.test/a?state=a",
            "plain pkce": "https://tenant.example.test/a?state=a&code_challenge=x&code_challenge_method=plain",
        }
        for name, url in cases.items():
            with self.subTest(name), self.assertRaises(PolicyError):
                check_authorize_url(url, GW, "example.test")


if __name__ == "__main__":
    unittest.main()
