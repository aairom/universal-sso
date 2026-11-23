import unittest

from sso_client.errors import APIError, SSOClientError


class ErrorsTest(unittest.TestCase):
    def test_api_error_carries_fields(self) -> None:
        e = APIError(404, "PROVIDER_NOT_FOUND", "auth0")
        self.assertEqual((e.status, e.code, e.message), (404, "PROVIDER_NOT_FOUND", "auth0"))
        self.assertIn("PROVIDER_NOT_FOUND", str(e))
        self.assertIsInstance(e, SSOClientError)


if __name__ == "__main__":
    unittest.main()
