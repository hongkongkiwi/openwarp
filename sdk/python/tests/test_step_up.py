import json
import unittest
from unittest.mock import patch

from openwarp import OpenWarp


class Response:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def read(self):
        return b'{"ok":true}'


class StepUpTests(unittest.TestCase):
    def test_explicit_grant_uses_dedicated_header_without_replacing_bearer(self):
        client = OpenWarp("https://example.invalid", "original-bearer")
        with patch("openwarp.client.build_opener") as build:
            build.return_value.open.return_value = Response()
            self.assertEqual(client.api("POST", ["incoming-webhooks", "hook", "reauthorize"], body={}, step_up="stepupg_safe-grant"), {"ok": True})
            request = build.return_value.open.call_args.args[0]
            headers = {key.lower(): value for key, value in request.header_items()}
            self.assertEqual(headers["x-openwarp-step-up"], "stepupg_safe-grant")
            self.assertEqual(headers["authorization"], "Bearer original-bearer")
            self.assertEqual(json.loads(request.data), {})
            client.api("GET", ["me"])
            request = build.return_value.open.call_args.args[0]
            self.assertNotIn("x-openwarp-step-up", {key.lower(): value for key, value in request.header_items()})

    def test_invalid_grants_fail_before_request(self):
        for grant in ("", "x\r\nAuthorization: forged", "x\0", "x\x1f", "x\x7f", "é", "x" * 513):
            with self.subTest(grant=repr(grant)):
                client = OpenWarp("https://example.invalid", "original-bearer")
                with patch.object(client, "_request") as request:
                    with self.assertRaises(ValueError):
                        client.api("POST", ["orgs"], body={}, step_up=grant)
                    request.assert_not_called()
