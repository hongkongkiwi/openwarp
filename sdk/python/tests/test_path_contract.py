import json
import os
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from openwarp import OpenWarp, OpenWarpError


TOKEN = "path-contract-dummy-token"
SECRETS = [
    {"id": "other", "key": "OTHER", "path": "/team/", "value": "dummy-other"},
    {"id": "folder", "key": "API_KEY", "path": "/team/", "value": "dummy-folder"},
    {"id": "nested", "key": "API_KEY", "path": "/team/nested/", "value": "dummy-nested"},
    {"id": "root", "key": "API_KEY", "path": "/", "value": "dummy-root"},
]


class PathHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def handle_request(self):
        self.server.calls.append((self.command, self.path,
                                  self.headers.get("Authorization")))
        if self.headers.get("Authorization") != f"Bearer {TOKEN}":
            status, body = 401, {"error": "unauthorized"}
        elif self.command == "GET" and self.path == "/api/envs/env/secrets":
            status, body = 200, {"secrets": self.server.secrets}
        elif self.command == "DELETE" and self.path in {
                f"/api/secrets/{secret['id']}" for secret in self.server.secrets}:
            status, body = 200, {"deleted": True}
        else:
            status, body = 404, {"error": "unexpected fixture route"}
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = do_DELETE = handle_request


class PathContractTests(unittest.TestCase):
    def setUp(self):
        self.proxy_env = patch.dict(os.environ, {
            "HTTP_PROXY": "", "HTTPS_PROXY": "", "ALL_PROXY": "",
            "http_proxy": "", "https_proxy": "", "all_proxy": "",
            "NO_PROXY": "*", "no_proxy": "*",
        })
        self.proxy_env.start()
        self.addCleanup(self.proxy_env.stop)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), PathHandler)
        self.server.calls = []
        self.server.secrets = list(SECRETS)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.client = OpenWarp(f"http://127.0.0.1:{self.server.server_port}", TOKEN, timeout=2)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def assert_calls(self, *requests):
        self.assertEqual(self.server.calls, [
            (method, path, f"Bearer {TOKEN}") for method, path in requests
        ])

    def test_key_only_get_rejects_ambiguity_instead_of_returning_first_value(self):
        with self.assertRaises(OpenWarpError) as caught:
            self.client.get_secret("env", "api_key")
        self.assertEqual(caught.exception.status, 409)
        self.assertIn("ambig", caught.exception.message.lower())
        self.assert_calls(("GET", "/api/envs/env/secrets"))

    def test_key_only_delete_rejects_ambiguity_without_delete(self):
        with self.assertRaises(OpenWarpError) as caught:
            self.client.delete_secret("env", "api_key")
        self.assertEqual(caught.exception.status, 409)
        self.assertIn("ambig", caught.exception.message.lower())
        self.assert_calls(("GET", "/api/envs/env/secrets"))

    def test_explicit_root_and_folder_select_exact_path_and_case_insensitive_key(self):
        for path, secret_id in [("/", "root"), ("/team/", "folder")]:
            with self.subTest(path=path):
                self.server.calls.clear()
                expected = next(s for s in SECRETS if s["id"] == secret_id)
                self.assertEqual(self.client.get_secret("env", "aPi_KeY", path=path), expected)
                self.client.delete_secret("env", "aPi_KeY", path=path)
                self.assert_calls(("GET", "/api/envs/env/secrets"),
                                  ("GET", "/api/envs/env/secrets"),
                                  ("DELETE", f"/api/secrets/{secret_id}"))

    def test_missing_exact_path_is_404_and_never_deletes(self):
        for path in ["/missing/", "/team", "/TEAM/"]:
            for operation in [self.client.get_secret, self.client.delete_secret]:
                with self.subTest(path=path, operation=operation.__name__):
                    self.server.calls.clear()
                    with self.assertRaises(OpenWarpError) as caught:
                        operation("env", "api_key", path=path)
                    self.assertEqual(caught.exception.status, 404)
                    self.assert_calls(("GET", "/api/envs/env/secrets"))

    def test_unique_legacy_lookup_and_delete_still_work_without_path(self):
        self.server.secrets = [SECRETS[0], SECRETS[1]]
        self.assertEqual(self.client.get_secret("env", "api_key"), SECRETS[1])
        self.client.delete_secret("env", "api_key")
        self.assert_calls(("GET", "/api/envs/env/secrets"),
                          ("GET", "/api/envs/env/secrets"),
                          ("DELETE", "/api/secrets/folder"))


if __name__ == "__main__":
    unittest.main()
