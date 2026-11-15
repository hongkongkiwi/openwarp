import json
import os
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit
from unittest.mock import patch

from openwarp import OpenWarp, OpenWarpError


TOKEN = "pagination-dummy-token"
FIRST = {"id": "first", "key": "API_KEY", "path": "/", "value": "dummy-first"}
LATER = {"id": "later", "key": "API_KEY", "path": "/team/", "value": "dummy-later"}
OTHER = {"id": "other", "key": "OTHER", "path": "/", "value": "dummy-other"}
OTHER2 = {"id": "other2", "key": "OTHER2", "path": "/", "value": "dummy-other2"}


class PaginationHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def handle_request(self):
        parts = urlsplit(self.path)
        query = parse_qs(parts.query, keep_blank_values=True)
        self.server.calls.append((self.command, self.path, self.headers.get("Authorization")))
        status, body = 404, {"error": "unexpected fixture route"}
        if self.headers.get("Authorization") != f"Bearer {TOKEN}":
            status, body = 401, {"error": "unauthorized"}
        elif self.command == "GET" and parts.path == "/api/envs/env/secrets":
            self.server.reads += 1
            if self.server.reads > 3:
                status, body = 500, {"error": "fixture pagination request budget exceeded"}
            elif set(query) <= {"offset", "limit"} and query.get("offset", ["0"]) in (["0"], ["2"]):
                status, body = 200, self.server.pages[int(query.get("offset", ["0"])[0])]
        elif self.command == "DELETE" and parts.path in {"/api/secrets/first", "/api/secrets/later"}:
            status, body = 200, {"deleted": True}
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    do_GET = do_DELETE = handle_request


class PaginationContractTests(unittest.TestCase):
    def setUp(self):
        env = patch.dict(os.environ, {"HTTP_PROXY": "", "HTTPS_PROXY": "", "ALL_PROXY": "",
                                    "http_proxy": "", "https_proxy": "", "all_proxy": "",
                                    "NO_PROXY": "*", "no_proxy": "*"})
        env.start()
        self.addCleanup(env.stop)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), PaginationHandler)
        self.server.calls, self.server.reads = [], 0
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.client = OpenWarp(f"http://127.0.0.1:{self.server.server_port}", TOKEN, timeout=2)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def pages(self, first, later, mode="valid"):
        self.server.calls, self.server.reads = [], 0
        self.server.pages = {0: {"secrets": first, "total": 4, "limit": 2, "offset": 0},
                             2: {"secrets": later, "total": 4, "limit": 2, "offset": 2}}
        if mode == "legacy":
            self.server.pages[0] = {"secrets": first}
        elif mode == "partial":
            self.server.pages[0] = {"secrets": first, "total": 4}
        elif mode == "stalled":
            self.server.pages[2]["offset"] = 0

    def assert_requests(self, offsets, deleted=None):
        reads, deletes = [], []
        for method, path, auth in self.server.calls:
            self.assertEqual(auth, f"Bearer {TOKEN}")
            parts = urlsplit(path)
            if method == "GET":
                self.assertEqual(parts.path, "/api/envs/env/secrets")
                reads.append(int(parse_qs(parts.query).get("offset", ["0"])[0]))
            else:
                deletes.append((method, parts.path))
        self.assertEqual(reads, offsets)
        self.assertEqual(deletes, [] if deleted is None else [("DELETE", f"/api/secrets/{deleted}")])

    def test_duplicate_key_on_later_page_rejects_get_and_delete(self):
        for operation in [self.client.get_secret, self.client.delete_secret]:
            with self.subTest(operation=operation.__name__):
                self.pages([FIRST, OTHER], [LATER, OTHER2])
                with self.assertRaises(OpenWarpError) as caught:
                    operation("env", "api_key")
                self.assertEqual(caught.exception.status, 409)
                self.assert_requests([0, 2])

    def test_exact_path_target_on_later_page_gets_and_deletes(self):
        self.pages([OTHER, OTHER2], [LATER, FIRST])
        self.assertEqual(self.client.get_secret("env", "api_key", path="/team/"), LATER)
        self.assert_requests([0, 2])
        self.pages([OTHER, OTHER2], [LATER, FIRST])
        self.client.delete_secret("env", "api_key", path="/team/")
        self.assert_requests([0, 2], deleted="later")

    def test_invalid_pagination_fails_closed_but_legacy_no_metadata_is_complete(self):
        self.pages([FIRST], [], mode="legacy")
        self.assertEqual(self.client.get_secret("env", "api_key"), FIRST)
        self.client.delete_secret("env", "api_key")
        self.assert_requests([0, 0], deleted="first")
        for mode in ["partial", "stalled"]:
            for operation in [self.client.get_secret, self.client.delete_secret]:
                with self.subTest(mode=mode, operation=operation.__name__):
                    self.pages([FIRST, OTHER], [OTHER, OTHER2], mode=mode)
                    with self.assertRaises(OpenWarpError):
                        operation("env", "api_key")
                    self.assert_requests([0] if mode == "partial" else [0, 2])


if __name__ == "__main__":
    unittest.main()
