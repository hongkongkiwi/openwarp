import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from openwarp import OpenWarp, OpenWarpError


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def handle_request(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self.server.calls.append((self.command, self.path, dict(self.headers),
                                  json.loads(raw) if raw else None))
        status, body = self.server.responses.pop(0)
        payload = body.encode() if isinstance(body, str) else json.dumps(body).encode()
        self.send_response(status)
        self.end_headers()
        self.wfile.write(payload)

    do_GET = do_PUT = do_POST = do_DELETE = handle_request


class ClientTests(unittest.TestCase):
    def setUp(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.calls = []
        self.server.responses = []
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.client = OpenWarp(f"http://127.0.0.1:{self.server.server_port}/", "test-token", timeout=2)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def test_read_routes_and_encoding(self):
        cases = [
            (self.client.me, (), "/api/me", {"id": "u"}),
            (self.client.orgs, (), "/api/orgs", [{"id": "o"}]),
            (self.client.apps, ("o/ #?%",), "/api/orgs/o%2F%20%23%3F%25/apps", []),
            (self.client.envs, ("a/b",), "/api/apps/a%2Fb/envs", []),
            (self.client.secrets, ("e/f",), "/api/envs/e%2Ff/secrets", {"secrets": []}),
            (self.client.export, ("e/f",), "/api/envs/e%2Ff/export", {"text": "KEY=value\n", "secrets": []}),
            (self.client.leases, ("e/f",), "/api/envs/e%2Ff/dynamic", []),
            (self.client.audit, ("o/p",), "/api/orgs/o%2Fp/audit", []),
        ]
        for method, args, path, response in cases:
            with self.subTest(path=path):
                self.server.responses.append((200, response))
                expected = response["secrets"] if method == self.client.secrets else response
                self.assertEqual(method(*args), expected)
                verb, actual, headers, body = self.server.calls[-1]
                self.assertEqual((verb, actual, body), ("GET", path, None))
                self.assertEqual(headers["Authorization"], "Bearer test-token")
                self.assertEqual(headers["Accept"], "application/json")

    def test_set_secret_defaults_and_options(self):
        for options in ({}, {"path": "/folder", "type": "plain", "comment": "note"}):
            with self.subTest(options=options):
                self.server.responses.append((200, {"deployed": 1, "sync_errors": []}))
                result = self.client.set_secret("e/f", "KEY", "雪\nvalue", **options)
                self.assertEqual(result["deployed"], 1)
                verb, path, headers, body = self.server.calls[-1]
                self.assertEqual((verb, path), ("PUT", "/api/envs/e%2Ff/secrets"))
                self.assertEqual(headers["Content-Type"], "application/json")
                self.assertEqual(body, {"secrets": [{"key": "KEY", "value": "雪\nvalue", "path": options.get("path", "/"), "type": options.get("type", "secret"), "comment": options.get("comment", ""), "tags": ""}]})

    def test_lookup_and_delete(self):
        secret = {"id": "s/#", "key": "Api_Key", "value": "v"}
        self.server.responses.extend([(200, {"secrets": [secret]}), (200, {"secrets": [secret]}), (204, "")])
        self.assertEqual(self.client.get_secret("env", "API_KEY"), secret)
        self.assertIsNone(self.client.delete_secret("env", "api_key"))
        self.assertEqual(self.server.calls[-1][:2], ("DELETE", "/api/secrets/s%2F%23"))

    def test_missing_key_never_deletes(self):
        self.server.responses.append((200, {"secrets": []}))
        with self.assertRaises(OpenWarpError) as caught:
            self.client.delete_secret("env", "missing")
        self.assertEqual(caught.exception.status, 404)
        self.assertEqual(len(self.server.calls), 1)

    def test_create_lease(self):
        for ttl in (None, 120):
            self.server.responses.append((200, {"id": "lease", "value": "v"}))
            args = () if ttl is None else (ttl,)
            self.assertEqual(self.client.create_lease("e/f", "job", *args)["id"], "lease")
            verb, path, headers, body = self.server.calls[-1]
            self.assertEqual((verb, path), ("POST", "/api/envs/e%2Ff/dynamic"))
            self.assertEqual(body, {"name": "job", "ttl_secs": 3600 if ttl is None else ttl})

    def test_http_errors_and_malformed_json(self):
        for status, raw, message in [(401, '{"error":"denied"}', "denied"),
                                     (500, "broken", "broken"),
                                     (400, '{"message":"bad"}', "bad"),
                                     (200, "not json", "Invalid JSON response")]:
            with self.subTest(status=status, raw=raw):
                self.server.responses.append((status, raw))
                with self.assertRaises(OpenWarpError) as caught:
                    self.client.me()
                self.assertEqual((caught.exception.status, caught.exception.message, caught.exception.body), (status, message, raw))

    def test_transport_error(self):
        self.client.base_url = "http://127.0.0.1:0"
        with self.assertRaises(OpenWarpError) as caught:
            self.client.me()
        self.assertEqual(caught.exception.status, 0)


if __name__ == "__main__":
    unittest.main()
