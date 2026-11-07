import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit
from unittest.mock import patch

from openwarp import OpenWarp, OpenWarpError


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def handle_request(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self.server.calls.append((self.command, self.path, dict(self.headers),
                                  json.loads(raw) if raw else None))
        status, body, headers = self.server.responses.pop(0)
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD" and status != 204:
            self.wfile.write(body.encode() if isinstance(body, str) else json.dumps(body).encode())

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = handle_request


def server():
    instance = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    instance.calls = []
    instance.responses = []
    thread = threading.Thread(target=instance.serve_forever, daemon=True)
    thread.start()
    return instance, thread


class ManagementBaseURLTests(unittest.TestCase):
    def test_rejects_query_and_fragment_delimiters_before_request(self):
        for suffix in ("?", "#", "?#", "?scope=admin", "#capture", "?scope=admin#capture"):
            with self.subTest(suffix=suffix):
                client = OpenWarp("https://example.invalid/prefix/" + suffix, "private-test-token")
                with patch.object(client, "_request", return_value={}) as request:
                    try:
                        with self.assertRaises(ValueError):
                            client.api("POST", ["orgs"], body={"name": "private"})
                    finally:
                        request.assert_not_called()


class ManagementTests(unittest.TestCase):
    def setUp(self):
        self.server, self.thread = server()
        self.addCleanup(self.thread.join)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.client = OpenWarp(f"http://127.0.0.1:{self.server.server_port}", "management-test-token", timeout=2)
        self.assertTrue(callable(getattr(self.client, "api", None)), "public OpenWarp.api is required")

    def test_segments_and_query_are_separate(self):
        self.server.responses.append((200, {"ok": True}, {}))
        result = self.client.api("GET", ["orgs", "a/b ?#雪", "audit"],
                                 query={"search": "a&b=雪 +/?#", "limit": "2"})
        self.assertEqual(result, {"ok": True})
        method, path, headers, body = self.server.calls[-1]
        self.assertEqual(method, "GET")
        self.assertEqual(urlsplit(path).path, "/api/orgs/a%2Fb%20%3F%23%E9%9B%AA/audit")
        self.assertEqual(parse_qs(urlsplit(path).query), {"search": ["a&b=雪 +/?#"], "limit": ["2"]})
        self.assertEqual(headers["Authorization"], "Bearer management-test-token")
        self.assertIsNone(body)

    def test_all_supported_methods_and_json_body(self):
        for method in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
            with self.subTest(method=method):
                self.server.responses.append((204, "", {}))
                body = {"name": "雪"} if method in ("POST", "PUT", "PATCH") else None
                self.assertIsNone(self.client.api(method, ["orgs", "o", "settings"], body=body))
                actual, path, headers, sent = self.server.calls[-1]
                self.assertEqual((actual, path, sent), (method, "/api/orgs/o/settings", body))
                if body is not None:
                    self.assertEqual(headers["Content-Type"], "application/json")

    def test_rejects_unsafe_segments_before_network(self):
        cases = [["."], [".."], ["%2e"], ["%2E%2e"], [".%2e"],
                 ["%252e%252e"], ["%25252e%25252e"], ["a/../b"],
                 ["a%2f..%2fb"], ["a%252f%252e%252e%252fb"],
                 ["a%25252f%25252e%25252e%25252fb"],
                 ["bad%"], ["%GG"], ["back\\slash"], ["bad\nheader"],
                 ["bad\x00"], ["bad\x7f"], ["https://example.invalid/api/me"],
                 ["//example.invalid/api/me"]]
        for segments in cases:
            with self.subTest(segments=segments):
                with self.assertRaises((ValueError, OpenWarpError)):
                    self.client.api("GET", segments)
        self.assertEqual(self.server.calls, [])

    def test_rejects_unsupported_methods_before_network(self):
        for method in ("TRACE", "CONNECT", "BREW", "GET\r\nX-Test: yes"):
            with self.subTest(method=method):
                with self.assertRaises((ValueError, OpenWarpError)):
                    self.client.api(method, ["me"])
        self.assertEqual(self.server.calls, [])

    def test_http_status_and_error_body_are_preserved(self):
        for status in (400, 401, 403, 404, 409, 429, 500, 503):
            with self.subTest(status=status):
                raw = '{"error":"management denied"}'
                self.server.responses.append((status, raw, {}))
                with self.assertRaises(OpenWarpError) as caught:
                    self.client.api("GET", ["orgs"])
                self.assertEqual(caught.exception.status, status)
                self.assertEqual(caught.exception.body, raw)

    def test_redirects_are_not_followed_even_to_same_origin(self):
        self.server.responses.extend([(302, "", {"Location": "/api/me"}), (200, {}, {})])
        try:
            self.client.api("GET", ["orgs"])
        except OpenWarpError:
            pass
        self.assertEqual(len(self.server.calls), 1)

    def test_redirect_does_not_forward_credentials_or_request(self):
        target, thread = server()
        try:
            target.responses.append((200, {}, {}))
            self.server.responses.append((307, "", {"Location": f"http://127.0.0.1:{target.server_port}/capture"}))
            try:
                self.client.api("POST", ["orgs"], body={"name": "private"})
            except OpenWarpError:
                pass
            self.assertEqual(target.calls, [], "redirect target must receive neither credentials nor request")
            self.assertEqual(len(self.server.calls), 1)
        finally:
            target.shutdown()
            target.server_close()
            thread.join()


if __name__ == "__main__":
    unittest.main()
