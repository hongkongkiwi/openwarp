"""Integration test for the Python SDK against a real server binary.

Run: OPENWARP_BIN=target/debug/openwarp-server python3 -m unittest sdk/contract/python/test_openwarp.py
"""
from __future__ import annotations

import json
import os
import queue
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from openwarp import Client, OpenWarpError  # noqa: E402

BIN = os.environ.get(
    "OPENWARP_BIN",
    str(Path(__file__).resolve().parents[3] / "target" / "debug" / "openwarp-server"),
)


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Server:
    def __init__(self) -> None:
        self.dir = tempfile.mkdtemp(prefix="openwarp-sdk-py-")
        self.port = free_port()
        self.base = f"http://127.0.0.1:{self.port}"
        self.inbox: queue.Queue[str] = queue.Queue()
        inbox = self.inbox

        class MailHandler(BaseHTTPRequestHandler):
            def log_message(self, *args) -> None:
                pass

            def do_POST(self) -> None:
                try:
                    message = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
                    text = message["text"]
                    if not isinstance(text, str):
                        raise ValueError("mail text must be a string")
                except (ValueError, KeyError, TypeError):
                    self.send_response(400)
                    self.end_headers()
                    return
                inbox.put(text)
                self.send_response(204)
                self.end_headers()

        self.mail = ThreadingHTTPServer(("127.0.0.1", 0), MailHandler)
        self.mail_thread = threading.Thread(target=self.mail.serve_forever, daemon=True)
        self.mail_thread.start()
        prefixes = ("OPENWARP_EMAIL_", "OPENWARP_SMTP_", "OPENWARP_RESEND_", "OPENWARP_SENDGRID_",
                    "OPENWARP_MAILGUN_", "OPENWARP_POSTMARK_", "OPENWARP_CLOUDFLARE_EMAIL_",
                    "OPENWARP_MASTER_KEY", "REDIS_URL", "OPENWARP_ENV")
        env = {key: value for key, value in os.environ.items() if not key.startswith(prefixes)}
        env.update({"DATABASE_URL": f"sqlite://{self.dir}/sdk.db", "ADDR": f"127.0.0.1:{self.port}",
                    "OPENWARP_PUBLIC_URL": self.base, "TOKIO_WORKER_THREADS": "2",
                    "OPENWARP_EMAIL_PROVIDER": "webhook",
                    "OPENWARP_EMAIL_WEBHOOK": f"http://127.0.0.1:{self.mail.server_port}",
                    "OPENWARP_EMAIL_FROM": "no-reply@test.invalid"})
        try:
            self.process = subprocess.Popen([BIN], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except OSError:
            self.mail.shutdown()
            self.mail.server_close()
            self.mail_thread.join()
            shutil.rmtree(self.dir, ignore_errors=True)
            raise
        deadline = time.time() + 20
        while time.time() < deadline:
            try:
                with urllib.request.urlopen(f"{self.base}/health", timeout=1) as response:
                    if response.status == 200:
                        return
            except OSError:
                pass
            time.sleep(0.1)
        self.stop()
        raise RuntimeError(f"server did not start at {self.base}")

    def next_mail(self) -> str:
        try:
            return self.inbox.get(timeout=10)
        except queue.Empty:
            raise AssertionError("verification mail did not arrive") from None

    def wait_for_verify_link(self) -> str:
        match = re.search(r"/api/auth/verify\?token=[^\s\"'<>]+", self.next_mail())
        if not match:
            raise AssertionError("verification link missing from mail")
        return self.base + match.group(0)

    def api_request(self, token: str, method: str, path: str, body: dict | None = None,
                    step_up: str | None = None) -> dict:
        headers = {"Accept": "application/json", "Authorization": f"Bearer {token}"}
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        if step_up is not None:
            headers["X-OpenWarp-Step-Up"] = step_up
        request = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
        with urllib.request.urlopen(request, timeout=10) as response:
            if response.status != 200:
                raise AssertionError(f"{method} {path} must succeed")
            return json.load(response)

    def stop(self) -> None:
        self.process.kill()
        self.process.wait()
        self.mail.shutdown()
        self.mail.server_close()
        self.mail_thread.join()
        shutil.rmtree(self.dir, ignore_errors=True)


class SdkTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = Server()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.stop()

    def test_round_trip(self) -> None:
        client = Client(self.server.base)
        registered = client.register("sdk-py@test.invalid", "sdk-password-1")
        self.assertTrue(registered.get("verification_required"))
        with urllib.request.urlopen(self.server.wait_for_verify_link(), timeout=5) as response:
            self.assertEqual(response.status, 200)
        session = client.login("sdk-py@test.invalid", "sdk-password-1")
        self.assertTrue(session.get("token"))
        client.token = session["token"]

        self.assertEqual(client.me()["email"], "sdk-py@test.invalid")
        self.assertTrue(client.providers()["password"])
        orgs = client.list_orgs()
        self.assertEqual(len(orgs), 1)
        org = orgs[0]["id"]

        app = client.create_app(org, "sdk-py-app")["id"]
        envs = client.list_envs(app)
        self.assertEqual(len(envs), 3)
        dev, prod = envs[0]["id"], envs[1]["id"]

        deployed = client.deploy_secrets(dev, [{"key": "API_KEY", "value": "v1"}, {"key": "DB_URL", "value": "postgres://x"}])
        self.assertEqual(deployed["deployed"], 2)
        listed = client.list_secrets(dev)["secrets"]
        api = next(s for s in listed if s["key"] == "API_KEY")
        self.assertEqual(api["value"], "v1")
        with self.assertRaises(OpenWarpError) as challenged:
            client.export_env(dev)
        self.assertEqual(challenged.exception.status, 428)
        self.assertTrue(challenged.exception.body["step_up_required"])
        self.assertEqual(challenged.exception.body["risk"], "very_risky")
        self.assertTrue(challenged.exception.body["email_required"])
        self.assertFalse(challenged.exception.body["totp_required"])
        challenge = self.server.api_request(client.token, "POST", "/api/auth/step-up/start", {"risk": "very_risky"})
        self.assertTrue(challenge.get("challenge"))
        code = re.search(r"\b\d{6}\b", self.server.next_mail())
        self.assertIsNotNone(code, "step-up verification code missing from mail")
        grant = self.server.api_request(client.token, "POST", "/api/auth/step-up/verify", {
            "challenge": challenge["challenge"], "email_code": code.group(0),
        })
        self.assertTrue(grant.get("token"))
        exported = self.server.api_request(client.token, "GET", f"/api/envs/{dev}/export", step_up=grant["token"])
        self.assertIn("API_KEY=v1", exported["text"])

        self.assertEqual(client.secret_history(api["id"])[0]["version"], 1)
        client.deploy_secrets(dev, [{"key": "API_KEY", "value": "v2"}])
        client.restore_secret(api["id"], 1)
        self.assertEqual(next(s for s in client.list_secrets(dev)["secrets"] if s["key"] == "API_KEY")["value"], "v1")

        created = client.create_token(app, "ci", dev)
        scoped = Client(self.server.base, created["token"])
        self.assertGreater(len(scoped.list_secrets(dev)["secrets"]), 0)
        with self.assertRaises(OpenWarpError) as denied:
            scoped.list_secrets(prod)
        self.assertEqual(denied.exception.status, 403)
        client.revoke_token(created["id"])

        self.assertTrue(any(r["key"] == "API_KEY" for r in client.search("API")["results"]))
        self.assertTrue(any(c["key"] == "API_KEY" for c in client.search("API")["results"]))

        lease = client.create_lease(dev, name="py-lease")
        self.assertTrue(lease["value"])
        self.assertTrue(any(item["id"] == lease["id"] for item in client.list_leases(dev)))
        client.revoke_lease(lease["id"])

        rotation = client.create_rotation(dev, "API_KEY", 60)
        client.delete_rotation(rotation["id"])

        db_secret = next(s for s in listed if s["key"] == "DB_URL")
        client.delete_secret(db_secret["id"])
        self.assertFalse(any(s["key"] == "DB_URL" for s in client.list_secrets(dev)["secrets"]))

        with self.assertRaises(OpenWarpError) as missing:
            client.deploy_secrets("missing-env", [{"key": "X", "value": "y"}])
        self.assertEqual(missing.exception.status, 404)


if __name__ == "__main__":
    unittest.main()
