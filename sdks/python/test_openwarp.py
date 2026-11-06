"""Integration test for the Python SDK against a real server binary.

Run: OPENWARP_BIN=target/debug/openwarp-server python3 -m unittest sdks/python/test_openwarp.py
"""
from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from openwarp import Client, OpenWarpError  # noqa: E402

BIN = os.environ.get(
    "OPENWARP_BIN",
    str(Path(__file__).resolve().parents[2] / "target" / "debug" / "openwarp-server"),
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
        env = {**os.environ, "DATABASE_URL": f"sqlite://{self.dir}/sdk.db", "ADDR": f"127.0.0.1:{self.port}",
               "OPENWARP_PUBLIC_URL": self.base, "TOKIO_WORKER_THREADS": "2"}
        env.pop("OPENWARP_MASTER_KEY", None)
        env.pop("REDIS_URL", None)
        self.process = subprocess.Popen([BIN], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
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

    def stop(self) -> None:
        self.process.kill()
        self.process.wait()
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
        self.assertTrue(registered["token"])
        client.token = registered["token"]

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
        self.assertIn("API_KEY=v1", client.export_env(dev)["text"])

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
