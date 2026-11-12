# OpenWarp Python SDK

Standard library only, Python 3.10+.

```python
from openwarp import Client, OpenWarpError

ow = Client("https://secrets.example.com")
session = ow.login("you@company.com", "password")
ow.token = session["token"]

org = ow.list_orgs()[0]
app = ow.create_app(org["id"], "billing-api")["id"]
env = ow.list_envs(app)[0]["id"]
ow.deploy_secrets(env, [{"key": "API_KEY", "value": "v1"}])
print(ow.export_env(env)["text"])
```

The contract is [`../../../openapi.json`](../../../openapi.json). A non-2xx response
raises `OpenWarpError` with `status` and the parsed `body`.

## Test

```bash
cargo build -p openwarp-server
OPENWARP_BIN=target/debug/openwarp-server python3 -m unittest discover -s sdk/contract/python -p 'test_*.py'
```

The test starts a private server on a loopback port with a temporary SQLite
database, exercises authentication, secrets, tokens, scoping, leases, rotations
and search, and then removes everything.
