# OpenWarp Python SDK

Requires Python 3.8+ and only the standard library. Run from this directory, or add this directory to `PYTHONPATH`. No install is required.

```python
import os
from openwarp import OpenWarp, OpenWarpError

client = OpenWarp(os.environ["OPENWARP_URL"], os.environ["OPENWARP_TOKEN"])
try:
    user = client.me()
    secret = client.get_secret("environment-id", "DATABASE_URL")
    client.set_secret("environment-id", "API_KEY", "value")
except OpenWarpError as exc:
    print(exc.status, exc.message)  # Do not log exc.body; it may contain secrets.
```

The base URL is the server root, without `/api`. Requests use Bearer authentication, a 30-second timeout by default, and the standard library's verified HTTPS handling.

Methods:

- `me()`, `orgs()`, `apps(org)`, `envs(app)`
- `secrets(env)`: returns the list inside the `secrets` response field.
- `get_secret(env, key)`: returns the first matching secret dictionary, ignoring key case.
- `set_secret(env, key, value, path="/", type="secret", comment="")`: sends a one-secret PUT with empty tags; returns the deployment response, including `sync_errors`.
- `delete_secret(env, key)`: looks up the secret ID, then deletes it.
- `export(env)`: returns the dictionary containing `text` and `secrets`.
- `leases(env)`, `create_lease(env, name, ttl_secs=3600)`, `audit(org)`

Other methods return decoded JSON unchanged. Empty successful responses return `None`. Missing keys raise `OpenWarpError` with status 404 and an empty body. Duplicate keys across paths resolve to the first match in the server response.

HTTP failures retain the status, parsed error message when available, and raw text body in `OpenWarpError`. Transport failures use status 0. Invalid JSON responses raise the same error with the response status. There are no retries. Error bodies and returned secrets are sensitive.

Run the local HTTP mock tests from this directory:

```sh
python3 -m unittest discover -s tests -v
```
