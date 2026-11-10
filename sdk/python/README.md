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

## Management requests

`api(method, segments, body=None, query=None, step_up=None)` calls any JSON endpoint under `/api` with the same Bearer token. The server still checks workspace membership, roles, environment scope and any required verification. The method does not grant administrative permissions or perform browser sign-in or client-side encryption.

```python
workspaces = client.api("GET", ["orgs"])
integrations = client.api("GET", ["envs", "environment-id", "integrations"])
client.api("PATCH", ["integrations", "integration-id"], body={"name": "deployment"})
```

Pass path segments as a list or tuple, not a URL or a slash-delimited path. The client encodes each segment and the separate query mapping. It rejects dot traversal, malformed percent escapes, backslashes, control characters and URL-like segments before making a request. Supported methods are `GET`, `POST`, `PUT`, `PATCH`, `DELETE`, `HEAD` and `OPTIONS`. A successful empty response returns `None`.

Generic management requests refuse redirects, including same-origin redirects. HTTP errors preserve their status and raw body; do not log a body that may contain credentials or secret values. This method cannot call endpoints outside `/api` or replace a protocol-specific flow that needs form data, a browser or local cryptography.

Pass an existing verification grant through `step_up` to send `X-OpenWarp-Step-Up` for that request only. It must contain 1-512 printable ASCII characters. The original Bearer credential is unchanged; the client does not complete or bypass verification.

Run the local HTTP mock tests from this directory:

```sh
python3 -m unittest discover -s tests -v
```
