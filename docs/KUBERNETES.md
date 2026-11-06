# Kubernetes

OpenWarp can get an environment into a pod three ways. They differ in who starts the transfer and how a change reaches running containers.

| Approach | Direction | Picks up a change | Extra component |
| --- | --- | --- | --- |
| Push a native Secret | OpenWarp calls the cluster API | on the next sync run | none beyond the `kubernetes` adapter |
| Init container | pod calls OpenWarp at start | on pod restart | none |
| ESO bridge | External Secrets Operator calls the bridge | on the `ExternalSecret` refresh interval | `openwarp-eso` and ESO |

The `kubernetes` adapter is the shortest path when OpenWarp can reach the cluster API. The init container is the right choice when the cluster must not accept writes and you do not run a controller. The ESO bridge is for clusters where a controller already owns `Secret` objects.

## Before you start

All three approaches authenticate with an OpenWarp service token scoped to one environment. Create one in the console under the application's Tokens tab, or with the API:

```sh
curl -sS -X POST "$OPENWARP_HOST/api/apps/$APP_ID/tokens" \
  -H "Authorization: Bearer $OPENWARP_TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"cluster-reader","env_id":"ENV_ID","expires_in":7776000,"scopes":"secrets:read"}'
```

The response contains `token` once. Store it in a Kubernetes Secret.

Two behaviours matter when the token is used for deployment:

- The token acts as the account that created it. Its organisation role decides which permissions apply, and the environment scope narrows it to one environment. Revoking the token, or deactivating the creator, stops new reads immediately.
- Personal overrides are applied unless you ask for canonical values. `openwarp export --base` and the bridge's `base=1` request skip the token owner's overrides, so a Deployment never runs with an individual's stand-in credentials. Use the base form in automation.

The environment scope also decides how you address the environment. A token created with `env_id` may only call `/api/envs/{that id}/...`, so it cannot list workspaces or applications. The bridge accounts for that: it reads the token's own scope from `/api/me`, then compares a name reference against that one environment. `Acme/api/Production` resolves when it names the token's environment; anything else returns 403 with the actual scope in the message. A token created without `env_id` can resolve any name its owning account can read. Prefer the scoped token: it is the narrower credential.

Two kinds of secret cannot be materialised on the server:

- Sealed secrets have no server-side value. Neither the CLI nor the bridge can turn one into an environment variable.
- End-to-end encrypted environments decrypt only on a client that holds the private key. The server stores ciphertext and per-user wrapped keys.

The bridge refuses an environment that contains either, with HTTP 422 and the affected key names, rather than write an empty string where a credential belongs. `openwarp export` is more permissive: a sealed secret, or one the server cannot decrypt, is printed as `KEY=` with no value and no error. Check the exported file for blank values before relying on it.

## Push a native Secret

Describe a `kubernetes` integration on the environment. The adapter writes an Opaque `Secret` and creates it after a not-found response.

```json
{
  "kind": "kubernetes",
  "config": {
    "api_server": "https://kubernetes.default.svc",
    "namespace": "apps",
    "secret_name": "api-secrets",
    "token": "CLUSTER_BEARER_TOKEN"
  }
}
```

Give the token only what the adapter needs: `get`, `create`, and `update` on `secrets` in one namespace. See [Integrations](INTEGRATIONS.md) for the request shape and the other adapter fields.

This is a push: OpenWarp must be able to reach `api_server`, so a cluster behind a NAT or a private control plane needs the private-network worker or one of the pull approaches below. Pods still restart to pick up a new value, because the value arrives through a `Secret` (unless your application reloads it).

## Init container

The pod fetches its own environment once at start and hands it to the application through a memory-backed volume.

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: openwarp-service-token
stringData:
  token: owp_REPLACE_ME
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  replicas: 2
  selector:
    matchLabels:
      app: api
  template:
    metadata:
      labels:
        app: api
    spec:
      initContainers:
        - name: openwarp-secrets
          image: YOUR_REGISTRY/openwarp:0.1.0
          command: ["sh", "-c", "openwarp export --base --format shell --env ENV_ID > /secrets/env.sh"]
          env:
            - name: OPENWARP_HOST
              value: https://openwarp.example.com
            - name: OPENWARP_TOKEN
              valueFrom:
                secretKeyRef:
                  name: openwarp-service-token
                  key: token
          volumeMounts:
            - name: secrets
              mountPath: /secrets
      containers:
        - name: api
          image: YOUR_REGISTRY/api:latest
          command: ["sh", "-c", ". /secrets/env.sh && exec /app/server"]
          volumeMounts:
            - name: secrets
              mountPath: /secrets
              readOnly: true
      volumes:
        - name: secrets
          emptyDir:
            medium: Memory
```

`--format shell` writes `export KEY='value'` lines with embedded single quotes escaped, so sourcing the file is safe for values that contain spaces, quotes, or newlines. `--format dotenv` is the default and suits `docker run --env-file` style tooling, but it is not shell syntax.

Notes:

- `--env` takes the environment ID, not its name. Copy it from the console's environment settings.
- The init container image must contain the `openwarp` binary. The published image does, alongside the server.
- If the application image cannot source a file, replace its entrypoint with a wrapper that does, as in the example. Kubernetes cannot populate `envFrom` from a volume.
- The volume is `emptyDir` with `medium: Memory`, so values never reach disk and disappear with the pod. If the application runs as a different UID than the init container, set `podSecurityContext.fsGroup` so both can read the file.
- A value change reaches the pod only after a restart (`kubectl rollout restart deployment/api`). There is no in-place refresh.

## External Secrets Operator bridge

`openwarp-eso` serves one environment as the JSON object an ESO [webhook provider](https://external-secrets.io/latest/provider/webhook/) reads. ESO keeps ownership of the `ExternalSecret` and the target `Secret`; the bridge only translates.

The bridge holds no credentials. Each request must carry an OpenWarp service token, which the bridge forwards, so a caller can never receive more than that token already allows.

Enable it in the Helm chart, or run the image directly:

```sh
helm upgrade --install openwarp deploy/helm/openwarp \
  --namespace openwarp \
  --set eso.enabled=true
```

That deploys a one-replica bridge and a ClusterIP Service on port 8090. Defaults and overrides are in the [chart README](../deploy/helm/openwarp/README.md).

Create the Secret that holds the token. ESO only reads Secrets labelled `external-secrets.io/type: webhook`:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: openwarp-service-token
  namespace: apps
  labels:
    external-secrets.io/type: webhook
stringData:
  token: owp_REPLACE_ME
```

Point a `SecretStore` at the bridge. `result.jsonPath` selects the object the bridge returns:

```yaml
apiVersion: external-secrets.io/v1
kind: SecretStore
metadata:
  name: openwarp
  namespace: apps
spec:
  provider:
    webhook:
      url: "http://openwarp-openwarp-eso.openwarp.svc:8090/v1/export"
      method: POST
      body: '{"ref": "{{ .remoteRef.key }}"}'
      headers:
        Content-Type: application/json
        Authorization: "Bearer {{ .auth.token }}"
      result:
        jsonPath: "$.data"
      timeout: 15s
      secrets:
        - name: auth
          secretRef:
            name: openwarp-service-token
```

Then one `ExternalSecret` per environment. `extract` takes the whole environment as the target `Secret`, which matches how OpenWarp models an environment:

```yaml
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: api-secrets
  namespace: apps
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: openwarp
    kind: SecretStore
  target:
    name: api-secrets
    creationPolicy: Owner
  dataFrom:
    - extract:
        key: ENV_ID
```

The reference in `key` is one of:

| Form | Example | Resolution |
| --- | --- | --- |
| `ENV_ID` | `k3n8...` | Used as given, no lookup; works with any token |
| `APP/ENV` | `api/Production` | Must match exactly one environment the token can reach |
| `WORKSPACE/APP/ENV` | `Acme/api/Production` | Same, with the workspace narrowing the match |

All three work with an environment-scoped token. The bridge reads the scope from `/api/me`; a name that points anywhere else is refused with 403 and the scope named in the error, because the API does not let that token list workspaces. Drop the environment scope from the token if one `ExternalSecret` set must span several environments.

The ID is on the environment's settings page in the console.

Use `extract`. The webhook provider implements whole-object reads (`dataFrom.extract`); per-key selection through `remoteRef.property` is resolved inside provider implementations, and this provider does not implement it. One `ExternalSecret` per environment is also cheaper: one HTTP call instead of one per key.

Behaviour worth knowing:

- A 404 from the bridge means the environment no longer resolves. ESO then applies the target's `deletionPolicy`, which is `Retain` unless you set `Delete`. A scoped token produces that 404 for its own environment, which is the reference the examples use. A different id returns 403 instead, and ESO retries rather than deletes, so alert on failing `ExternalSecret` objects if removal matters.
- 401 and 403 pass through, so a revoked token shows up as a failing `ExternalSecret` rather than an empty `Secret`.
- A 5xx from OpenWarp becomes a 502, which ESO treats as a retryable error.
- The bridge is stateless. Raise `eso.replicas` freely; each replica resolves names through the API per request.
- Restrict port 8090 with a NetworkPolicy. Anything that can reach the bridge can present a token, though it still needs a valid one.

### Running the bridge without Helm

```sh
OPENWARP_URL=https://openwarp.example.com \
OPENWARP_ESO_ADDR=0.0.0.0:8090 \
openwarp-eso
```

`OPENWARP_URL` is required. The bridge also serves `GET /healthz` for probes and accepts a reference as `?ref=`, as a JSON body `{"ref": "..."}`, or as the remainder of the path (`/v1/export/Acme/api/Production`).

## Choosing

- You already run ESO or another controller that owns Secrets: use the bridge. It is the only option that refreshes without a restart.
- The cluster must not accept writes from outside, and you want no extra controller: use the init container.
- OpenWarp already holds cluster credentials and you just want the values as a normal `Secret`: use the `kubernetes` adapter.

None of these removes the need to restart pods when values arrive through environment variables. Prefer a volume or an application that reloads its configuration if you need rotation without a rollout.
