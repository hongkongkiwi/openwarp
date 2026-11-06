# OpenWarp Helm chart

This chart deploys OpenWarp 0.1.0 with at least two replicas, rolling updates,
health probes, and a PodDisruptionBudget. It does not install Postgres or Redis.
Set `image.repository` to an image available to your cluster; `openwarp` is a
local image name, not a published registry guarantee. An empty tag uses appVersion.

## Required configuration

Provision Kubernetes Secrets in the release namespace before installing:

| Value | Default Secret name | Required key | Purpose |
| --- | --- | --- | --- |
| `existingSecret` | `openwarp-master` | `master-key` | Base64 text decoding to exactly 32 random bytes, shared by every replica |
| `existingDatabaseSecret` | `openwarp-database` | `database-url` | Shared Postgres connection URL |
| `existingRedisSecret` | unset | `redis-url` | Shared Redis connection URL, when configured |
| `metrics.existingSecret` | unset | `metrics-token` | Bearer token protecting `/metrics`, when configured |

The master key value is itself base64 text. When using Kubernetes Secret `data`,
encode that text again as Kubernetes requires, or use `stringData` instead.
Never generate a different master key for an existing database.

`existingDatabaseSecret` takes precedence over `databaseUrl`. To use a literal URL,
set `existingDatabaseSecret: ""` and supply `databaseUrl`. Likewise,
`existingRedisSecret` takes precedence over `redisUrl`. Prefer Secret references:
literal credentials are stored in Helm release values and rendered manifests.
Configured references use `optional: false` (Kubernetes has no `required` field
on secretKeyRef); unconfigured Redis and metrics references are omitted.

Set `env.OPENWARP_PUBLIC_URL` to the public HTTPS URL. For example, after preparing
Secrets and an image, install from the repository root:

```sh
helm upgrade --install openwarp deploy/helm/openwarp \
  --namespace openwarp --create-namespace \
  --set image.repository=YOUR_REGISTRY/openwarp \
  --set env.OPENWARP_PUBLIC_URL=https://openwarp.example.com
```

## High availability and background jobs

For HA, all replicas must use the same Postgres database, master key, and shared
Redis service when using the `redis-cache` feature. Redis is optional for the
server and this chart, but per-pod caches are not shared infrastructure. The
server image must include the Postgres and Redis features needed by your setup.
SQLite is not suitable for this multi-replica chart. No writable database volume
is mounted, and the root filesystem is read-only. Only `/tmp` has an `emptyDir`.

Leader election makes background jobs single-runner only when the server actually
implements that coordination. In this repository version, scheduled rotations use
an atomic Postgres slot claim to elect one runner per due rotation. Every replica
still polls; there is no dedicated cluster-wide leader-election service, and the
claim does not guarantee exactly-once completion after a crash. This chart does
not add election or Kubernetes lease permissions.

The PDB defaults to one available pod. Use `affinity` or `nodeSelector` to place
replicas across failure domains; the chart does not enforce placement. Configure
`resources`, `tolerations`, and security contexts for your cluster. Do not put
secrets in `env`; use `extraEnv` EnvVar entries with `valueFrom.secretKeyRef` for
additional credentials. Avoid duplicating chart-managed environment names.

## Ingress and operations

Enable `ingress.enabled`, set `ingress.className`, and configure `ingress.hosts`
(each host has `paths` with `path` and `pathType`). `ingress.tls` accepts standard
Kubernetes TLS entries with `secretName` and `hosts`. Supply TLS Secrets and an
ingress controller separately. The Service defaults to ClusterIP port 8080.

Both probes call `/health` on container port 8080. The Service has no session
affinity: any ready pod can take a request, and a pod that fails readiness stops
receiving new ones. `preStop` waits five seconds so the endpoints controller
drops the pod before the process drains, and `terminationGracePeriodSeconds` is
30. A WebSocket on `/api/live` is tied to the pod that accepted it and ends when
that pod stops; the client reconnects to whichever pod is ready. The default
ingress annotations raise the nginx read and send timeouts to an hour so that
socket is not cut off. Secret updates require a rollout restart because
environment variables are read at startup. No Secret contents or checksums are
embedded in the chart.

```sh
helm lint deploy/helm/openwarp
helm template openwarp deploy/helm/openwarp
```
