# XCLOAK Helm chart

Deploys the XCLOAK Security Suite backend (Go/Gin) and frontend (Next.js)
into Kubernetes, with optional bundled Postgres and Redis for evaluation
installs.

## Prerequisites

- Kubernetes 1.24+
- An ingress controller (nginx assumed by the default annotations; change
  `ingress.className`/`ingress.annotations` for a different controller)
- Backend and frontend images built and pushed (see `.github/workflows/docker-build.yml`)

## Quick start (bundled Postgres + Redis)

```sh
helm dependency update charts/xcloak
helm install xcloak charts/xcloak \
  --set global.ingress.host=xcloak.yourcompany.com \
  --set backend.image.tag=<git-sha-or-version> \
  --set frontend.image.tag=<git-sha-or-version>
```

Run `helm test xcloak` afterward to confirm both the backend and frontend
are serving traffic.

## Bringing your own Postgres/Redis

Set `postgresql.enabled: false` / `redis.enabled: false` and fill in the
matching `postgresqlExternal` / `redisExternal` block (host, port,
credentials via `existingSecret`). This is the supported path for
production deployments — bundled mode has no backup/replication story for
its single-node defaults.

## Kafka and MinIO

These are **not bundled** — verified live (2026-06-23) that Bitnami no
longer publishes free images for either. Both features are fully optional
from the app's own perspective:

- Without Kafka (`kafkaExternal.enabled: false`, the default): the IOC
  match event bus is simply disabled.
- Without MinIO (`minioExternal.enabled: false`, the default): immutable
  audit log export to object storage is simply disabled.

Set `kafkaExternal.enabled`/`minioExternal.enabled: true` and fill in the
rest only if you have an external Kafka cluster or S3-compatible store to
point at.

## Required Secret keys (if using `backend.secrets.existingSecret`)

If you supply your own pre-existing Secret (e.g. from Vault or an External
Secrets Operator pipeline) instead of letting the chart create one, it must
contain:

| Key | Required | Notes |
|---|---|---|
| `JWT_SECRET` | yes | Session signing key |
| `METRICS_TOKEN` | yes | Bearer token for `/metrics` |
| `ANTHROPIC_API_KEY` | only if using the Anthropic LLM provider | |
| `SMTP_PASS` | only if SMTP alerting is configured | |
| `DB_PASSWORD` | only if `postgresql.enabled: false` | |

## High availability

`backend.replicaCount` can safely be set above 1 — the backend's singleton
background jobs (audit export, scheduled-task dispatch, health scoring, KEV
refresh, offline-agent marking) are guarded by a Postgres advisory lock
(`services/leader_lock.go`), so only one replica runs a given job per tick.
This requires a backend image built after 2026-06-23; older images will
double-dispatch under more than one replica.

The frontend (`frontend.replicaCount`) is stateless and always safe to
scale.

## Known limitations

- `/api/health` is a liveness check only — it reflects cached circuit-
  breaker state, not a live DB ping, so it won't immediately detect
  Postgres dying mid-run. `/api/health/deep` does run a real `SELECT 1`
  against primary + replica with latency and pool stats; point a
  Kubernetes readiness probe there if you need that signal (it's not
  wired up as the chart's default readinessProbe today).
- `/metrics` is protected only by a static bearer token, not mTLS or a
  NetworkPolicy — it's deliberately not exposed on the public Ingress, but
  is reachable by anything else in-cluster. Restrict with a NetworkPolicy
  if that's a concern in your environment.
- The bundled Postgres/Redis (when enabled) are single-node — fine for
  evaluation, not a substitute for your own backup/HA story in production.
- `backend.podDisruptionBudget.minAvailable: 1` with `replicaCount: 1`
  will block voluntary node drains for the backend pod until you either
  raise replicas or temporarily relax the PDB — standard Kubernetes PDB
  behavior, not chart-specific, just worth knowing going in.

## Values

See `values.yaml` for the full set, each documented inline. Key sections:
`global.ingress.host` (single source of truth for the public URL),
`backend.*`, `frontend.*`, `ingress.*`, `postgresql.*`/`redis.*` (bundled),
`postgresqlExternal.*`/`redisExternal.*`/`kafkaExternal.*`/`minioExternal.*`
(BYO).
