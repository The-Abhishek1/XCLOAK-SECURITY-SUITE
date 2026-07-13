# XCloak Deployment Guide

For operators deploying and maintaining XCloak in production.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Quick Start](#quick-start)
3. [Production Docker Compose](#production-docker-compose)
4. [Kubernetes / Helm](#kubernetes--helm)
5. [Environment Variables Reference](#environment-variables-reference)
5. [Database](#database)
6. [Redis](#redis)
7. [Kafka](#kafka)
8. [Elasticsearch](#elasticsearch)
9. [MinIO (Audit Log)](#minio-audit-log)
10. [TLS](#tls)
11. [PgBouncer](#pgbouncer)
12. [HashiCorp Vault](#hashicorp-vault)
13. [Observability](#observability)
14. [Backups & Recovery](#backups--recovery)
15. [Upgrades](#upgrades)
16. [Tenant Provisioning](#tenant-provisioning)
17. [Agent Release Management](#agent-release-management)
18. [Troubleshooting](#troubleshooting)

---

## Prerequisites

| Component | Minimum version | Notes |
|-----------|----------------|-------|
| Go | 1.21 | Backend |
| Node.js | 18 | Frontend |
| PostgreSQL | 16 | Partitioning and RLS features required |
| Redis | 7 | Token revocation, rate limiting, pub/sub |
| Docker | 24 | For the observability stack |

Optional but recommended for production:
- Apache Kafka 3.x — event bus for IOC matching, async tasks
- Elasticsearch / OpenSearch 8.x — log search at scale
- MinIO — immutable audit export
- HashiCorp Vault — secret management, TOTP transit engine

---

## Quick Start

For evaluation or trying XCloak locally. No config required — secrets are generated automatically.

```bash
curl -fsSL https://raw.githubusercontent.com/The-Abhishek1/XCLOAK-SECURITY-SUITE/main/install.sh | bash
```

Or manually:

```bash
git clone --depth 1 https://github.com/The-Abhishek1/XCLOAK-SECURITY-SUITE.git
cd XCLOAK-SECURITY-SUITE
docker compose -f docker-compose.quickstart.yml up -d --build
```

Open `http://localhost:3000`. The first registered user becomes the tenant admin.

Migrations run automatically on backend startup. On first start you will see ~70 migration steps logged.

### Enroll the first agent

```bash
cd xcloak-agent-desktop
go build -o xcloak-agent-desktop ./main.go
./xcloak-agent-desktop
```

Generate an install token from **Settings → Integrations → Install Tokens** in the UI, then paste it when the agent prompts on first run. The token is single-use. After registration the agent saves its token and reconnects automatically.

**Autonomous collectors** start immediately after registration. Expect an initial burst of telemetry as all 15 collectors fire their first run (staggered by up to 30 s of random jitter). After that, collection intervals settle to:

| Collector | Interval |
|-----------|---------|
| Processes, connections, disk usage | 5 min |
| Auth logs | 2 min |
| auditd events | 30 s |
| eBPF TCP connect events | real-time |
| Services | 15 min |
| Users, kernel modules | 30 min |
| File hashes, cron jobs | 1 h |
| Packages, SUID/SGID scan | 6 h |

---

## Production Docker Compose

Use `docker-compose.yml` (the full stack) for production. It includes Kafka, MinIO, PgBouncer, Prometheus, and Grafana.

### 1. Configure

```bash
git clone --depth 1 https://github.com/The-Abhishek1/XCLOAK-SECURITY-SUITE.git
cd XCLOAK-SECURITY-SUITE
cp .env.example .env
```

Edit `.env` — at minimum set:

```env
DB_PASSWORD=<strong-password>
JWT_SECRET=$(openssl rand -hex 64)
METRICS_TOKEN=$(openssl rand -hex 32)
CORS_ALLOWED_ORIGINS=https://xcloak.yourdomain.com
APP_BASE_URL=https://xcloak.yourdomain.com
```

### 2. Start

```bash
docker compose up -d --build
```

This starts: PostgreSQL, Redis, Zookeeper, Kafka, Kafka UI, MinIO, PgBouncer, backend, seeder, frontend, Prometheus, Grafana.

### 3. TLS

Terminate TLS at a reverse proxy (Caddy, nginx, Traefik) in front of port 3000 (frontend) and 8080 (API). Leave `TLS_CERT_FILE` and `TLS_KEY_FILE` empty in `.env`.

### High availability

The backend is stateless — you can run multiple replicas behind a load balancer. Redis pub/sub ensures WebSocket alerts reach clients regardless of which replica they are connected to. All replicas must share the same PostgreSQL and Redis instances.

---

## Kubernetes / Helm

### Add the chart

```bash
helm repo add bitnami https://charts.bitnami.com/bitnami

helm dependency update charts/xcloak
helm install xcloak charts/xcloak \
  --namespace xcloak --create-namespace \
  --set global.ingress.host=xcloak.yourdomain.com \
  --set backend.env.JWT_SECRET=$(openssl rand -hex 32) \
  --set backend.env.METRICS_TOKEN=$(openssl rand -hex 32)
```

### Minimal values file

```yaml
# values-prod.yaml
backend:
  replicaCount: 3
  image:
    repository: ghcr.io/the-abhishek1/xcloak-backend
    tag: "latest"
  env:
    DB_SSLMODE: require
    LLM_PROVIDER: anthropic
    AUDIT_EXPORT_RETENTION_DAYS: "365"
  secrets:
    existingSecret: xcloak-secrets   # see below

frontend:
  replicaCount: 2
  image:
    repository: ghcr.io/the-abhishek1/xcloak-frontend
    tag: "latest"

postgresql:
  enabled: true
  auth:
    username: xcloak
    database: ngfw
    existingSecret: xcloak-pg-secret  # key: password

redis:
  enabled: true

pgbouncer:
  enabled: true

ingress:
  enabled: true
  className: nginx
  hosts:
    - host: xcloak.yourdomain.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: xcloak-tls
      hosts:
        - xcloak.yourdomain.com
```

### Create secrets

```bash
kubectl create secret generic xcloak-secrets \
  --from-literal=JWT_SECRET=$(openssl rand -hex 32) \
  --from-literal=METRICS_TOKEN=$(openssl rand -hex 32) \
  --from-literal=DB_PASSWORD=<strong-password>

kubectl create secret generic xcloak-pg-secret \
  --from-literal=password=<strong-password>
```

### Install

```bash
helm install xcloak ./charts/xcloak -f values-prod.yaml -n xcloak --create-namespace
```

### Upgrade

```bash
helm upgrade xcloak ./charts/xcloak -f values-prod.yaml -n xcloak
```

Migrations run automatically in an init container on every upgrade.

### High availability

The backend is stateless — scale horizontally freely. Redis pub/sub (enabled by default) ensures WebSocket alerts reach clients regardless of which replica they are connected to.

```yaml
backend:
  replicaCount: 3
  resources:
    requests:
      cpu: 250m
      memory: 256Mi
    limits:
      cpu: 1000m
      memory: 512Mi
```

---

## Environment Variables Reference

### Required

| Variable | Description |
|----------|-------------|
| `DB_HOST` | PostgreSQL host |
| `DB_PORT` | PostgreSQL port (default: 5432) |
| `DB_USER` | Database user |
| `DB_PASSWORD` | Database password |
| `DB_NAME` | Database name |
| `DB_SSLMODE` | `disable` / `require` / `verify-full` |
| `JWT_SECRET` | HS256 signing key — minimum 32 bytes of entropy |
| `METRICS_TOKEN` | Bearer token for `/metrics` endpoint |
| `CORS_ALLOWED_ORIGINS` | Frontend URL (e.g. `https://xcloak.yourdomain.com`) |
| `APP_BASE_URL` | Base URL for password-reset and invite email links (default: `http://localhost:3000`) — **must** be set to your public URL in production |

### Redis

| Variable | Default | Description |
|----------|---------|-------------|
| `REDIS_ADDR` | `localhost:6379` | Redis address |
| `REDIS_PASSWORD` | _(empty)_ | Redis password |

### AI

| Variable | Description |
|----------|-------------|
| `LLM_PROVIDER` | `ollama` or `anthropic` |
| `OLLAMA_URL` | Ollama base URL (if provider=ollama) |
| `OLLAMA_MODEL` | Model name (e.g. `qwen2.5:3b`) |
| `ANTHROPIC_API_KEY` | Anthropic API key (if provider=anthropic) |
| `ANTHROPIC_MODEL` | Model ID (default: `claude-sonnet-4-6`) |

### Kafka

| Variable | Default | Description |
|----------|---------|-------------|
| `KAFKA_ENABLED` | `false` | Set to `true` to enable |
| `KAFKA_BROKERS` | `localhost:9092` | Comma-separated broker list |
| `KAFKA_REQUIRE_ALL_ACKS` | `false` | Set `true` for `min.insync.replicas=2` clusters |

### Elasticsearch

| Variable | Description |
|----------|-------------|
| `ELASTICSEARCH_URL` | ES/OpenSearch URL (e.g. `http://elasticsearch:9200`) |
| `ELASTICSEARCH_USERNAME` | Optional basic auth username |
| `ELASTICSEARCH_PASSWORD` | Optional basic auth password |

### MinIO

| Variable | Description |
|----------|-------------|
| `MINIO_ENDPOINT` | MinIO endpoint (e.g. `minio:9000`) |
| `MINIO_ACCESS_KEY` | Access key |
| `MINIO_SECRET_KEY` | Secret key |
| `MINIO_AUDIT_BUCKET` | Bucket name for audit exports |
| `MINIO_USE_SSL` | `true` / `false` |
| `AUDIT_EXPORT_RETENTION_DAYS` | Days to retain audit exports (default: 365) |

### TLS (backend)

| Variable | Description |
|----------|-------------|
| `TLS_CERT_FILE` | Path to TLS certificate PEM |
| `TLS_KEY_FILE` | Path to TLS private key PEM |

Leave both empty to run plain HTTP (terminate TLS at ingress/load balancer instead).

### Agent release signing

| Variable | Description |
|----------|-------------|
| `AGENT_RELEASE_SIGNING_KEY` | base64url-encoded ed25519 seed (32 bytes) — used to sign agent releases |
| `AGENT_RELEASE_PUBLIC_KEY` | base64url-encoded ed25519 public key — stored on server for fingerprinting |
| `AGENT_RELEASE_REQUIRE_SIGNATURE` | `true` to reject unsigned release uploads |

Generate a keypair:

```bash
# Generate 32-byte seed
SEED=$(openssl rand 32 | base64 | tr '+/' '-_' | tr -d '=')
echo "AGENT_RELEASE_SIGNING_KEY=$SEED"

# Derive public key (Go snippet)
# The backend derives the public key from the seed automatically.
# To get the public key for embedding in agent builds:
go run ./cmd/keygen/main.go  # if provided, or use the backend /api/platform/agent-releases key info
```

### Logging (backend)

| Variable | Default | Description |
|----------|---------|-------------|
| `LOG_LEVEL` | `info` | `debug` / `info` / `warn` / `error` |
| `LOG_FORMAT` | `text` | `json` for structured production logging |

Set `LOG_FORMAT=json` in production to integrate with log aggregators.

### Agent (`xcloak-agent-desktop/.env`)

| Variable | Default | Description |
|----------|---------|-------------|
| `XCLOAK_INSTALL_TOKEN` | _(empty)_ | One-time install token for first registration (generate from UI → Settings → Install Tokens) |
| `SERVER_URL` | `http://localhost:8080` | Backend base URL |
| `XCLOAK_CA_CERT_PATH` | _(empty)_ | Path to PEM CA certificate for TLS verification against a private CA |
| `XCLOAK_INSECURE_SKIP_VERIFY` | `false` | Disable TLS verification — dev only |
| `XCLOAK_DISABLE_SELF_UPDATE` | `false` | Opt out of automatic binary self-update (for change-controlled environments) |
| `LOG_LEVEL` | `info` | `debug` / `info` / `warn` / `error` |
| `LOG_FORMAT` | `text` | `json` for structured output consumable by any log aggregator |

The agent reads `.env` from its working directory on startup (same precedence rules as the backend). Environment variables set in the OS environment take precedence over `.env` values.

### Vault

| Variable | Description |
|----------|-------------|
| `VAULT_ADDR` | HashiCorp Vault address |
| `VAULT_TOKEN` | Vault token (or use `existingSecret` in Helm) |

---

## Database

### Migrations

Migrations run automatically on backend startup via `golang-migrate`. The migration files are in `backend/database/migrations/`. There are 70 migrations as of the latest release.

To run migrations manually:

```bash
migrate -path backend/database/migrations \
        -database "postgres://xcloak:password@localhost/ngfw?sslmode=disable" up
```

### Row-Level Security

RLS is enforced at the database level. Every query is scoped to the current tenant via `SET LOCAL app.tenant_id = $1` before execution. This is transparent to the application layer but means you **must** use PgBouncer in transaction mode (not session mode) to avoid GUC leaking across connections.

### Partitioning

The `endpoint_logs` table is partitioned by `collected_at` in monthly partitions (`endpoint_logs_2026_06`, etc.). The scheduler creates next-month's partition automatically each day. Pre-existing data was attached as the `endpoint_logs_legacy` DEFAULT partition.

To manually create a partition for a given month:

```sql
SELECT create_endpoint_logs_partition('2026-08-01'::DATE);
```

### Retention

Set retention per tenant from the UI at **Settings → Log Retention**. The nightly retention job deletes logs older than the configured number of days. For partitioned data, whole-month partitions are deleted as a single fast operation when the entire partition is past the retention window.

---

## Redis

Redis is used for:
- **Token revocation** — JWT blacklist on logout
- **Rate limiting** — auth and API endpoints
- **WebSocket pub/sub** — `xcloak:ws:alerts` channel for multi-replica alert broadcasting

In production, use Redis Sentinel or Redis Cluster for HA. The `REDIS_ADDR` variable accepts a single address; for cluster/sentinel configure via the Helm `redis` section.

---

## Kafka

Kafka is optional. When disabled (`KAFKA_ENABLED=false`) all event bus operations are silently no-oped — the platform degrades gracefully.

### Production cluster (3-broker)

The bundled `docker-compose.yml` runs a single Kafka broker sufficient for most deployments.

In Helm, enable the bundled Kafka StatefulSet:

```yaml
kafka:
  enabled: true      # spins up 3-broker KRaft cluster
```

The Helm chart configures:
- `replication.factor=3` on all XCloak topics
- `min.insync.replicas=2` — writes require 2 of 3 replicas to acknowledge
- `KAFKA_REQUIRE_ALL_ACKS=true` in the backend — backend waits for all ISR acks

For an external cluster, use `kafkaExternal.enabled=true` and set `kafkaExternal.brokers` to your broker list.

### Topics and consumer groups

Every topic has a dedicated consumer group that runs inside the backend process. All consumers are no-ops when `KAFKA_ENABLED=false`.

**Panic isolation** — each consumer extracts per-message processing into a dedicated `process*Event()` function with its own `defer logRecover(...)`. A panic on a single malformed message is logged and discarded; the consumer loop continues. The outer `Start*Consumer` function also defers `logRecover` to catch setup panics.

| Topic | Consumer group | What the consumer does |
|-------|----------------|------------------------|
| `xcloak.alerts` | `xcloak-alert-consumer` | Index alert into `xcloak-alerts-<tenantID>` in Elasticsearch |
| `xcloak.incidents` | `xcloak-incident-consumer` | Fire webhook/Slack delivery (with retry); push WS notification to dashboards |
| `xcloak.agent_tasks` | `xcloak-task-consumer` | Maintain `AgentTasksPending` Prometheus gauge; push WS notification on task completion |
| `xcloak.audit` | `xcloak-audit-consumer` | Stream high-risk actions (ROLE_CHANGE, DELETE_USER, AGENT_TOKEN_ROTATED, etc.) to Splunk HEC in real time; Splunk tenant configs cached in-process for 2 minutes to reduce DB round-trips |
| `xcloak.fim_alerts` | `xcloak-fim-consumer` | Auto-create `quarantine_file` task (pending_approval) when critical system paths are modified or deleted |
| `xcloak.yara_matches` | `xcloak-yara-consumer` | Auto-create `quarantine_file` task (pending_approval) for each YARA-matched file |
| `xcloak.ioc_match_jobs` | `xcloak-ioc-matcher` | Run file hash and connection IOC matching off the ingest request path |

**FIM and YARA auto-quarantine notes:**
- Tasks enter the `pending_approval` queue — an operator must approve before the agent acts
- Destructive tasks that remain unapproved expire after 15 minutes (`ExpireStaleTasks`)
- Critical FIM paths: `/bin/*`, `/sbin/*`, `/usr/bin/*`, `/usr/sbin/*`, `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/ssh/*`, `/etc/cron*`, `/etc/ld.so.preload`

### Webhook delivery reliability

All outbound deliveries (Slack, PagerDuty, generic webhook, Splunk HEC, Jira, ServiceNow, Teams) go through `deliver()` in `webhook_service.go`, which applies exponential backoff retries:

| Attempt | Delay |
|---------|-------|
| 1 | immediate |
| 2 | 5 seconds |
| 3 | 30 seconds |

Network errors and 5xx responses are retried; 4xx failures are treated as permanent and not retried. SSRF-blocked URLs fail immediately without any retry. The final outcome (success/failure, HTTP status, error message) is recorded in the `webhook_deliveries` table and in `xcloak_webhook_deliveries_total` (see Prometheus metrics below).

---

## Elasticsearch

Elasticsearch (or OpenSearch) is optional. When `ELASTICSEARCH_URL` is not set, all log search goes through PostgreSQL.

When ES is configured:
- Logs are dual-written: Postgres remains the source of truth; ES is indexed asynchronously (non-blocking goroutine) after the Postgres commit
- Log search routes to ES first; falls back to Postgres if ES returns an error
- One log index per tenant: `xcloak-logs-<tenant_id>`
- One alert index per tenant: `xcloak-alerts-<tenant_id>` — alerts are indexed by the `xcloak-alert-consumer` Kafka consumer; requires `KAFKA_ENABLED=true`
- Index template `xcloak-logs` is registered on startup (idempotent)

### OpenSearch compatibility

The ES client uses the REST API only (no ES-specific SDK). OpenSearch 2.x is compatible — just set `ELASTICSEARCH_URL` to your OpenSearch endpoint.

---

## MinIO (Audit Log)

Audit logs are exported to MinIO under Object Lock (GOVERNANCE mode). This means:
- Exported objects cannot be deleted or modified until the retention period expires
- Not even the MinIO root user can delete them before expiry
- The export schedule is configurable per deployment; status is visible at **Audit → Export Status**

Set up MinIO Object Lock when creating the bucket:

```bash
mc mb --with-lock minio/xcloak-audit-log
mc retention set --default GOVERNANCE 365d minio/xcloak-audit-log
```

---

## TLS

### Option 1 — Terminate at reverse proxy (recommended)

Configure TLS in Caddy, nginx, or Traefik in front of port 8080 and 3000. Leave `TLS_CERT_FILE` and `TLS_KEY_FILE` empty in `.env`.

### Option 2 — Backend TLS

Set `TLS_CERT_FILE` and `TLS_KEY_FILE` to the paths of your certificate and private key inside the container. The backend listens on HTTPS directly.

```env
TLS_CERT_FILE=/etc/xcloak/tls/tls.crt
TLS_KEY_FILE=/etc/xcloak/tls/tls.key
```

Mount the cert files into the backend container via a `volumes:` entry in `docker-compose.yml`.

In Helm, set `backend.tls.enabled=true` and provide a cert secret:

```yaml
backend:
  tls:
    enabled: true
    secretName: xcloak-backend-tls
```

### Agent → Backend TLS

Set `XCLOAK_CA_CERT_PATH` on the agent to the CA certificate path for TLS verification. Set `XCLOAK_INSECURE_SKIP_VERIFY=true` to disable verification (development only).

---

## PgBouncer

PgBouncer sits between the backend and PostgreSQL. It pools connections and reduces connection overhead at scale (critical for 1,000+ agents sending concurrent log batches).

**Required mode: transaction pooling** — session pooling breaks RLS because the `SET LOCAL app.tenant_id` GUC would persist across different tenants' requests.

PgBouncer is included in `docker-compose.yml`. The backend's `DB_HOST` points to `pgbouncer:6432` rather than `postgres:5432`.

In Helm, enable PgBouncer:

```yaml
pgbouncer:
  enabled: true
  poolSize: 25        # connections per pool
  maxClientConn: 500
```

The backend automatically routes through PgBouncer when `pgbouncer.enabled=true`.

---

## HashiCorp Vault

Vault integration is optional. When enabled, it provides:
- **KV secrets** — per-tenant integration credentials (OIDC client secrets, Slack tokens, etc.) stored in Vault rather than Postgres
- **Transit engine** — TOTP secrets are encrypted/decrypted via Vault's transit engine instead of stored directly

Set `VAULT_ADDR` and `VAULT_TOKEN` in `.env`. The backend falls back to Postgres-only storage when Vault is not configured.

In Helm:

```yaml
vault:
  enabled: true
  addr: https://vault.yourdomain.com
  existingSecret: xcloak-vault-token  # key: token
```

---

## Observability

### Prometheus

The backend exposes a `/metrics` endpoint gated by the `METRICS_TOKEN` bearer token.

Add to your Prometheus scrape config:

```yaml
scrape_configs:
  - job_name: xcloak-backend
    static_configs:
      - targets: ['xcloak-backend:8080']
    authorization:
      credentials: <METRICS_TOKEN value>
```

### Grafana

The Docker Compose stack includes a pre-configured Grafana at `http://localhost:3001` (admin/xcloak). Dashboards cover request rates, database query latency, Kafka lag, and alert throughput.

In Kubernetes, configure Grafana via the `grafana` section of your `values.yaml`.

### Prometheus metrics — Kafka consumer lag

Seven gauges track per-consumer group message lag, each scraped from `reader.Stats().Lag`:

| Metric | Consumer group |
|--------|----------------|
| `xcloak_kafka_alert_consumer_lag` | `xcloak-alert-consumer` |
| `xcloak_kafka_incident_consumer_lag` | `xcloak-incident-consumer` |
| `xcloak_kafka_task_consumer_lag` | `xcloak-task-consumer` |
| `xcloak_kafka_audit_consumer_lag` | `xcloak-audit-consumer` |
| `xcloak_kafka_fim_consumer_lag` | `xcloak-fim-consumer` |
| `xcloak_kafka_yara_consumer_lag` | `xcloak-yara-consumer` |
| `xcloak_kafka_ioc_consumer_lag` | `xcloak-ioc-matcher` |

Alert if any consumer lag exceeds your SLA threshold (suggest: > 500 messages for more than 2 minutes).

### Prometheus metrics — Webhook deliveries

`xcloak_webhook_deliveries_total` is a CounterVec with three labels:

| Label | Values |
|-------|--------|
| `integration` | `splunk_audit`, `slack`, `pagerduty`, `webhook`, `jira`, `servicenow`, `teams`, etc. |
| `event_type` | e.g. `alert.created`, `incident.created`, `audit.ROLE_CHANGE` |
| `outcome` | `success` or `failure` |

Use this metric to build SLO dashboards on outbound delivery reliability. Example alert: failure rate > 5% for the `slack` integration over 5 minutes.

### Structured logs

Set `LOG_FORMAT=json` for JSON-structured logs compatible with any log aggregator (Loki, CloudWatch, Datadog, Splunk). Each log line includes `level`, `msg`, `time`, and contextual fields (`tenant_id`, `agent_id`, etc. where applicable).

All `fmt.Printf` / `fmt.Println` calls across the backend (services, API handlers, Kafka consumers) have been replaced with `log/slog` structured calls. There are no more unstructured log lines in the codebase — every operational event carries typed key-value fields that parse cleanly in any log aggregator.

The Go agent has the same structured-log treatment: `InitLogger()` is called at startup and honours the same `LOG_LEVEL` / `LOG_FORMAT` env vars. Set `LOG_FORMAT=json` on agents deployed to hosts whose logs are shipped to a SIEM (Splunk, Elastic, Datadog).

---

## Backups & Recovery

### Manual backup

```bash
./scripts/backup_db.sh
# Output: backups/ngfw_YYYYMMDD_HHMMSS.sql.gz
```

### Automated daily backup

Add to crontab:

```
0 2 * * * /path/to/xcloak/scripts/backup_db.sh >> /var/log/xcloak-backup.log 2>&1
```

Backups are pruned after `RETENTION_DAYS` days (default: 14). Set this in `scripts/backup_db.sh`.

### Restore

```bash
# DESTRUCTIVE — drops all tables and restores from the backup
./scripts/restore_db.sh backups/ngfw_20260630_020000.sql.gz
```

Always take a fresh backup before restoring.

### Docker volume backups

For Docker Compose deployments, supplement `pg_dump` with Docker volume backups using `docker run --rm -v postgres_data:/data -v /backups:/out busybox tar czf /out/postgres_data.tar.gz /data`.

### Kubernetes / persistent volumes

For Kubernetes deployments, back up the PostgreSQL PersistentVolume using your storage provider's snapshot feature (EBS snapshots, GCE disk snapshots, etc.) in addition to logical pg_dump backups.

---

## Upgrades

1. Back up the database.
2. Pull the new backend image (or build from source).
3. Restart the backend — migrations run automatically on startup.
4. Check `GET /api/health/deep` to confirm all subsystems are healthy.

**Rolling upgrades** — the backend is stateless. In Kubernetes, a rolling update is safe: new replicas come up (running new migrations) while old replicas continue serving. Because migrations are additive (no column drops or renames), old and new replicas can coexist during the rollout window.

**Migration squashing** — do not squash or remove migration files. Always add new migrations rather than editing existing ones.

---

## Tenant Provisioning

XCloak supports multi-tenancy. Each tenant is an isolated environment with its own agents, alerts, rules, users, and configuration.

### Create a tenant (platform admin only)

From the UI: **Platform → Tenants → New Tenant**. Set a name and optionally a primary domain.

Via API:

```bash
curl -X POST http://localhost:8080/api/platform/tenants \
  -H "Authorization: Bearer <platform-admin-token>" \
  -H "Content-Type: application/json" \
  -d '{"name": "Acme Corp", "domain": "acme.com"}'
```

### First user in a tenant

The first user to register on a tenant becomes that tenant's admin. Subsequent users default to the `analyst` role. Admins can change roles from **Settings → Users**.

### Tenant domains

Domains are used for SSO discovery (`GET /api/auth/sso-discover?domain=acme.com` returns the tenant's OIDC config). Add domains at **Platform → Tenants → [tenant] → Domains**.

### Disable a tenant

Toggle a tenant inactive from **Platform → Tenants → [toggle]**. Users and agents in that tenant can no longer log in or send data.

---

## Agent Release Management

Signed agent releases let endpoints self-update safely.

### Generate a signing keypair

```bash
# Backend derives the public key from the seed automatically.
# Generate a seed:
openssl rand 32 | base64 | tr '+/' '-_' | tr -d '='
# → set as AGENT_RELEASE_SIGNING_KEY
```

### Publish a release (platform admin)

```bash
curl -X POST http://localhost:8080/api/platform/agent-releases \
  -H "Authorization: Bearer <platform-admin-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "platform": "linux_amd64",
    "version": "2.0.0",
    "sha256": "<sha256-of-binary>",
    "signature": "<base64url-ed25519-signature>",
    "download_url": "https://releases.yourdomain.com/xcloak-agent-desktop-2.0.0-linux-amd64"
  }'
```

### Build agent with embedded public key

```bash
PUBLIC_KEY=$(cat public_key.b64)  # base64url of the 32-byte ed25519 public key
go build \
  -ldflags "-X xcloak-agent-desktop/agent.AgentReleasePublicKey=${PUBLIC_KEY}" \
  -o xcloak-agent-desktop ./main.go
```

Agents built without `-ldflags` skip signature verification (development builds only). Set `AGENT_RELEASE_REQUIRE_SIGNATURE=true` on the backend to reject any unsigned release upload.

---

## Mobile Agent Deployment (Android)

### Prerequisites

- Flutter 3.24.5 and Java 21 on the build machine
- Android SDK with a connected device or emulator (API 26+ recommended)
- A running XCloak backend reachable from the device network

### Build the APK

```bash
cd xcloak-agent-mobile
flutter pub get
flutter build apk --release
# APK at: build/app/outputs/flutter-apk/app-release.apk
```

> **Java compatibility**: Flutter 3.24.5 requires Java ≤ 21.
> `flutter config --jdk-dir=/usr/lib/jvm/java-21-openjdk-amd64`

### Generate an enrollment token

```bash
curl -X POST http://localhost:8080/api/mdm/enrollment-tokens \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{"ttl_hours": 24, "owner_email": "user@company.com"}'
# Returns: {"token": "enrl_...", "expires_at": "..."}
```

### Enroll a device

1. Install the APK on the Android device (`adb install app-release.apk`)
2. Open XCloak Agent → tap **Enroll Device**
3. Enter the Server URL and the enrollment token
4. Tap **Enroll** — the device posts a full posture snapshot and receives an agent token

On successful enrollment the backend receives: UDID, model, manufacturer, hardware, OS version, SDK int, security patch, build fingerprint, encryption status, root status, developer options, USB debugging, battery level, storage stats, RAM, network type.

### MDM check-in intervals

| Timer | Default | Env override |
|-------|---------|-------------|
| Device check-in | 5 min | not configurable on-device |
| Command poll | 2 min | not configurable on-device |
| Log forward | 10 min | not configurable on-device |
| App inventory | 30 min | not configurable on-device |
| Threat scan | 15 min | not configurable on-device |

All timers apply up to 30 s of random jitter on their first tick to avoid thundering-herd on fleet-wide reboots.

### Dispatch MDM commands

```bash
# Trigger an immediate posture refresh
curl -X POST http://localhost:8080/api/mdm/devices/<device-id>/commands \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{"command_type": "collect_posture"}'

# Push a message to the device user
curl -X POST http://localhost:8080/api/mdm/devices/<device-id>/commands \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{"command_type": "message", "payload": {"text": "Please update your OS."}}'

# Rotate the device agent token
curl -X POST http://localhost:8080/api/mdm/devices/<device-id>/commands \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{"command_type": "rotate_token"}'
```

### Unenroll a device remotely

```bash
curl -X DELETE http://localhost:8080/api/mdm/devices/<device-id> \
  -H "Authorization: Bearer <admin-token>"
```

The device receives a 403 on its next check-in and automatically wipes its credentials from Android Keystore.

---

## Troubleshooting

### Backend won't start — migration error

Check the migration log output. Common causes:
- Wrong `DB_*` credentials or the database doesn't exist
- A previous failed migration left the schema in a dirty state

To force-reset a dirty migration:

```bash
migrate -path backend/database/migrations \
        -database "postgres://..." force <version>
```

### `503 Service Unavailable` on all endpoints

The DB circuit breaker tripped. Check `/api/health/deep` — it will tell you which subsystem is down (Postgres, Redis, etc.). The circuit resets automatically once the subsystem recovers.

### Agents show offline immediately after heartbeat

Check that the backend clock is synced (NTP). Agents are considered offline after 5 minutes without a heartbeat. A clock skew of more than a few seconds between the agent host and the backend can cause false offline status.

### WebSocket alerts not appearing (multi-replica)

Verify Redis pub/sub is working: `redis-cli subscribe xcloak:ws:alerts` and trigger a test alert. If no messages arrive, check `REDIS_ADDR` is correct and the backend has `REDIS_ADDR` configured consistently across all replicas.

### Elasticsearch search returning no results

Check that the backend logged `elasticsearch: connected` on startup. If the per-tenant index (`xcloak-logs-<id>`) doesn't exist yet (no logs ingested since ES was enabled), search returns an empty result — this is expected.

### Kafka consumer lag growing

Check Kafka UI at `http://localhost:8090` and the Prometheus lag gauges. All 7 consumer groups run in the same backend process — if lag grows on any topic, check the relevant `xcloak_kafka_*_consumer_lag` metric and look for `slog.Error` log lines from that consumer.

Common causes:
- A single slow consumer blocks its topic; it does not block others — each runs in an independent goroutine
- `xcloak-fim-consumer` and `xcloak-yara-consumer` write to the DB for every message; high ingest rate during a sweep may cause lag — monitor `AgentTasksPending` alongside consumer lag
- Adding more backend replicas does **not** parallelize single-partition consumers — consider increasing topic partition count for `xcloak.fim_alerts` and `xcloak.yara_matches` if sustained lag is observed

Verify all consumer groups are registered:
```bash
kafka-consumer-groups.sh --bootstrap-server localhost:9092 --list | grep xcloak
```

### JWT errors after key rotation

Rotating `JWT_SECRET` invalidates all existing sessions. After rotation, all users must re-login. There is no zero-downtime key rotation in the current release — schedule maintenance accordingly or accept the session disruption.
