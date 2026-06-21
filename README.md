# XCloak Security Suite

An open-core enterprise security platform combining NGFW, SIEM, EDR, and SOAR capabilities. Built with Go, PostgreSQL, and Next.js.

![XCloak Dashboard](docs/dashboard.png)

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        XCloak Platform                          │
├──────────────┬──────────────┬──────────────┬────────────────────┤
│   Frontend   │   Backend    │    Agent     │  Observability     │
│  Next.js 14  │  Go / Gin    │  Go Binary   │  Prometheus        │
│  TypeScript  │  PostgreSQL  │  Linux/Win   │  Grafana           │
│  Port 3000   │  Port 8080   │  Endpoint    │  Kafka             │
└──────────────┴──────────────┴──────────────┴────────────────────┘
```

## Features

### Detection
- **Sigma Rules** — custom detection engine with field-level matching
- **YARA Rules** — malware signature scanning on endpoints
- **IOC Engine** — IP, domain, hash, URL, email indicator matching, async-matched off the request path via a Kafka consumer
- **Threat Intel Ingestion** — STIX/TAXII, MISP, and AlienVault OTX feed connectors alongside the original flat-file feed
- **Brute Force Detection** — automated SSH/auth log analysis
- **FIM** — file integrity monitoring with SHA256/MD5 hashing
- **Vulnerability Scanning** — CVE matching against installed packages

### Response (SOAR)
- **Playbooks** — automated response chains triggered by alert conditions, with a human-in-the-loop approval gate before any destructive action (kill process, isolate host, quarantine file, firewall changes, script execution) actually dispatches to an agent
- **Agent Tasks** — remote execution: kill process, isolate host, quarantine file, FIM scan, script execution
- **Firewall Sync** — push firewall rules to agents from a central UI; agents apply them locally
- **Script Runner** — run bash/python scripts on agents with real-time output

### Investigation
- **Threat Hunt** — ad-hoc query across endpoint telemetry
- **Incident Management** — correlation, timeline, AI deep-dive reports
- **Network Map** — interactive force graph of agent connections with GeoIP
- **AI Triage** — Ollama/Claude-powered alert and incident analysis

### Compliance
- **SOC 2, NIST CSF, PCI-DSS, ISO 27001** — automated framework scoring
- **Audit Trail** — immutable log of all platform actions, batch-exported to MinIO under Object Lock (WORM/GOVERNANCE retention) so it can't be altered or deleted even by an admin
- **Compliance Reports** — PDF-ready framework scoring reports

### Multi-Tenancy & Access Control
- **Tenants** — every agent, alert, rule, playbook, and integration is scoped to a tenant; platform operators provision/suspend tenants from a dedicated admin-only API
- **Custom Roles** — fine-grained, additive RBAC (19 permissions) on top of the built-in admin/analyst/viewer roles
- **SSO (OIDC)** — per-tenant generic OpenID Connect login
- **API Keys** — per-tenant, SHA-256-hashed keys for programmatic access, scoped to a role
- **TOTP 2FA** — RFC 4226, works with Google Authenticator/Authy

### Observability
- **Prometheus** — custom metrics (threat score, alert rates, task queues, Kafka consumer lag)
- **Grafana** — pre-built dashboards plus alerting rules (agent-offline storms, task backlog, consumer lag)
- **Kafka** — event bus for alerts, incidents, tasks, FIM, YARA, and async IOC matching

## Quick Start

### Prerequisites
- Go 1.21+
- Node.js 18+
- PostgreSQL 16
- Redis (rate limiting + token revocation state)
- Docker (for Kafka/Prometheus/Grafana/MinIO)

### 1. Backend

```bash
cd xcloak-ngfw/backend

# Copy and configure environment
cp .env.example .env
# Edit .env — set DB credentials, JWT_SECRET, METRICS_TOKEN, SMTP settings

# Generate a secure JWT secret and metrics token
openssl rand -hex 32  # paste as JWT_SECRET in .env
openssl rand -hex 32  # paste as METRICS_TOKEN in .env — also set in prometheus/metrics_token

# Migrations run automatically on startup (database/migrate.go applies
# database/migrations/*.sql via golang-migrate — no manual step needed)

# Start with hot reload
air
```

### 2. Frontend

```bash
cd xcloak-ngfw/frontend
npm install
npm run dev
```

### 3. Observability Stack

```bash
cd XCLOAK-SECURITY-SUITE
docker compose up -d
```

Services:
- Grafana: http://localhost:3001 (admin/xcloak)
- Prometheus: http://localhost:9090
- Kafka UI: http://localhost:8090
- MinIO Console: http://localhost:9001 (immutable audit log export target)

### 4. Agent

```bash
cd xcloak-agent
go build -o xcloak-agent ./main.go

# First run — will prompt for install token
# Generate one: XCloak UI → Agents → Add Agent
./xcloak-agent
```

After first registration, the agent token is saved to `~/.config/xcloak-agent/token` and reused on every subsequent start.

## Environment Variables

### Backend (`xcloak-ngfw/backend/.env`)

```env
# Database
DB_HOST=localhost
DB_PORT=5432
DB_USER=xcloak
DB_PASSWORD=your_password
DB_NAME=ngfw
DB_SSLMODE=disable           # set to require/verify-full in production
DB_SSLROOTCERT=
DB_SSLCERT=
DB_SSLKEY=

# Security — REQUIRED
JWT_SECRET=<openssl rand -hex 32>
METRICS_TOKEN=<openssl rand -hex 32>      # gates /metrics; also set in prometheus/metrics_token
CORS_ALLOWED_ORIGINS=http://localhost:3000

# Agent ↔ backend TLS (optional — agent defaults to plaintext if unset)
TLS_CERT_FILE=
TLS_KEY_FILE=

# AI (choose one)
LLM_PROVIDER=ollama          # or: anthropic
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=qwen2.5:3b
ANTHROPIC_API_KEY=           # if using Claude

# Redis — rate limiting + token revocation (fails open if unreachable)
REDIS_ADDR=localhost:6379

# MinIO — immutable audit log export (non-fatal to startup if unreachable)
MINIO_ENDPOINT=localhost:9000
MINIO_ACCESS_KEY=
MINIO_SECRET_KEY=
MINIO_AUDIT_BUCKET=xcloak-audit-log
MINIO_USE_SSL=false
AUDIT_EXPORT_RETENTION_DAYS=365

# Kafka
KAFKA_ENABLED=true
KAFKA_BROKER=localhost:9092

# Email alerts (optional)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your@gmail.com
SMTP_PASS=your_app_password
SMTP_FROM=xcloak@yourdomain.com
```

Per-tenant settings (OIDC SSO, threat feed credentials, API keys, custom roles) are configured from the UI and stored in the database, not as env vars — see Settings → SSO / Integrations / API Keys / Roles.

### Agent (`xcloak-agent/.env`)

```env
# Only needed for first-time registration
XCLOAK_INSTALL_TOKEN=<generate from UI>

# Override the backend URL (defaults to http://localhost:8080)
SERVER_URL=http://localhost:8080

# TLS to the backend (optional)
XCLOAK_CA_CERT_PATH=
XCLOAK_INSECURE_SKIP_VERIFY=false
```

## Security

- JWT authentication with configurable expiry (8h access / 7d refresh), Redis-backed token blacklist on logout
- Agent registration requires one-time install tokens (single-use, claimed atomically, 24h expiry)
- TOTP 2FA support (RFC 4226 — works with Google Authenticator, Authy)
- Multi-tenancy: tenant_id scoping enforced across agents, alerts, rules, playbooks, and integrations; tenant provisioning is platform-operator-only
- Role-based access control — built-in admin/analyst/viewer plus custom roles with 19 granular permissions
- Per-tenant SSO (generic OIDC) and per-tenant, SHA-256-hashed API keys
- SOAR actions that are destructive (kill process, isolate host, quarantine file, firewall changes, scripts) require human approval when triggered autonomously by a playbook; manual dispatch is unaffected
- Immutable audit log export to MinIO under Object Lock (GOVERNANCE retention) — verified at the storage layer to reject overwrites/deletes of exported batches
- Postgres and agent↔backend connections support TLS (`DB_SSLMODE`, `TLS_CERT_FILE`/`TLS_KEY_FILE`, agent's `XCLOAK_CA_CERT_PATH`)
- Stale task expiry (destructive tasks expire after 15min, others after 1h)

## Backups

```bash
# Manual backup (reads DB_* from xcloak-ngfw/backend/.env)
./scripts/backup_db.sh

# Restore (DESTRUCTIVE — drops and recreates every table first)
./scripts/restore_db.sh backups/ngfw_20260619_213343.sql.gz
```

For automated daily backups, add to crontab (`crontab -e`):
```
0 2 * * * /path/to/xcloak/scripts/backup_db.sh >> /var/log/xcloak-backup.log 2>&1
```
Backups land in `backups/` (gitignored — contains live data) and are pruned after `RETENTION_DAYS` (default 14).

## API

Base URL: `http://localhost:8080`

Authentication: `Authorization: Bearer <token>`

Key endpoints:

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/auth/login` | Login (returns JWT or 2FA prompt) |
| GET | `/api/alerts/paginated` | Paginated alerts with status filter |
| POST | `/api/alerts/:id/acknowledge` | Acknowledge alert |
| GET | `/api/incidents/paginated` | Paginated incidents |
| GET | `/api/agents` | List all agents (tenant-scoped) |
| POST | `/api/scripts/run` | Execute script on agents |
| POST | `/api/firewall/sync` | Push firewall rules to agents |
| GET | `/api/tasks/pending-approval` / POST `/api/tasks/:id/approve` | SOAR human-approval queue |
| GET/POST | `/api/threat-feeds` | List/create STIX·TAXII/MISP/OTX/flat-file threat feeds |
| GET/POST/DELETE | `/api/api-keys` | Per-tenant API key management |
| GET/POST/PUT/DELETE | `/api/custom-roles` | Granular custom role management |
| GET/POST/PATCH | `/api/platform/tenants` | Tenant provisioning (platform-admin only) |
| GET | `/api/audit/export/status` | Immutable audit export progress |
| GET | `/api/kafka/status` | Kafka connection status |
| GET | `/metrics` | Prometheus metrics endpoint (bearer-gated) |

## Kafka Topics

| Topic | Events |
|-------|--------|
| `xcloak.alerts` | Alert created |
| `xcloak.incidents` | Incident opened |
| `xcloak.agent_tasks` | Task dispatched / completed |
| `xcloak.audit` | Admin actions |
| `xcloak.fim_alerts` | File integrity violations |
| `xcloak.yara_matches` | YARA signature matches |
| `xcloak.ioc_match_jobs` | Async IOC matching jobs (consumed off the request path) |

## Agent Capabilities

| Task Type | Description |
|-----------|-------------|
| `collect_processes` | Snapshot running processes |
| `collect_connections` | Active network connections |
| `collect_packages` | Installed packages (for CVE scanning) |
| `collect_auth_logs` | Read /var/log/auth.log |
| `collect_file_hashes` | SHA256/MD5 file inventory |
| `fim_scan` | File integrity check against baseline |
| `vulnerability_scan` | Collect packages for server-side CVE matching |
| `kill_process` | Kill a process by PID |
| `isolate_host` | Block all traffic except XCloak server |
| `quarantine_file` | Move file to quarantine directory |
| `execute_script` | Run bash/sh/python3 script, return output |
| `apply_firewall_rules` | Apply iptables rules from XCloak |

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | Next.js 14, TypeScript, Tailwind CSS |
| Backend | Go 1.21, Gin, JWT |
| Database | PostgreSQL 16 (golang-migrate migrations) |
| Cache / State | Redis (rate limiting, token revocation) |
| Agent | Go (single binary, no dependencies) |
| Message Bus | Apache Kafka |
| Object Storage | MinIO (immutable audit log export, Object Lock) |
| Metrics | Prometheus + Grafana |
| AI | Ollama (local) / Anthropic Claude |
| Auth | JWT + TOTP 2FA + per-tenant OIDC SSO + API keys |

## License

MIT License — see [LICENSE](LICENSE) for details.

---

Built by [0xIdiot](https://github.com/0xIdiot)