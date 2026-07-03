# XCloak Security Suite

An open-core enterprise security platform combining NGFW, SIEM, EDR, and SOAR capabilities. Built with Go, PostgreSQL, and Next.js — designed as a single solution for enterprises of all sizes.

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

## Detection Engines

### Threat Detection
- **Sigma Rules** — custom detection engine with field-level matching, tags, MITRE ATT&CK mapping
- **YARA Rules** — malware signature scanning on endpoints, real-time match reporting
- **IOC Engine** — IP, domain, hash, URL, email indicator matching; async-matched via Kafka consumer off the request path
- **Threat Intel Ingestion** — STIX/TAXII, MISP, and AlienVault OTX feed connectors plus flat-file feeds

### Network & Endpoint Behavioral Detectors (scheduled, per-tenant)

| Detector | Patterns | MITRE |
|----------|----------|-------|
| **C2 Beacon Detector** | CV-based interval analysis on periodic outbound connections | T1071, T1571 |
| **DNS Security** | DGA/Shannon entropy, DNS tunneling (payload length + query rate), flood detection | T1568.002, T1071.004 |
| **Port Scan + Lateral Movement** | Vertical, horizontal, SYN sweep; SMB spray detection | T1046, T1021.002 |
| **Data Exfiltration** | Volume flood (100MB+), session burst, cloud storage drain (S3/GDrive/OneDrive/Dropbox/Box/Mega), off-hours transfer | T1048, T1567.002 |
| **TLS/JA3 Fingerprinting** | Match TLS ClientHello hashes against blocklist of 13+ known C2 tools (Cobalt Strike, TrickBot, Emotet, Dridex, Sliver, Havoc, BruteRatel, etc.) | T1071.001 |
| **Credential Attacks** | SSH/RDP brute force per src_ip, password spray (≥5 usernames), credential stuffing (≥5 IPs/username), successful brute force | T1110, T1110.001, T1110.003, T1110.004 |
| **Privilege Escalation** | Windows EventID 4728/4732/4756 (group add), 4720 (new user), 4672 (special privs); Linux sudo/su/SUID/sudoers | T1098, T1136.001, T1548 |
| **Ransomware Behavior** | FIM mass-modification sweep + crypto extensions; kill-chain commands (vssadmin, wmic shadowcopy, bcdedit, wbadmin); security service kill (17 AV/EDR names) | T1486, T1490, T1562.001 |
| **Living-off-the-Land (LotL)** | Suspicious parent→child process chains (Office→PowerShell); LOLBin abuse (certutil, regsvr32, mshta, bitsadmin, wmic, rundll32, odbcconf); encoded PowerShell (-enc, IEX, DownloadString) | T1059, T1218, T1027 |
| **Impossible Travel** | GeoIP haversine distance (>900 km/h = suspicious); /16 subnet fallback for when GeoIP unavailable | T1078 |
| **Network Behavior Analytics** | Baseline deviation, anomalous connection patterns, protocol abuse | T1095 |
| **UEBA** | User and Entity Behavior Analytics — risk scoring across auth, file access, network | T1078, T1530 |

### Identity & Context Enrichment
- **AD/LDAP Identity Enrichment** — every alert auto-enriched with user display name, department, title from Active Directory; 3-tier cache (in-memory → DB → live LDAP)
- **Alert Investigation Context** — IOC hits, similar historical alerts, suggested cases, correlated Sigma rules for each alert
- **IP Enrichment** — GeoIP, ASN, proxy/hosting flags, port risk scoring

### Agentless Log Ingestion
- **Syslog Receiver** — UDP/TCP syslog ingest on port 5140; auto-parses CEF, LEEF, JSON, NDJSON, plain syslog
- **HTTP Log Source API** — REST endpoint with per-source API key auth; accepts any log format
- **Log Normalizer** — unified ParsedFields extraction across all formats: src_ip, dst_ip, user, auth_result, event_id, bytes_sent/recv, JA3 hash, command_line, parent_image, process name

## Response (SOAR)

- **Playbooks** — automated response chains triggered by alert conditions, with human-in-the-loop approval gate before any destructive action dispatches to an agent
- **AI Playbook Recommender** — Claude/Ollama suggests playbook chains based on MITRE technique and alert context
- **Agent Tasks** — remote execution: kill process, isolate host, quarantine file, FIM scan, script execution
- **Firewall Sync** — push firewall rules to agents from a central UI; agents apply them locally
- **Script Runner** — run bash/python scripts on agents with real-time output
- **Deception Technology** — honeypot management, canary token deployment, decoy file/user creation

## Investigation

- **Threat Hunt** — ad-hoc query across endpoint telemetry; Hunt Workbench for hypothesis tracking
- **Incident Management** — correlation, timeline, AI deep-dive reports, DFIR artifact collection
- **Network Map** — interactive force graph of agent connections with GeoIP
- **AI Triage** — Ollama/Claude-powered alert and incident analysis with MITRE context
- **Alert Clusters** — automatic grouping of related alerts by fingerprint and technique
- **Correlation Engine** — cross-source pattern matching, multi-stage attack detection
- **Threat Actor Intelligence** — threat actor profiles with TTPs, attribution, associated IOCs
- **Timeline** — unified attack timeline across all agents and events
- **Attack Paths** — visualize lateral movement and privilege escalation chains

## Risk & Compliance

- **Risk Posture Score** — continuous tenant-level risk scoring across detection coverage, vulnerabilities, and alert trends
- **SOC 2, NIST CSF, PCI-DSS, ISO 27001** — automated framework scoring
- **SOC Metrics** — MTTD, MTTR, alert volume, analyst performance tracking
- **Vulnerability Priority Queue** — EPSS + KEV + asset criticality weighted prioritization
- **Audit Trail** — immutable log of all platform actions, batch-exported to MinIO under Object Lock (WORM/GOVERNANCE) so it can't be altered or deleted even by an admin
- **Executive Reports** — PDF-ready risk summaries and compliance scoring

## Integrations

| Integration | Purpose |
|-------------|---------|
| **Slack** | Real-time alert notifications |
| **Webhook** | Generic outbound events for any SIEM/SOAR |
| **Email** | Alert email delivery with severity filtering |
| **PagerDuty** | Incident escalation |
| **Microsoft Teams** | Alert cards via Incoming Webhook |
| **Jira** | Auto-create tickets from alerts/incidents |
| **ServiceNow** | Incident creation via Table API |
| **Active Directory / LDAP** | Identity enrichment on all alerts |
| **OIDC / SSO** | Per-tenant single sign-on |

## Multi-Tenancy & Access Control

- **Tenants** — every agent, alert, rule, playbook, and integration is scoped to a tenant
- **Custom Roles** — fine-grained, additive RBAC (19 permissions) on top of built-in admin/analyst/viewer
- **SSO (OIDC)** — per-tenant generic OpenID Connect login
- **API Keys** — per-tenant, SHA-256-hashed keys scoped to a role
- **TOTP 2FA** — RFC 4226, works with Google Authenticator/Authy
- **Session Management** — active session listing and remote revocation

## Documentation

| Guide | Audience |
|-------|---------|
| [User Guide](docs/user-guide.md) | SOC analysts — alerts, incidents, threat hunting, detection rules, AI tools |
| [Deployment Guide](docs/deployment-guide.md) | Operators — production setup, Kubernetes/Helm, TLS, Kafka, Elasticsearch, backups |
| [Agent Deployment](docs/agent-deployment.md) | Sysadmins — installing and managing the agent on Linux, Windows, and macOS |
| [Security Audit Prep](docs/security-audit-prep.md) | Security team — controls inventory, pentest scope, known gaps |

---

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

# Generate secure secrets
openssl rand -hex 32  # paste as JWT_SECRET in .env
openssl rand -hex 32  # paste as METRICS_TOKEN in .env — also set in prometheus/metrics_token

# Migrations run automatically on startup (golang-migrate, 38 migrations)
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

### 5. Agentless Log Sources (Syslog / HTTP)

```bash
# Syslog (UDP/TCP, port 5140) — configure your firewall/switch to forward here
# CEF, LEEF, JSON, NDJSON, plain syslog all auto-detected

# HTTP — create a log source in UI → Log Sources → Add → HTTP
# Then POST logs with the generated API key:
curl -X POST http://localhost:8080/api/ingest/http/<source-id> \
  -H "Authorization: Bearer <api-key>" \
  -H "Content-Type: application/json" \
  -d '{"timestamp":"2026-06-29T12:00:00Z","src_ip":"10.0.0.1","event":"login_failed","user":"admin"}'
```

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

# Security — REQUIRED
JWT_SECRET=<openssl rand -hex 32>
METRICS_TOKEN=<openssl rand -hex 32>
CORS_ALLOWED_ORIGINS=http://localhost:3000

# Agent ↔ backend TLS (optional)
TLS_CERT_FILE=
TLS_KEY_FILE=

# AI (choose one)
LLM_PROVIDER=ollama          # or: anthropic
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=qwen2.5:3b
ANTHROPIC_API_KEY=           # if using Claude

# Redis — rate limiting + token revocation
REDIS_ADDR=localhost:6379

# MinIO — immutable audit log export
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

Per-tenant settings (OIDC SSO, LDAP, threat feed credentials, API keys, custom roles) are configured from the UI and stored in the database — see Settings → Integrations / API Keys / Roles.

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

- JWT authentication (8h access / 7d refresh), Redis-backed token blacklist on logout
- Agent registration requires one-time install tokens (single-use, claimed atomically, 24h expiry)
- TOTP 2FA (RFC 4226 — Google Authenticator, Authy)
- Multi-tenancy: `tenant_id` scoping enforced across all resources; platform provisioning is operator-only
- RBAC — built-in admin/analyst/viewer plus custom roles with 19 granular permissions
- Per-tenant SSO (OIDC) and per-tenant SHA-256-hashed API keys
- SOAR destructive actions require human approval when triggered by playbooks
- Immutable audit log to MinIO under Object Lock (GOVERNANCE retention)
- TLS support for Postgres and agent↔backend (`DB_SSLMODE`, `TLS_CERT_FILE`/`TLS_KEY_FILE`)
- Stale task expiry: destructive tasks expire after 15 min, others after 1h

## Backups

```bash
# Manual backup (reads DB_* from xcloak-ngfw/backend/.env)
./scripts/backup_db.sh

# Restore (DESTRUCTIVE — drops and recreates every table first)
./scripts/restore_db.sh backups/ngfw_20260619_213343.sql.gz
```

For automated daily backups, add to crontab:
```
0 2 * * * /path/to/xcloak/scripts/backup_db.sh >> /var/log/xcloak-backup.log 2>&1
```
Backups land in `backups/` (gitignored) and are pruned after `RETENTION_DAYS` (default 14).

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
| GET/POST | `/api/tasks/pending-approval` | SOAR human-approval queue |
| GET/POST/DELETE | `/api/sigma/rules` | Sigma rule management |
| GET/POST/DELETE | `/api/yara/rules` | YARA rule management |
| GET/POST/DELETE | `/api/ja3/fingerprints` | JA3 TLS fingerprint blocklist |
| GET/POST/DELETE | `/api/log-sources` | Agentless log source management |
| POST | `/api/ingest/http/:id` | HTTP log ingest endpoint |
| GET | `/api/identity` | AD/LDAP identity cache viewer |
| GET/POST | `/api/threat-feeds` | STIX·TAXII/MISP/OTX/flat-file feed management |
| GET/POST/DELETE | `/api/api-keys` | Per-tenant API key management |
| GET/POST/PUT/DELETE | `/api/custom-roles` | Granular custom role management |
| GET/POST/PATCH | `/api/platform/tenants` | Tenant provisioning (platform-admin only) |
| GET | `/api/audit/export/status` | Immutable audit export progress |
| GET | `/metrics` | Prometheus metrics (bearer-gated) |

## Kafka Topics

| Topic | Events |
|-------|--------|
| `xcloak.alerts` | Alert created |
| `xcloak.incidents` | Incident opened |
| `xcloak.agent_tasks` | Task dispatched / completed |
| `xcloak.audit` | Admin actions |
| `xcloak.fim_alerts` | File integrity violations |
| `xcloak.yara_matches` | YARA signature matches |
| `xcloak.ioc_match_jobs` | Async IOC matching jobs |

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
| Database | PostgreSQL 16 (golang-migrate, 38 migrations) |
| Cache / State | Redis (rate limiting, token revocation) |
| Agent | Go (single binary, no dependencies) |
| Message Bus | Apache Kafka |
| Object Storage | MinIO (immutable audit log, Object Lock) |
| Metrics | Prometheus + Grafana |
| AI | Ollama (local) / Anthropic Claude |
| Auth | JWT + TOTP 2FA + per-tenant OIDC SSO + API keys |
| Identity | Active Directory / LDAP (go-ldap/v3) |

## License

XCloak Security Suite is licensed under the
[Business Source License 1.1](LICENSE).

- **Free** for non-commercial use and self-hosted deployments up to 10 agents
- **Commercial license required** for production SaaS or commercial deployments
- Converts to Apache 2.0 on 2029-01-01

For commercial licensing: abhishekn1003@gmail.com

---

Built by [0xIdiot](https://github.com/The-Abhishek1)
