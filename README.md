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
- **IOC Engine** — IP, domain, hash, URL, email indicator matching
- **Brute Force Detection** — automated SSH/auth log analysis
- **FIM** — file integrity monitoring with SHA256/MD5 hashing
- **Vulnerability Scanning** — CVE matching against installed packages

### Response (SOAR)
- **Playbooks** — automated response chains triggered by alert conditions
- **Agent Tasks** — remote execution: kill process, isolate host, quarantine file, FIM scan, script execution
- **Firewall Sync** — push iptables rules to agents from a central UI
- **Script Runner** — run bash/python scripts on agents with real-time output

### Investigation
- **Threat Hunt** — ad-hoc query across endpoint telemetry
- **Incident Management** — correlation, timeline, AI deep-dive reports
- **Network Map** — interactive force graph of agent connections with GeoIP
- **AI Triage** — Ollama/Claude-powered alert and incident analysis

### Compliance
- **SOC 2, NIST CSF, PCI-DSS, ISO 27001** — automated framework scoring
- **Audit Trail** — immutable log of all platform actions
- **Compliance Reports** — PDF-ready framework scoring reports

### Observability
- **Prometheus** — 16 custom metrics (threat score, alert rates, task queues)
- **Grafana** — pre-built dashboard with alert rate, agent health, SOAR execution
- **Kafka** — event bus for alerts, incidents, tasks, FIM, YARA across 6 topics

## Quick Start

### Prerequisites
- Go 1.21+
- Node.js 18+
- PostgreSQL 16
- Docker (for Kafka/Prometheus/Grafana)

### 1. Backend

```bash
cd xcloak-ngfw/backend

# Copy and configure environment
cp .env.example .env
# Edit .env — set DB credentials, JWT_SECRET, SMTP settings

# Generate a secure JWT secret
openssl rand -hex 32  # paste as JWT_SECRET in .env

# Run migrations
psql -U xcloak -d ngfw < database/schema.sql

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

# Security — REQUIRED
JWT_SECRET=<openssl rand -hex 32>

# AI (choose one)
LLM_PROVIDER=ollama          # or: anthropic
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=qwen2.5:3b
ANTHROPIC_API_KEY=           # if using Claude

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

### Agent (`xcloak-agent/.env`)

```env
# Only needed for first-time registration
XCLOAK_INSTALL_TOKEN=<generate from UI>
```

## Security

- JWT authentication with configurable expiry (8h access / 7d refresh)
- Token blacklist on logout
- Agent registration requires one-time install tokens (single-use, 24h expiry)
- TOTP 2FA support (RFC 4226 — works with Google Authenticator, Authy)
- Stale task expiry (destructive tasks expire after 15min, others after 1h)
- Role-based access control (admin / analyst)

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
| GET | `/api/agents` | List all agents |
| POST | `/api/scripts/run` | Execute script on agents |
| POST | `/api/firewall/sync` | Push firewall rules to agents |
| GET | `/api/kafka/status` | Kafka connection status |
| GET | `/metrics` | Prometheus metrics endpoint |

## Kafka Topics

| Topic | Events |
|-------|--------|
| `xcloak.alerts` | Alert created |
| `xcloak.incidents` | Incident opened |
| `xcloak.agent_tasks` | Task dispatched / completed |
| `xcloak.audit` | Admin actions |
| `xcloak.fim_alerts` | File integrity violations |
| `xcloak.yara_matches` | YARA signature matches |

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
| Database | PostgreSQL 16 |
| Agent | Go (single binary, no dependencies) |
| Message Bus | Apache Kafka |
| Metrics | Prometheus + Grafana |
| AI | Ollama (local) / Anthropic Claude |
| Auth | JWT + TOTP 2FA |

## License

MIT License — see [LICENSE](LICENSE) for details.

---

Built by [0xIdiot](https://github.com/0xIdiot)