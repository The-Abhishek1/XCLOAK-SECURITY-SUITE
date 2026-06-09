<div align="center">

```
        ██╗  ██╗ ██████╗██╗      ██████╗  █████╗ ██╗  ██╗
        ╚██╗██╔╝██╔════╝██║     ██╔═══██╗██╔══██╗██║ ██╔╝
        ╚███╔╝ ██║     ██║     ██║   ██║███████║█████╔╝ 
        ██╔██╗ ██║     ██║     ██║   ██║██╔══██║██╔═██╗ 
        ██╔╝ ██╗╚██████╗███████╗╚██████╔╝██║  ██║██║  ██╗
        ╚═╝  ╚═╝ ╚═════╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
```

**XCloak Security Suite**

*Next-Generation Open Security Platform*

[![Go](https://img.shields.io/badge/Go-1.22-00ADD8?style=flat-square&logo=go)](https://golang.org)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-336791?style=flat-square&logo=postgresql)](https://postgresql.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red?style=flat-square)](https://attack.mitre.org)
[![Status](https://img.shields.io/badge/Status-Active%20Development-yellow?style=flat-square)]()

</div>

---

## Overview

**XCloak Security Suite** is a self-hosted, open-architecture security operations platform combining NGFW, SIEM, EDR, and XDR capabilities into a single unified system. Built for security engineers who want full control — no black boxes, no vendor lock-in, no per-seat pricing that scales against you.

> Built from scratch. Every line intentional.

---

## Architecture

```
                          Internet
                              │
                    ┌─────────▼─────────┐
                    │   XCloak NGFW     │  ← Firewall Rule Engine
                    └─────────┬─────────┘
                              │
                    ┌─────────▼─────────┐
                    │   XCloak IDS/IPS  │  ← Sigma-Lite Detection
                    └─────────┬─────────┘
                              │
                       Internal Network
                              │
              ┌───────────────┼───────────────┐
              │               │               │
         Agent A         Agent B         Agent C
              │               │               │
              └───────────────┼───────────────┘
                              │
                    ┌─────────▼─────────┐
                    │   XCloak Server   │
                    │ ─────────────────│
                    │  SIEM  │  EDR    │
                    │  XDR   │  SOAR   │
                    │  IOC   │  MITRE  │
                    └─────────┬─────────┘
                              │
                         Grafana / UI
```

---

## Feature Modules

### 🔐 Authentication & Access Control
- JWT-based authentication with configurable expiry
- Role-Based Access Control (RBAC) — `admin` / `user` roles
- Full audit trail — every action logged with actor, timestamp, and details
- Request ID middleware for distributed tracing

### 🧱 NGFW — Next-Generation Firewall
- Full CRUD for firewall rules (source IP, dest IP, protocol, port, action)
- Enable/disable rules without deletion
- Firewall Sync Engine for rule propagation
- PostgreSQL-backed rule persistence

### 🖥️ Agent Management & EDR
- Lightweight agent registration (hostname, OS, IP)
- Heartbeat-based online/offline detection
- Endpoint inventory collection:
  - Running processes
  - Active network connections
  - Installed services
  - Package inventory
  - Local users
- Remote response actions:
  - `kill_process` — terminate by PID
  - `collect_file` — pull file from endpoint
  - `quarantine_file` — isolate malicious files
  - `execute_script` — run arbitrary commands
  - `isolate_host` — full network isolation

### 🔎 Detection Engine (Sigma-Lite)
- Dynamic rule evaluation engine (graduated from `strings.Contains` to a full Sigma-lite implementation)
- MITRE ATT&CK mapping on every rule (Tactic → Technique ID → Name)
- Rule CRUD with enable/disable toggle
- Rule test API — validate rules against sample log messages
- PostgreSQL-backed rule storage

### 🚨 Alert Management
- Automated alert creation from rule matches
- Alert deduplication — no duplicate noise
- MITRE context embedded in every alert
- Severity classification: `low` / `medium` / `high` / `critical`

### 🔗 Incident Engine (XDR)
- Cross-alert correlation into incidents
- Incident deduplication via fingerprinting
- Full incident timeline with event linkage
- Severity escalation logic

### 🧩 IOC Engine
- Indicator of Compromise database (IP-based, extensible)
- Real-time IOC matching against endpoint telemetry
- Enable/disable IOCs without deletion
- Full CRUD API

### 📊 Dashboard & Observability
- Unified overview: agents, alerts, incidents, inventory counts
- Per-agent summary view
- Grafana integration for metrics visualization

---

## Current Maturity

| Module | Status | Completeness |
|--------|--------|--------------|
| NGFW | ✅ Functional | 70% |
| SIEM | ✅ Functional | 75% |
| EDR | ✅ Functional | 80% |
| XDR | 🔄 In Progress | 55% |
| SOAR | 🔄 Early Stage | 15% |

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Go (Golang) |
| Database | PostgreSQL 16 |
| Auth | JWT (HS256) |
| Detection | Sigma-Lite (custom engine) |
| Threat Intel | MITRE ATT&CK Framework |
| Observability | Grafana |
| Agent Protocol | HTTP REST (polling) |

---

## API Reference

### Auth

```bash
# Register
POST /api/auth/register
{ "username": "admin", "email": "admin@xcloak.local", "password": "Password@123", "role": "admin" }

# Login
POST /api/auth/login
{ "username": "admin", "password": "Password@123" }
# → returns JWT token
```

### Firewall Rules

```bash
POST   /api/firewall/rules         # Create rule
GET    /api/firewall/rules         # List all rules
GET    /api/firewall/rules/:id     # Get rule by ID
PUT    /api/firewall/rules/:id     # Update rule
DELETE /api/firewall/rules/:id     # Delete rule
```

### Agents

```bash
POST /api/agents/register          # Register new agent
POST /api/agents/heartbeat         # Agent keepalive
GET  /api/agents                   # List all agents
GET  /api/agents/:id               # Get agent details
GET  /api/agents/:id/summary       # Get agent inventory summary
```

### Tasks & Response

```bash
POST /api/tasks                    # Dispatch task to agent
GET  /api/tasks/agent/:id          # Agent polls for pending tasks
POST /api/tasks/result             # Agent submits task result
```

**Supported task types:**

| Task Type | Description |
|-----------|-------------|
| `collect_processes` | Enumerate running processes |
| `collect_connections` | Enumerate network connections |
| `collect_services` | Enumerate running services |
| `collect_packages` | Enumerate installed packages |
| `collect_users` | Enumerate local users |
| `kill_process` | Kill process by PID |
| `execute_script` | Run shell script |
| `collect_file` | Retrieve file from endpoint |
| `quarantine_file` | Quarantine malicious file |
| `isolate_host` | Network-isolate the endpoint |

### Detection (Sigma Rules)

```bash
POST   /api/sigma/rules            # Create detection rule
GET    /api/sigma/rules            # List all rules
GET    /api/sigma/rules/:id        # Get rule by ID
PUT    /api/sigma/rules/:id        # Update rule
DELETE /api/sigma/rules/:id        # Delete rule
PATCH  /api/sigma/rules/:id/enable # Enable rule
PATCH /api/sigma/rules/:id/disable # Disable rule
POST   /api/sigma/rules/test       # Test rule against log sample
```

### Alerts & Incidents

```bash
GET /api/alerts                    # List all alerts
GET /api/incidents                 # List all incidents
GET /api/incidents/:id/events      # Get incident timeline
```

### IOC Engine

```bash
POST   /api/iocs                   # Create IOC
GET    /api/iocs                   # List all IOCs
GET    /api/iocs/:id               # Get IOC by ID
PUT    /api/iocs/:id               # Update IOC
DELETE /api/iocs/:id               # Delete IOC
PATCH  /api/iocs/:id/enable        # Enable IOC
PATCH  /api/iocs/:id/disable       # Disable IOC
```

### Audit & Dashboard

```bash
GET /api/audit/logs                # Full audit log
GET /api/dashboard/overview        # Platform-wide stats
GET /api/health                    # Health check
```

---

## Quick Start

### Prerequisites

- Go 1.22+
- PostgreSQL 16+
- Git

### Setup

```bash
# Clone the repository
git clone https://github.com/The-Abhishek1/Xcloak-Security-Suite
cd Xcloak-Security-Suite

# Configure environment
cd xcloak-ngfw/backend
# Run air
air

# Start the Agent
cd xcloak-agent
air
```

### Verify Installation

```bash
curl http://localhost:8080/api/health
# → {"service":"xcloak-ngfw","status":"healthy"}
```

### Deploy an Agent

```bash
# Register your first endpoint
curl -X POST http://localhost:8080/api/agents/register \
  -H "Content-Type: application/json" \
  -d '{"hostname":"DESKTOP-01","os":"Ubuntu 24.04","ip_address":"192.168.1.100"}'

# Start sending heartbeats from the agent binary
./xcloak-agent --server http://localhost:8080 --agent-id 1
```

---

## Detection Rule Example

```json
{
  "title": "Privilege Escalation via Sudo",
  "severity": "high",
  "mitre_tactic": "Privilege Escalation",
  "mitre_technique": "T1548",
  "mitre_name": "Abuse Elevation Control Mechanism",
  "keywords": ["sudo", "pam_unix", "session opened for user root"],
  "enabled": true
}
```

This rule fires on any log containing all keywords, creates an alert with MITRE context, and correlates into an incident if the threshold is crossed.

---

## Roadmap

- [ ] **SOAR Playbooks** — automated response chains triggered by alert conditions
- [ ] **Multi-tenancy** — organisation-scoped data isolation
- [ ] **IOC expansion** — domain, hash, URL indicator types
- [ ] **Threat Intel feeds** — STIX/TAXII ingestion, OTX integration
- [ ] **Web Dashboard** — React-based SOC analyst interface
- [ ] **Agent v2** — push-based websocket transport, replacing HTTP polling
- [ ] **Network tap mode** — passive traffic analysis for NGFW
- [ ] **Report generation** — PDF incident reports for compliance
- [ ] **Kubernetes deployment** — Helm chart for cloud-native deployments

---

## Project Structure

```
xcloak-security-suite/
|
├── xcloak-agent/
|   |
│   ├── agent/                # Agent
│   ├── config/               # Config Files
│   └── models/               # Model Files
├── xcloak-ngfw/
|     |
|     ├── backend
|     |   |   
|     │   ├── api/            # API Endpoint Files
|     │   ├── auth/           # Auth Files
|     │   ├── database/       # Database Config Files
|     │   ├── firewall/       # Firewall Files
|     │   ├── middleware/     # Middleware files
|     │   ├── models/         # Model Files
|     │   ├── repositories/   # Repo Files
|     │   ├── routes/         # Route File
|     │   ├── rules/          # Sigma Rule Files
|     │   ├── services/       # Services Files
|     │   └── main.go         # Entry point  
|     |
|     └── frontend            # Frontend Files
│            
└── README.md
```

---

## Contributing

Pull requests are welcome. For significant changes, open an issue first to discuss the direction.

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/soar-playbooks`)
3. Commit your changes (`git commit -m 'Add SOAR playbook engine'`)
4. Push and open a PR

---

## Author

**Abhishek** ([@0xIdiot](https://github.com/The-Abhishek1))  
MCA Cybersecurity Engineering · S-VYASA University, Bangalore  
TryHackMe Top 1% · PortSwigger Practitioner

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">

*Built with intent. Designed for defenders.*

</div>
