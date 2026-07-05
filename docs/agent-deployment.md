# XCloak Agent Deployment Guide

For sysadmins installing and managing the XCloak agent on endpoints.

---

## Table of Contents

1. [Overview](#overview)
2. [Supported Platforms](#supported-platforms)
3. [Generating an Install Token](#generating-an-install-token)
4. [Installation](#installation)
   - [Linux](#linux)
   - [Windows](#windows)
   - [macOS](#macos)
5. [Configuration](#configuration)
6. [What the Agent Collects](#what-the-agent-collects)
7. [File Integrity Monitoring](#file-integrity-monitoring)
8. [Self-Update](#self-update)
9. [Firewall Requirements](#firewall-requirements)
10. [Running at Scale](#running-at-scale)
11. [Uninstalling](#uninstalling)
12. [Troubleshooting](#troubleshooting)
13. [Android Mobile Agent](#android-mobile-agent)

---

## Overview

The XCloak agent is a single Go binary with no runtime dependencies. It runs as a system service, sends telemetry to the XCloak backend every 30–60 seconds, and executes tasks dispatched from the UI (process kills, host isolation, file quarantine, script execution, etc.).

The agent authenticates to the backend using a per-device token stored locally after registration. Install tokens are single-use and expire after 24 hours.

---

## Supported Platforms

| OS | Architecture | Notes |
|----|-------------|-------|
| Linux (kernel 3.10+) | amd64, arm64 | Tested on Ubuntu 20.04/22.04, RHEL 8/9, Debian 11/12 |
| Windows | amd64 | Windows 10/11, Server 2016/2019/2022 |
| macOS | amd64, arm64 (Apple Silicon) | macOS 12 Monterey and later |

---

## Generating an Install Token

Before installing the agent on any endpoint, generate a single-use install token from the XCloak UI.

1. Log in as an admin.
2. Go to **Settings → Integrations → Install Tokens**.
3. Click **Generate Token**.
4. Copy the token — it is only shown once and expires in 24 hours.

One token can be used once to register one agent. Generate a token for each endpoint, or use a deployment script that calls the API to generate tokens programmatically:

```bash
curl -X POST http://xcloak.yourdomain.com/api/integrations/install-tokens \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json"
# Returns: {"token": "xck_install_...", "expires_at": "..."}
```

---

## Installation

### Linux

**Download the binary**

```bash
curl -Lo xcloak-agent https://releases.yourdomain.com/xcloak-agent-latest-linux-amd64
chmod +x xcloak-agent
sudo mv xcloak-agent /usr/local/bin/xcloak-agent
```

**Register (first run)**

```bash
export SERVER_URL=https://xcloak.yourdomain.com
export XCLOAK_INSTALL_TOKEN=<token-from-ui>
sudo -E xcloak-agent
```

The agent registers, saves its device token to `/etc/xcloak/token`, and begins sending telemetry. Press Ctrl+C after confirming it is online in the UI.

**Install as a systemd service**

Create `/etc/systemd/system/xcloak-agent.service`:

```ini
[Unit]
Description=XCloak Security Agent
After=network.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/xcloak-agent
Restart=always
RestartSec=10
Environment=SERVER_URL=https://xcloak.yourdomain.com
EnvironmentFile=-/etc/xcloak/agent.env
# Run as root to access system logs, process list, network stats, and FIM paths
User=root
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now xcloak-agent
sudo systemctl status xcloak-agent
```

View logs:

```bash
journalctl -u xcloak-agent -f
```

### Windows

**Download**

Download `xcloak-agent-latest-windows-amd64.exe` from your releases URL.

**Register (first run — run as Administrator)**

```powershell
$env:SERVER_URL = "https://xcloak.yourdomain.com"
$env:XCLOAK_INSTALL_TOKEN = "<token-from-ui>"
.\xcloak-agent.exe
```

The agent saves its device token to `%ProgramData%\xcloak\token`.

**Install as a Windows service**

```powershell
sc.exe create XCloakAgent binPath= "C:\Program Files\XCloak\xcloak-agent.exe" start= auto
sc.exe description XCloakAgent "XCloak Security Agent"
sc.exe start XCloakAgent
```

Or use `nssm` (Non-Sucking Service Manager) for easier environment variable management:

```powershell
nssm install XCloakAgent "C:\Program Files\XCloak\xcloak-agent.exe"
nssm set XCloakAgent AppEnvironmentExtra "SERVER_URL=https://xcloak.yourdomain.com"
nssm start XCloakAgent
```

### macOS

**Download**

```bash
curl -Lo xcloak-agent https://releases.yourdomain.com/xcloak-agent-latest-darwin-arm64
chmod +x xcloak-agent
sudo mv xcloak-agent /usr/local/bin/xcloak-agent
```

**Register**

```bash
export SERVER_URL=https://xcloak.yourdomain.com
export XCLOAK_INSTALL_TOKEN=<token-from-ui>
sudo -E xcloak-agent
```

**Install as a launchd service**

Create `/Library/LaunchDaemons/com.xcloak.agent.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.xcloak.agent</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/xcloak-agent</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>SERVER_URL</key>
    <string>https://xcloak.yourdomain.com</string>
  </dict>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>/var/log/xcloak-agent.log</string>
  <key>StandardErrorPath</key>
  <string>/var/log/xcloak-agent-error.log</string>
</dict>
</plist>
```

```bash
sudo launchctl load /Library/LaunchDaemons/com.xcloak.agent.plist
```

---

## Configuration

The agent reads configuration from environment variables. The only required variable after initial registration is `SERVER_URL`.

| Variable | Default | Description |
|----------|---------|-------------|
| `SERVER_URL` | `http://localhost:8080` | XCloak backend URL |
| `XCLOAK_INSTALL_TOKEN` | _(required on first run only)_ | Single-use registration token |
| `XCLOAK_CA_CERT_PATH` | _(empty)_ | Path to CA certificate for TLS verification |
| `XCLOAK_INSECURE_SKIP_VERIFY` | `false` | Skip TLS certificate verification (dev only) |
| `XCLOAK_DISABLE_SELF_UPDATE` | `false` | Set `true` to disable self-update checks |
| `XCLOAK_AGENT_LABEL` | hostname | Custom label shown in the UI agent list |

Store environment variables on Linux in `/etc/xcloak/agent.env` (referenced by the systemd `EnvironmentFile`). On Windows use the service environment settings.

### Token storage

After registration, the device token is saved at:
- **Linux/macOS:** `/etc/xcloak/token` (root-owned, mode 0600)
- **Windows:** `%ProgramData%\xcloak\token`

Do not copy or share this file between hosts. Each endpoint must have its own unique token.

---

## What the Agent Collects

The agent sends the following telemetry to the backend. All data is scoped to your tenant and never shared.

| Data | Interval | Notes |
|------|----------|-------|
| Heartbeat | 30s | Agent status and version |
| Process list | 60s | Running processes with PID, command line, parent PID |
| Network connections | 60s | Active TCP/UDP connections with remote IP and port |
| Auth events | On change | Login/logout, sudo, privilege escalation from auth log |
| Windows Event Log | On change | Security events (4624, 4625, 4672, 4720, 4728, etc.) |
| Installed packages | On demand | Triggered by vulnerability scan task |
| Local users | On demand | User account list |
| Running services | On demand | Service name, status, start type |
| File hashes | On demand | SHA-256 of specified paths |
| FIM events | On file change | File create/modify/delete/permission change |
| YARA matches | On file access | Malware signatures from enabled YARA rules |
| Registry entries | On demand (Windows) | Registry key values |

**On-demand collections** are triggered by tasks dispatched from the XCloak UI or by scheduled tasks.

### What the agent does NOT collect

- File contents (only hashes and metadata)
- Keystrokes or clipboard
- Screenshots
- Personal documents or user data

---

## File Integrity Monitoring

FIM monitors specified paths for changes in real time.

### Default monitored paths

| Platform | Paths |
|----------|-------|
| Linux | `/etc/`, `/bin/`, `/sbin/`, `/usr/bin/`, `/usr/sbin/`, `/boot/` |
| Windows | `C:\Windows\System32\`, `C:\Windows\SysWOW64\`, registry hives |
| macOS | `/etc/`, `/usr/bin/`, `/usr/sbin/`, `/Library/LaunchDaemons/` |

### Configuring FIM paths

FIM configuration is managed from the XCloak UI, not the agent config file. Go to **Agents → [agent] → FIM** to view monitored paths.

### Accepting the baseline

After the first FIM scan, the agent reports all monitored files as the initial baseline. Accept the baseline from **Agents → [agent] → FIM → Accept Baseline** to mark the current state as trusted. Subsequent changes will generate FIM alerts.

Run a manual FIM scan at any time by dispatching a `fim_scan` task from the agent detail page.

---

## Self-Update

The agent checks for new releases every 6 hours by polling `GET /api/agent-releases/<platform>`.

When a newer version is available:
1. The agent downloads the new binary to a temporary path.
2. Verifies the SHA-256 checksum matches the published value.
3. If the binary was built with an embedded public key, verifies the ed25519 signature. If verification fails, the update is rejected and the current binary continues running.
4. Replaces the running binary and restarts.

**Disable self-update** — set `XCLOAK_DISABLE_SELF_UPDATE=true` if you manage agent versions through your own deployment pipeline.

**Rollback** — the old binary is kept as a backup at the same path with a `.bak` extension for manual rollback if needed.

---

## Firewall Requirements

The agent makes outbound connections only — no inbound ports need to be opened.

| Direction | Protocol | Port | Destination | Purpose |
|-----------|----------|------|-------------|---------|
| Outbound | HTTPS | 443 | XCloak backend | All agent communication |
| Outbound | HTTPS | 443 | Release server | Self-update binary downloads |

If the agent is behind an HTTP proxy, set the standard `HTTPS_PROXY` environment variable.

The agent does **not** require DNS resolution beyond the backend hostname. If deploying in restricted environments, you can use an IP address as `SERVER_URL`.

---

## Running at Scale

### Mass deployment with Ansible

```yaml
# xcloak-agent.yml
- name: Deploy XCloak Agent
  hosts: all
  become: yes
  vars:
    xcloak_server: https://xcloak.yourdomain.com
    xcloak_version: latest

  tasks:
    - name: Download agent binary
      get_url:
        url: "https://releases.yourdomain.com/xcloak-agent-{{ xcloak_version }}-linux-{{ ansible_architecture }}"
        dest: /usr/local/bin/xcloak-agent
        mode: '0755'

    - name: Generate install token
      uri:
        url: "{{ xcloak_server }}/api/integrations/install-tokens"
        method: POST
        headers:
          Authorization: "Bearer {{ xcloak_admin_token }}"
        status_code: 200
      register: token_response
      delegate_to: localhost

    - name: Register agent (if not already registered)
      command: /usr/local/bin/xcloak-agent
      environment:
        SERVER_URL: "{{ xcloak_server }}"
        XCLOAK_INSTALL_TOKEN: "{{ token_response.json.token }}"
      args:
        creates: /etc/xcloak/token  # skip if token file already exists

    - name: Install systemd service
      copy:
        dest: /etc/systemd/system/xcloak-agent.service
        content: |
          [Unit]
          Description=XCloak Security Agent
          After=network.target
          [Service]
          ExecStart=/usr/local/bin/xcloak-agent
          Restart=always
          RestartSec=10
          Environment=SERVER_URL={{ xcloak_server }}
          User=root
          [Install]
          WantedBy=multi-user.target

    - name: Enable and start agent service
      systemd:
        name: xcloak-agent
        enabled: yes
        state: started
        daemon_reload: yes
```

### Deployment via Group Policy (Windows)

1. Place `xcloak-agent.exe` on a network share accessible by all machines.
2. Create a GPO startup script that:
   - Copies the binary to `C:\Program Files\XCloak\xcloak-agent.exe`
   - Calls a provisioning script that generates a token via the API and runs the agent with `XCLOAK_INSTALL_TOKEN` set
   - Installs the Windows service
3. Apply the GPO to the relevant OUs.

### Token generation at scale

For mass deployment where you need many tokens at once, call the API in a loop from your deployment script:

```bash
for host in $(cat hosts.txt); do
  TOKEN=$(curl -s -X POST http://xcloak.yourdomain.com/api/integrations/install-tokens \
    -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r .token)
  ssh $host "export XCLOAK_INSTALL_TOKEN=$TOKEN SERVER_URL=https://xcloak.yourdomain.com && sudo -E /usr/local/bin/xcloak-agent &"
done
```

---

## Uninstalling

### Linux

```bash
sudo systemctl stop xcloak-agent
sudo systemctl disable xcloak-agent
sudo rm /etc/systemd/system/xcloak-agent.service
sudo systemctl daemon-reload
sudo rm /usr/local/bin/xcloak-agent
sudo rm -rf /etc/xcloak/
```

Remove the agent from XCloak: go to **Agents → [agent] → Delete**.

### Windows

```powershell
sc.exe stop XCloakAgent
sc.exe delete XCloakAgent
Remove-Item -Recurse "C:\Program Files\XCloak"
Remove-Item -Recurse "$env:ProgramData\xcloak"
```

### macOS

```bash
sudo launchctl unload /Library/LaunchDaemons/com.xcloak.agent.plist
sudo rm /Library/LaunchDaemons/com.xcloak.agent.plist
sudo rm /usr/local/bin/xcloak-agent
sudo rm -rf /etc/xcloak/
```

---

## Troubleshooting

### Agent registers but shows as offline immediately

The backend marks agents offline after 5 minutes without a heartbeat. Check:
1. `SERVER_URL` points to the correct backend address and is reachable from the endpoint.
2. TLS certificate is valid. If using a private CA, set `XCLOAK_CA_CERT_PATH`.
3. No firewall between the endpoint and backend is blocking outbound HTTPS.

Test connectivity:

```bash
curl -v https://xcloak.yourdomain.com/api/health
```

### Registration fails with `invalid install token`

- The token was already used — generate a new one.
- The token expired (24 hours) — generate a new one.
- The token was generated for a different tenant — ensure you are using a token from the correct tenant.

### Self-update fails with `signature verification failed`

The agent binary has an embedded public key and the release uploaded to the backend was signed with a different key, or was not signed at all.

- Check that `AGENT_RELEASE_SIGNING_KEY` on the backend matches the private key used to sign the release.
- If you want to skip signature verification for this release, build a new agent binary without `-ldflags` embedding the public key.

### Agent consuming too much CPU/memory

By default the agent scans processes and connections every 60 seconds. If this is too frequent for your environment, check if a large number of FIM paths are configured — FIM path expansion on directories with many files can be CPU-intensive on the first scan.

Reduce monitored FIM paths to only critical directories and accept the baseline to stop re-hashing all files on every scan.

### Logs show `task execution failed: permission denied`

The agent must run as root (Linux/macOS) or SYSTEM/Administrator (Windows) to execute certain tasks like isolating the host (iptables manipulation) or reading process memory. Check the service user configuration.

### Agent token lost / host reimaged

If the token file (`/etc/xcloak/token`) is lost, the agent cannot re-authenticate. Generate a new install token and re-register. The old agent entry in XCloak can be deleted from **Agents → [old agent] → Delete** or will automatically transition to offline after 5 minutes.

---

## Android Mobile Agent

The XCloak Mobile Agent is a Flutter 3.24 Android application that runs on enrolled Android devices. It provides two modes: **Agent Mode** (endpoint monitoring for any enrolled device) and **Admin Console Mode** (full 53-section NGFW dashboard for admins).

### Requirements

| Requirement | Version |
|-------------|---------|
| Android | 6.0 Marshmallow (API 23) or later |
| Flutter SDK | 3.24.5 |
| Java (build only) | 21 (not 25 — see note below) |
| Android SDK / NDK | NDK 27.0.12077973 |

> **Build note:** Flutter 3.24.5 is incompatible with Java 25. If your system default is Java 25, override it:
> ```bash
> flutter config --jdk-dir=/usr/lib/jvm/java-21-openjdk-amd64
> ```

### Building the APK

```bash
cd xcloak-agent-mobile
flutter pub get

# Debug build (for development / sideloading)
flutter run -d <device-id>
flutter build apk --debug

# Release build (for distribution)
flutter build apk --release
# Output: build/app/outputs/flutter-apk/app-release.apk
```

### Sideloading onto a Device

1. Enable **Settings → Developer Options → USB Debugging** on the device.
2. Connect via USB and verify: `adb devices`
3. Install: `adb install build/app/outputs/flutter-apk/app-debug.apk`
4. Or use `flutter run -d <device-id>` for a live debug session.

For distribution without the Play Store, host the APK on an internal file server or MDM and allow installation from unknown sources in device policy.

### Enrollment

1. Open the XCloak app on the device.
2. Tap **Enroll Device**.
3. Enter:
   - **Server URL** — your XCloak backend (e.g. `https://xcloak.yourdomain.com`)
   - **Enrollment Token** — single-use token from **Settings → Install Tokens** in the web UI
   - **Email** *(optional)* — associates the device with a user account
   - **Admin API Key** *(optional)* — enables the full admin console; create one under **Settings → API Keys → Create** with role `admin`
4. Tap **Enroll Device**. The app registers with the backend, stores the token in the Android Keystore, and starts the background monitoring service.

### Agent Mode — What It Monitors

| Check | Details |
|-------|---------|
| **Root Detection** | Checks for `su`, Magisk, known root binaries, and superuser apps |
| **Developer Options** | Reads `Settings.Global.DEVELOPMENT_SETTINGS_ENABLED` |
| **Sideloaded Apps** | Lists packages not installed via `com.android.vending` (Play Store) |
| **OS Version** | Reports Android API level and build string |
| **Device Fingerprint** | Stable SHA-256 ID derived from `ANDROID_ID` + device model |
| **MDM Check-in** | Reports posture JSON to `/api/mobile/checkin` every 60 seconds |

The background service runs as a foreground service (persistent notification) so Android does not kill it when the app is backgrounded or the screen is off.

### Admin Console Mode

When an Admin API Key is stored, the app switches to Admin Console Mode — a full mobile NGFW dashboard covering all 53 sections:

- **Alerts** — live feed with severity filter (All / Critical / High / Medium); acknowledge and resolve from mobile
- **Agents** — list of enrolled endpoints with online/offline status, OS, IP, and last-seen time; queue remote tasks (process collection, vulnerability scan, host isolation, etc.)
- **Detection** — incidents, UEBA, insider threat, ITDR findings, canary tokens, honeyports
- **Threat Intel** — threat actors, IOCs, Sigma rules, YARA rules, JA3 fingerprints, threat feeds
- **Response** — cases, playbooks, approval queue, firewall rules, forensic collection
- **Inventory** — CMDB assets, vulnerabilities, processes, connections, packages
- **Compliance** — framework scores (SOC 2, NIST, PCI-DSS, ISO 27001), controls, audit trail, reports
- **Platform** — user management, API key management, integrations, custom roles, tenants, AI assistant

To enter admin mode from agent mode, tap the shield icon in the top-right corner and enter your API key when prompted.

### Switching Back to Agent Mode

From the admin console, tap the hamburger menu → **Agent Mode** at the bottom of the sidebar. This clears the stored API key and returns to the standard agent view.

### Unenrolling a Device

In the app: tap **⋮ (overflow menu) → Unenroll device**. This deletes the local agent token and stops the background service. The device will appear offline in the NGFW dashboard within 5 minutes and can be deleted from **Agents → [device] → Delete**.

### Permissions Required

| Permission | Why |
|------------|-----|
| `FOREGROUND_SERVICE` | Background monitoring service |
| `RECEIVE_BOOT_COMPLETED` | Restart service after device reboot |
| `INTERNET` | Backend communication |
| `QUERY_ALL_PACKAGES` | Sideloaded app detection |
| `POST_NOTIFICATIONS` | Foreground service notification (Android 13+) |
