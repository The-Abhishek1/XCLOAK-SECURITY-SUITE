#!/usr/bin/env bash
# XCloak Agent — enroll and install as a systemd service
#
# Usage (one-liner):
#   curl -fsSL https://raw.githubusercontent.com/The-Abhishek1/XCLOAK-SECURITY-SUITE/main/scripts/enroll-agent.sh | sudo bash
#
# Or if you already have the repo:
#   sudo bash scripts/enroll-agent.sh
set -euo pipefail

BINARY_NAME="xcloak-agent"
INSTALL_PATH="/usr/local/bin/${BINARY_NAME}"
CONFIG_DIR="/etc/xcloak-agent-desktop"
ENV_FILE="${CONFIG_DIR}/.env"
SERVICE_FILE="/etc/systemd/system/xcloak-agent.service"
REPO_URL="https://github.com/The-Abhishek1/XCLOAK-SECURITY-SUITE"
REPO_CLONE_URL="https://github.com/The-Abhishek1/XCLOAK-SECURITY-SUITE.git"
BUILD_DIR="/tmp/xcloak-agent-build"

# ── colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[xcloak]${RESET} $*"; }
success() { echo -e "${GREEN}[xcloak]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[xcloak]${RESET} $*"; }
die()     { echo -e "${RED}[xcloak] ERROR:${RESET} $*" >&2; exit 1; }

# prompt reads from /dev/tty so it works even when the script is piped:
#   curl ... | sudo bash
ask() {
  local __var="$1" __prompt="$2"
  printf "  %s" "$__prompt" >/dev/tty
  local __val
  read -r __val </dev/tty
  printf -v "$__var" '%s' "$__val"
}

# ── banner ────────────────────────────────────────────────────────────────────
echo -e "${BOLD}"
cat <<'EOF'
 ██╗  ██╗ ██████╗██╗      ██████╗  █████╗ ██╗  ██╗
 ╚██╗██╔╝██╔════╝██║     ██╔═══██╗██╔══██╗██║ ██╔╝
  ╚███╔╝ ██║     ██║     ██║   ██║███████║█████╔╝
  ██╔██╗ ██║     ██║     ██║   ██║██╔══██║██╔═██╗
 ██╔╝ ██╗╚██████╗███████╗╚██████╔╝██║  ██║██║  ██╗
 ╚═╝  ╚═╝ ╚═════╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
 Agent Enrollment
EOF
echo -e "${RESET}"

# ── root ──────────────────────────────────────────────────────────────────────
[ "$(id -u)" -eq 0 ] || die "Run with sudo: sudo bash $0"

# ── platform ──────────────────────────────────────────────────────────────────
OS="$(uname -s)"
ARCH="$(uname -m)"

[ "$OS" = "Linux" ] || die "This script supports Linux only. For Windows agents see the docs."

case "$ARCH" in
  x86_64)  GOARCH="amd64" ;;
  aarch64) GOARCH="arm64" ;;
  armv7l)  GOARCH="arm"   ;;
  *) die "Unsupported architecture: $ARCH" ;;
esac

# ── systemd ───────────────────────────────────────────────────────────────────
command -v systemctl >/dev/null 2>&1 || die "systemd not found. Cannot install as a service."

# ── server URL ────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}Step 1 — Server URL${RESET}"
echo "  The URL of your XCloak backend."
echo "  Examples: https://xcloak.yourdomain.com  |  http://192.168.1.10:8080"
echo ""
ask SERVER_URL "Server URL: "
SERVER_URL="${SERVER_URL%/}"   # strip trailing slash
[ -n "$SERVER_URL" ] || die "Server URL cannot be empty."

# ── connectivity check ────────────────────────────────────────────────────────
info "Testing connectivity to ${SERVER_URL}/api/health ..."
if ! curl -sf --max-time 10 "${SERVER_URL}/api/health" >/dev/null 2>&1; then
  die "Cannot reach ${SERVER_URL}/api/health\n  → Check the URL and confirm the XCloak backend is running."
fi
success "Backend is reachable."

# ── install token ─────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}Step 2 — Install Token${RESET}"
echo "  Generate a token in the XCloak UI:"
echo "  Agents → Add Agent → Generate Token"
echo "  (Tokens are single-use and expire in 24 hours)"
echo ""
ask INSTALL_TOKEN "Install token: "
INSTALL_TOKEN="$(printf '%s' "$INSTALL_TOKEN" | tr -d '[:space:]')"
[ -n "$INSTALL_TOKEN" ] || die "Install token cannot be empty."

# ── binary ────────────────────────────────────────────────────────────────────
echo ""
info "Step 3 — Installing agent binary..."

DOWNLOADED=false

# Try a pre-built release binary first.
RELEASE_URL="${REPO_URL}/releases/latest/download/xcloak-agent-linux-${GOARCH}"
info "Checking for pre-built release at ${RELEASE_URL} ..."
if curl -sf --max-time 30 -L "$RELEASE_URL" -o /tmp/xcloak-agent-dl 2>/dev/null; then
  if file /tmp/xcloak-agent-dl 2>/dev/null | grep -q "ELF"; then
    install -m 755 /tmp/xcloak-agent-dl "$INSTALL_PATH"
    rm -f /tmp/xcloak-agent-dl
    DOWNLOADED=true
    success "Downloaded pre-built binary (linux/${GOARCH})."
  else
    rm -f /tmp/xcloak-agent-dl
    info "Downloaded file is not an ELF binary — will build from source."
  fi
else
  info "No pre-built release found — will build from source."
fi

if [ "$DOWNLOADED" = false ]; then
  command -v go >/dev/null 2>&1 || die \
    "Go is not installed and no pre-built binary is available.\n" \
    "  Install Go from https://go.dev/dl/ then re-run this script.\n" \
    "  Or download a pre-built binary from ${REPO_URL}/releases"

  GO_VERSION="$(go version | awk '{print $3}' | sed 's/go//')"
  info "Building from source with Go ${GO_VERSION} ..."

  # Reuse the repo if we're already inside it, otherwise clone.
  if [ -f "$(dirname "$0")/../xcloak-agent-desktop/main.go" ]; then
    AGENT_SRC="$(cd "$(dirname "$0")/.." && pwd)/xcloak-agent-desktop"
    info "Using local source at ${AGENT_SRC}"
  else
    if [ -d "${BUILD_DIR}/.git" ]; then
      info "Updating cached source..."
      git -C "$BUILD_DIR" pull --ff-only --quiet
    else
      rm -rf "$BUILD_DIR"
      info "Cloning repository..."
      git clone --depth 1 "$REPO_CLONE_URL" "$BUILD_DIR" --quiet
    fi
    AGENT_SRC="${BUILD_DIR}/xcloak-agent-desktop"
  fi

  (
    cd "$AGENT_SRC"
    go build -ldflags "-s -w" -o "$INSTALL_PATH" ./main.go
  )
  success "Built and installed binary from source."
fi

# ── config ────────────────────────────────────────────────────────────────────
mkdir -p "$CONFIG_DIR"
chmod 750 "$CONFIG_DIR"

# Write the env file. After the agent registers for the first time it saves a
# permanent token; XCLOAK_INSTALL_TOKEN is only needed on the first run and is
# silently ignored on subsequent starts once a saved token exists.
cat > "$ENV_FILE" <<EOF
SERVER_URL=${SERVER_URL}
XCLOAK_INSTALL_TOKEN=${INSTALL_TOKEN}
LOG_LEVEL=info
EOF
chmod 640 "$ENV_FILE"

success "Config written to ${ENV_FILE}"

# ── systemd service ───────────────────────────────────────────────────────────
cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=XCloak Security Agent
Documentation=${REPO_URL}
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=120
StartLimitBurst=5

[Service]
Type=simple
ExecStart=${INSTALL_PATH}
Restart=on-failure
RestartSec=15s

# Config — SERVER_URL, XCLOAK_INSTALL_TOKEN, LOG_LEVEL etc.
EnvironmentFile=${ENV_FILE}

# Working directory doubles as the .env fallback the agent checks on startup.
WorkingDirectory=${CONFIG_DIR}

# eBPF collectors and privileged system access require root.
User=root
Group=root

StandardOutput=journal
StandardError=journal
SyslogIdentifier=xcloak-agent

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --quiet xcloak-agent

# Stop any existing instance cleanly before starting fresh.
if systemctl is-active --quiet xcloak-agent 2>/dev/null; then
  info "Stopping existing agent instance..."
  systemctl stop xcloak-agent
fi

info "Starting xcloak-agent service..."
systemctl start xcloak-agent

# ── verify ────────────────────────────────────────────────────────────────────
info "Waiting for agent to start (10s)..."
sleep 10

if systemctl is-active --quiet xcloak-agent; then
  success "xcloak-agent is running."
else
  echo ""
  warn "Agent service did not start cleanly. Last 20 log lines:"
  echo "──────────────────────────────────────────────────────────"
  journalctl -u xcloak-agent -n 20 --no-pager 2>/dev/null || true
  echo "──────────────────────────────────────────────────────────"
  echo ""
  warn "Common causes:"
  echo "  • Invalid install token — generate a fresh one in the UI"
  echo "  • Backend unreachable from this host (firewall / wrong URL)"
  echo "  • Token already used — each token is single-use"
  echo ""
  echo "  Full logs: journalctl -u xcloak-agent -f"
  exit 1
fi

# ── done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
success "Agent enrolled and running!"
echo ""
echo -e "  ${CYAN}Binary${RESET}   → ${INSTALL_PATH}"
echo -e "  ${CYAN}Config${RESET}   → ${ENV_FILE}"
echo -e "  ${CYAN}Service${RESET}  → xcloak-agent (systemd, enabled on boot)"
echo ""
echo -e "  ${YELLOW}Useful commands:${RESET}"
echo -e "  systemctl status xcloak-agent"
echo -e "  journalctl -u xcloak-agent -f"
echo -e "  systemctl stop xcloak-agent"
echo -e "  systemctl restart xcloak-agent"
echo ""
echo -e "  The agent appears in your XCloak dashboard within ~30 seconds."
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""
