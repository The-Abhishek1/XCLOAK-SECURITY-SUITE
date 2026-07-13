#!/usr/bin/env bash
# XCloak Security Suite — one-command installer
# Usage: curl -fsSL https://raw.githubusercontent.com/The-Abhishek1/XCLOAK-SECURITY-SUITE/main/install.sh | bash
set -euo pipefail

REPO="https://github.com/The-Abhishek1/XCLOAK-SECURITY-SUITE.git"
DIR="XCLOAK-SECURITY-SUITE"
COMPOSE_FILE="docker-compose.quickstart.yml"

# ── colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[xcloak]${RESET} $*"; }
success() { echo -e "${GREEN}[xcloak]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[xcloak]${RESET} $*"; }
die()     { echo -e "${RED}[xcloak] ERROR:${RESET} $*" >&2; exit 1; }

# ── banner ────────────────────────────────────────────────────────────────────
echo -e "${BOLD}"
cat <<'EOF'
 ██╗  ██╗ ██████╗██╗      ██████╗  █████╗ ██╗  ██╗
 ╚██╗██╔╝██╔════╝██║     ██╔═══██╗██╔══██╗██║ ██╔╝
  ╚███╔╝ ██║     ██║     ██║   ██║███████║█████╔╝
  ██╔██╗ ██║     ██║     ██║   ██║██╔══██║██╔═██╗
 ██╔╝ ██╗╚██████╗███████╗╚██████╔╝██║  ██║██║  ██╗
 ╚═╝  ╚═╝ ╚═════╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
 Security Suite — Open Source SOC Platform
EOF
echo -e "${RESET}"

# ── requirements ──────────────────────────────────────────────────────────────
info "Checking requirements..."

command -v docker >/dev/null 2>&1 || die "Docker is not installed. Install it from https://docs.docker.com/get-docker/"
command -v git    >/dev/null 2>&1 || die "git is not installed."
command -v curl   >/dev/null 2>&1 || die "curl is not installed. Install it (e.g. apt install curl)."

# Docker Compose v2 (plugin) or v1 (standalone)
if docker compose version >/dev/null 2>&1; then
  COMPOSE="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE="docker-compose"
else
  die "Docker Compose is not installed. Install it from https://docs.docker.com/compose/install/"
fi

# Check Docker daemon is running
docker info >/dev/null 2>&1 || die "Docker daemon is not running. Start Docker and try again."

success "Requirements satisfied."

# ── system resources warning ──────────────────────────────────────────────────
TOTAL_MEM_KB=$(grep MemTotal /proc/meminfo 2>/dev/null | awk '{print $2}' || echo 0)
if [ "$TOTAL_MEM_KB" -gt 0 ] && [ "$TOTAL_MEM_KB" -lt 3145728 ]; then
  warn "Less than 3 GB RAM detected. XCloak may run slowly. 4 GB+ recommended."
fi

DISK_FREE_KB=$(df -k . | awk 'NR==2{print $4}' || echo 0)
if [ "$DISK_FREE_KB" -gt 0 ] && [ "$DISK_FREE_KB" -lt 10485760 ]; then
  warn "Less than 10 GB free disk space. Docker images need ~4 GB."
fi

# ── clone or update ───────────────────────────────────────────────────────────
if [ -d "$DIR/.git" ]; then
  info "Repository already exists — pulling latest..."
  git -C "$DIR" pull --ff-only
elif [ -f "docker-compose.quickstart.yml" ]; then
  info "Running inside the repository — skipping clone."
  DIR="."
else
  info "Cloning XCloak..."
  git clone --depth 1 "$REPO" "$DIR"
fi

cd "$DIR"

# ── secrets ───────────────────────────────────────────────────────────────────
# Generate secure secrets and export them so docker compose picks them up via
# the ${JWT_SECRET} / ${METRICS_TOKEN} substitution in docker-compose.quickstart.yml.
# No temp files — avoids Docker Compose resolving relative build paths from /tmp.
export JWT_SECRET="${JWT_SECRET:-$(openssl rand -hex 32 2>/dev/null || head -c 32 /dev/urandom | od -A n -t x1 | tr -d ' \n')}"
export METRICS_TOKEN="${METRICS_TOKEN:-$(openssl rand -hex 16 2>/dev/null || head -c 16 /dev/urandom | od -A n -t x1 | tr -d ' \n')}"

# ── pull base images first so progress is visible ─────────────────────────────
info "Pulling base images..."
$COMPOSE -f "$COMPOSE_FILE" pull --ignore-buildable 2>/dev/null || true

# ── build & start ─────────────────────────────────────────────────────────────
info "Building and starting XCloak (this takes ~3 minutes on first run)..."
$COMPOSE -f "$COMPOSE_FILE" up -d --build

# ── wait for healthy ─────────────────────────────────────────────────────────
info "Waiting for backend to be ready..."
TIMEOUT=120
ELAPSED=0
until curl -sf http://localhost:8080/api/health >/dev/null 2>&1; do
  if [ "$ELAPSED" -ge "$TIMEOUT" ]; then
    die "Backend did not start within ${TIMEOUT}s. Check logs: $COMPOSE -f $COMPOSE_FILE logs backend"
  fi
  sleep 3
  ELAPSED=$((ELAPSED + 3))
  echo -n "."
done
echo ""

success "XCloak is running!"
echo ""
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "  ${GREEN}Dashboard${RESET}   →  ${BOLD}http://localhost:3000${RESET}"
echo -e "  ${GREEN}Backend API${RESET} →  http://localhost:8080/api/health"
echo ""
echo -e "  Create your admin account on first visit."
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""
echo -e "  ${YELLOW}Enroll an agent:${RESET}"
echo -e "  curl -fsSL https://raw.githubusercontent.com/The-Abhishek1/XCLOAK-SECURITY-SUITE/main/scripts/enroll-agent.sh | bash"
echo ""
echo -e "  ${YELLOW}Stop XCloak:${RESET}"
echo -e "  $COMPOSE -f $(pwd)/$COMPOSE_FILE down"
echo ""
echo -e "  Docs → ${CYAN}https://docs.xcloak.tech${RESET}"
echo -e "  Repo → ${CYAN}https://github.com/The-Abhishek1/XCLOAK-SECURITY-SUITE${RESET}"
echo ""
