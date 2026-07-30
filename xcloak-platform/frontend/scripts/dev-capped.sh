#!/usr/bin/env bash
# Runs `next dev` inside its own cgroup with a hard memory ceiling. Measured
# during the 2026-07-30 backend memory-leak investigation: next-server hit
# 1.73GB RSS on this machine just running the e2e suite once, the heaviest
# single dev-mode process on the box. It's not known to leak (unlike the
# backend bug fixed the same day) — this is a precautionary cap, mirroring
# ../../backend/scripts/dev-capped.sh, so a bad Fast-Refresh loop or a
# large webpack cache buildup can't do the same thing the backend leak did.
#
# Usage: ./scripts/dev-capped.sh   (from xcloak-platform/frontend)
set -euo pipefail
cd "$(dirname "$0")/.."
exec systemd-run --user --scope --collect \
  -p MemoryMax=2G \
  -p MemorySwapMax=0 \
  npm run dev
