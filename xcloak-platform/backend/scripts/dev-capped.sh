#!/usr/bin/env bash
# Runs `air` (backend hot-reload) inside its own cgroup with a hard memory
# ceiling. The Go runtime's own soft limit (see applyMemoryLimit in main.go)
# makes GC work harder as it approaches BACKEND_MEMORY_LIMIT_MB, but it can't
# stop truly unbounded growth — only a hard cgroup cap can. Without this, a
# runaway process on this machine grows until the *system* runs out of
# memory and the kernel OOM-killer picks a target, which has repeatedly
# taken down the whole VS Code terminal session instead of just the leaking
# process (see kernel log: "main" hit ~11GB RSS 3x on 2026-07-30).
#
# Usage: ./scripts/dev-capped.sh   (from xcloak-platform/backend)
set -euo pipefail
cd "$(dirname "$0")/.."
exec systemd-run --user --scope --collect \
  -p MemoryMax=3G \
  -p MemorySwapMax=0 \
  air
