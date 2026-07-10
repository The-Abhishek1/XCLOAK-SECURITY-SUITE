#!/usr/bin/env bash
# Run integration tests using docker-compose.test.yml.
# Usage:  ./scripts/test-integration.sh [go-test-args...]
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

COMPOSE_FILE="docker-compose.test.yml"

cleanup() {
    docker compose -f "$COMPOSE_FILE" down -v --remove-orphans 2>/dev/null || true
}
trap cleanup EXIT

echo "==> Starting test infrastructure..."
docker compose -f "$COMPOSE_FILE" up -d --wait

echo "==> Waiting for Postgres to accept connections..."
until docker compose -f "$COMPOSE_FILE" exec -T postgres_test \
        pg_isready -U xcloak -d xcloak_test -q 2>/dev/null; do
    sleep 1
done

export TEST_DB_URL="postgres://xcloak:testpassword@localhost:5433/xcloak_test?sslmode=disable"
export TEST_REDIS_URL="redis://localhost:6380"

echo "==> Running integration tests..."
cd backend
go test -tags integration -count=1 -timeout 120s "${@:-.}" 2>&1

echo "==> Done."
