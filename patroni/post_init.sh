#!/bin/bash
# Called by Patroni once after the cluster is first initialized on the primary.
# $1 = libpq connection string to the primary (passed by Patroni).
# Creates the application database if it doesn't already exist.
set -e

DB="${POSTGRES_DB:-ngfw}"
USER="${PATRONI_SUPERUSER_USERNAME:-xcloak}"

psql "$1" -c "CREATE DATABASE \"$DB\";" 2>/dev/null || true
psql "$1" -c "GRANT ALL PRIVILEGES ON DATABASE \"$DB\" TO \"$USER\";" 2>/dev/null || true

echo "[post_init] database '$DB' ready"
