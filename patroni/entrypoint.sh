#!/bin/bash
set -e

DATA_DIR="${PATRONI_POSTGRESQL_DATA_DIR:-/data/patroni}"
mkdir -p "$DATA_DIR"
chown -R postgres:postgres "$DATA_DIR"
chmod 700 "$DATA_DIR"

# Patroni reads all PATRONI_* env vars natively; we only need the bootstrap config file.
exec gosu postgres patroni /etc/patroni/bootstrap.yml
