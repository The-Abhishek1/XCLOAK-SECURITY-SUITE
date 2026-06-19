#!/usr/bin/env bash
# Restores a backup produced by backup_db.sh. DESTRUCTIVE — drops and
# recreates every object in the target database first.
#
# Usage: ./scripts/restore_db.sh backups/ngfw_20260619_213300.sql.gz

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$REPO_ROOT/xcloak-ngfw/backend/.env"

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <backup-file.sql.gz>" >&2
  exit 1
fi

backup_file="$1"
if [[ ! -f "$backup_file" ]]; then
  echo "backup file not found: $backup_file" >&2
  exit 1
fi

if [[ ! -f "$ENV_FILE" ]]; then
  echo "missing $ENV_FILE — can't read DB credentials" >&2
  exit 1
fi

set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

echo "About to restore '$backup_file' into database '$DB_NAME' on $DB_HOST:$DB_PORT."
echo "This will DROP every table currently in that database. Type the database name to confirm:"
read -r confirm
if [[ "$confirm" != "$DB_NAME" ]]; then
  echo "confirmation did not match — aborting"
  exit 1
fi

gunzip -c "$backup_file" | PGPASSWORD="$DB_PASSWORD" psql \
  -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" \
  -v ON_ERROR_STOP=1

echo "restore complete"
