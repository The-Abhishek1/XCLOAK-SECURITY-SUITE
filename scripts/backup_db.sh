#!/usr/bin/env bash
# Dumps the XCLOAK Postgres database to backups/, then deletes dumps older
# than RETENTION_DAYS. Reads DB_* from xcloak-ngfw/backend/.env so this stays
# in sync with whatever the backend is actually connecting to.
#
# Usage: ./scripts/backup_db.sh
# Cron (daily at 02:00): 0 2 * * * /path/to/xcloak/scripts/backup_db.sh >> /var/log/xcloak-backup.log 2>&1

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$REPO_ROOT/xcloak-ngfw/backend/.env"
BACKUP_DIR="$REPO_ROOT/backups"
RETENTION_DAYS="${RETENTION_DAYS:-14}"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "missing $ENV_FILE — can't read DB credentials" >&2
  exit 1
fi

set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

mkdir -p "$BACKUP_DIR"

timestamp="$(date +%Y%m%d_%H%M%S)"
dest="$BACKUP_DIR/ngfw_${timestamp}.sql.gz"

PGPASSWORD="$DB_PASSWORD" pg_dump \
  -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" \
  --no-owner --no-privileges --clean --if-exists \
  | gzip > "$dest"

echo "backup written: $dest ($(du -h "$dest" | cut -f1))"

find "$BACKUP_DIR" -name 'ngfw_*.sql.gz' -mtime "+${RETENTION_DAYS}" -delete

echo "pruned backups older than ${RETENTION_DAYS} days"
