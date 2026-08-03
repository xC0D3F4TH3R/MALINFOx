#!/usr/bin/env bash
# MALINFO — Restore Script
# Restore from backup created by backup.sh

set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-/opt/malinfo/backups}"
PROJECT_ROOT="${PROJECT_ROOT:-/opt/malinfo}"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <backup_name_or_path>"
    echo ""
    echo "Available backups:"
    ls -1 "${BACKUP_DIR}"/malinfo_backup_*_manifest.json 2>/dev/null | while read manifest; do
        name=$(basename "$manifest" _manifest.json)
        timestamp=$(jq -r .timestamp "$manifest" 2>/dev/null || echo "unknown")
        echo "  $name  ($timestamp)"
    done
    exit 1
fi

BACKUP_IDENTIFIER="$1"
BACKUP_BASE=""

# Find backup by name or path
if [[ -f "$BACKUP_IDENTIFIER" ]]; then
    BACKUP_BASE="${BACKUP_IDENTIFIER%_manifest.json}"
    BACKUP_BASE="${BACKUP_BASE%_db.sql.gz}"
    BACKUP_BASE="${BACKUP_BASE%_storage.tar.gz}"
    BACKUP_BASE="${BACKUP_BASE%_config.tar.gz}"
    BACKUP_BASE="${BACKUP_BASE%_redis.tar.gz}"
elif [[ -f "${BACKUP_DIR}/${BACKUP_IDENTIFIER}_manifest.json" ]]; then
    BACKUP_BASE="${BACKUP_DIR}/${BACKUP_IDENTIFIER}"
else
    log_error "Backup not found: $BACKUP_IDENTIFIER"
    exit 1
fi

MANIFEST="${BACKUP_BASE}_manifest.json"
[[ -f "$MANIFEST" ]] || { log_error "Manifest not found: $MANIFEST"; exit 1; }

log_info "Restoring from: $(basename "$BACKUP_BASE")"
cat "$MANIFEST" | jq .

echo ""
log_warn "=========================================="
log_warn "WARNING: This will OVERWRITE current data!"
log_warn "=========================================="
echo ""
read -p "Type 'RESTORE' to confirm: " CONFIRM
[[ "$CONFIRM" == "RESTORE" ]] || { log_error "Aborted"; exit 1; }

# Stop services
log_info "Stopping services..."
docker compose -f "${PROJECT_ROOT}/docker-compose.prod.yml" down

# 1. Restore Configuration
if [[ -f "${BACKUP_BASE}_config.tar.gz" ]]; then
    log_info "Restoring configuration..."
    tar xzf "${BACKUP_BASE}_config.tar.gz" -C "${PROJECT_ROOT}"
fi

# 2. Restore Database
if [[ -f "${BACKUP_BASE}_db.sql.gz" ]]; then
    log_info "Restoring database..."
    docker compose -f "${PROJECT_ROOT}/docker-compose.prod.yml" up -d db
    log_info "Waiting for database to be ready..."
    for i in {1..30}; do
        if docker compose -f "${PROJECT_ROOT}/docker-compose.prod.yml" exec -T db pg_isready -U malinfo >/dev/null 2>&1; then
            break
        fi
        sleep 2
    done
    gunzip -c "${BACKUP_BASE}_db.sql.gz" | docker compose -f "${PROJECT_ROOT}/docker-compose.prod.yml" exec -T db psql -U malinfo malinfo
    log_info "Database restored"
fi

# 3. Restore Storage
if [[ -f "${BACKUP_BASE}_storage.tar.gz" ]]; then
    log_info "Restoring storage..."
    docker run --rm -v malinfo_storage:/data -v "$(dirname "${BACKUP_BASE}")":/backup alpine \
        tar xzf "/backup/$(basename "${BACKUP_BASE}_storage.tar.gz")" -C /data
    log_info "Storage restored"
fi

# 4. Restore Redis
if [[ -f "${BACKUP_BASE}_redis.tar.gz" ]]; then
    log_info "Restoring Redis..."
    docker run --rm -v malinfo_redis_data:/data -v "$(dirname "${BACKUP_BASE}")":/backup alpine \
        tar xzf "/backup/$(basename "${BACKUP_BASE}_redis.tar.gz")" -C /data
    log_info "Redis restored"
fi

# Start all services
log_info "Starting all services..."
docker compose -f "${PROJECT_ROOT}/docker-compose.prod.yml" up -d

# Wait for health
log_info "Waiting for services to be healthy..."
for i in {1..30}; do
    if curl -kfs https://localhost/api/health >/dev/null 2>&1; then
        log_info "Health check passed"
        break
    fi
    sleep 2
done

log_info "=========================================="
log_info "Restore completed successfully!"
log_info "=========================================="