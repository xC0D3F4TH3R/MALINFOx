#!/usr/bin/env bash
# MALINFO — Backup Script
# Comprehensive backup for database, storage, and configuration

set -euo pipefail

# Configuration
BACKUP_DIR="${BACKUP_DIR:-/opt/malinfo/backups}"
PROJECT_ROOT="${PROJECT_ROOT:-/opt/malinfo}"
RETENTION_DAYS="${RETENTION_DAYS:-30}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_NAME="malinfo_backup_${TIMESTAMP}"
BACKUP_PATH="${BACKUP_DIR}/${BACKUP_NAME}"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

mkdir -p "${BACKUP_DIR}"

echo "=========================================="
echo "MALINFO Backup - ${TIMESTAMP}"
echo "=========================================="

# 1. Backup PostgreSQL Database
log_info "Backing up PostgreSQL database..."
docker compose -f "${PROJECT_ROOT}/docker-compose.prod.yml" exec -T db pg_dump -U malinfo malinfo | gzip > "${BACKUP_PATH}_db.sql.gz"
DB_SIZE=$(du -h "${BACKUP_PATH}_db.sql.gz" | cut -f1)
log_info "Database backup: ${DB_SIZE}"

# 2. Backup Redis (optional - RDB dump)
log_info "Backing up Redis..."
docker compose -f "${PROJECT_ROOT}/docker-compose.prod.yml" exec -T redis redis-cli BGSAVE >/dev/null 2>&1 || true
sleep 2
docker run --rm -v malinfo_redis_data:/data -v "${BACKUP_DIR}":/backup alpine tar czf "/backup/${BACKUP_NAME}_redis.tar.gz" -C /data dump.rdb 2>/dev/null || true
log_info "Redis backup completed"

# 3. Backup Storage (uploads, reports, pcaps)
log_info "Backing up storage volumes..."
docker run --rm -v malinfo_storage:/data -v "${BACKUP_DIR}":/backup alpine tar czf "/backup/${BACKUP_NAME}_storage.tar.gz" -C /data .
STORAGE_SIZE=$(du -h "${BACKUP_PATH}_storage.tar.gz" | cut -f1)
log_info "Storage backup: ${STORAGE_SIZE}"

# 4. Backup Configuration
log_info "Backing up configuration..."
tar czf "${BACKUP_PATH}_config.tar.gz" -C "${PROJECT_ROOT}" \
    .env \
    docker-compose.prod.yml \
    deploy/nginx.prod.conf \
    deploy/kubernetes/ \
    deploy/prometheus/ \
    deploy/grafana/ \
    backend/app/rules/yara/feeds.yaml \
    2>/dev/null || true
CONFIG_SIZE=$(du -h "${BACKUP_PATH}_config.tar.gz" | cut -f1)
log_info "Config backup: ${CONFIG_SIZE}"

# 5. Create manifest
log_info "Creating backup manifest..."
cat > "${BACKUP_PATH}_manifest.json" <<EOF
{
  "backup_name": "${BACKUP_NAME}",
  "timestamp": "$(date -Iseconds)",
  "hostname": "$(hostname)",
  "components": {
    "database": "${BACKUP_NAME}_db.sql.gz",
    "redis": "${BACKUP_NAME}_redis.tar.gz",
    "storage": "${BACKUP_NAME}_storage.tar.gz",
    "config": "${BACKUP_NAME}_config.tar.gz"
  },
  "sizes": {
    "database": "${DB_SIZE}",
    "storage": "${STORAGE_SIZE}",
    "config": "${CONFIG_SIZE}"
  },
  "version": "1.0.0-pilot",
  "retention_days": ${RETENTION_DAYS}
}
EOF

# 6. Verify backups
log_info "Verifying backups..."
for file in "${BACKUP_PATH}"_*; do
    if [[ -f "$file" && -s "$file" ]]; then
        log_info "  ✓ $(basename "$file") ($(du -h "$file" | cut -f1))"
    else
        log_warn "  ✗ $(basename "$file") - missing or empty"
    fi
done

# 7. Clean old backups
log_info "Cleaning backups older than ${RETENTION_DAYS} days..."
find "${BACKUP_DIR}" -name "malinfo_backup_*" -type f -mtime +${RETENTION_DAYS} -delete
REMAINING=$(ls -1 "${BACKUP_DIR}"/malinfo_backup_*_manifest.json 2>/dev/null | wc -l)
log_info "Remaining backups: ${REMAINING}"

echo ""
echo "=========================================="
echo "Backup completed: ${BACKUP_NAME}"
echo "Location: ${BACKUP_DIR}"
echo "=========================================="