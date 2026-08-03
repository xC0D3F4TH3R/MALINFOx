# MALINFO — Operational Runbooks

## Table of Contents
1. [Deployment Runbook](#1-deployment-runbook)
2. [Scaling Runbook](#2-scaling-runbook)
3. [Incident Response Runbook](#3-incident-response-runbook)
4. [Backup & Recovery Runbook](#4-backup--recovery-runbook)
5. [Maintenance Runbook](#5-maintenance-runbook)
6. [Security Incident Runbook](#6-security-incident-runbook)

---

## 1. Deployment Runbook

### 1.1 Initial Deployment (Docker Compose)

**Prerequisites:**
- Docker 24+ and Docker Compose 2+
- 16GB+ RAM, 4+ CPU cores
- 200GB+ disk space
- TLS certificates or Let's Encrypt access

**Steps:**

```bash
# 1. Clone and prepare
git clone https://github.com/your-org/malinfo.git
cd malinfo
make init

# 2. Generate secrets
make secrets
# Save outputs to your secrets manager!

# 3. Configure environment
cp .env.example .env
# Edit .env with ALL required values:
#   - SECRET_KEY (from secrets)
#   - POSTGRES_PASSWORD (from secrets)
#   - GRAFANA_PASSWORD (from secrets)
#   - ALLOWED_ORIGINS (your domains)
#   - Threat intel API keys
#   - MISP URL/key (if using)

# 4. Generate TLS certificates
# For staging:
make certs MODE=selfsigned DOMAIN=malinfo-staging.example.com
# For production:
make certs MODE=letsencrypt DOMAIN=malinfo.example.gov EMAIL=admin@example.gov

# 5. Deploy
make prod
# Or for specific profiles:
make deploy-docker ACTION=up PROFILE=all

# 6. Verify deployment
make health
make status
```

**Rollback Plan:**
```bash
# If deployment fails:
make deploy-docker ACTION=down
# Fix issues, then re-deploy
make deploy-docker ACTION=up PROFILE=all
```

### 1.2 Kubernetes Deployment

```bash
# 1. Create namespace and secrets
kubectl apply -f deploy/kubernetes/malinfo-platform.yaml

# 2. Create secrets (use sealed-secrets or external-secrets in production)
kubectl create secret generic malinfo-secrets -n malinfo \
  --from-literal=POSTGRES_PASSWORD="..." \
  --from-literal=SECRET_KEY="..." \
  --from-literal=VIRUSTOTAL_API_KEY="..." \
  --from-literal=OTX_API_KEY="..." \
  --from-literal=ABUSEIPDB_API_KEY="..." \
  --from-literal=MISP_API_KEY="..." \
  --from-literal=GRAFANA_PASSWORD="..."

# 3. Create TLS secret
kubectl create secret tls malinfo-tls -n malinfo \
  --cert=deploy/certs/fullchain.pem \
  --key=deploy/certs/privkey.pem

# 4. Deploy
kubectl apply -f deploy/kubernetes/

# 5. Verify
kubectl get all -n malinfo
kubectl logs -f deployment/malinfo-backend -n malinfo
```

### 1.3 systemd (Bare Metal) Deployment

```bash
# 1. Create user and directories
sudo useradd -r -s /bin/bash -d /opt/malinfo malinfo
sudo mkdir -p /opt/malinfo/{backend,storage/{uploads,reports,pcaps},logs}
sudo chown -R malinfo:malinfo /opt/malinfo

# 2. Install Python dependencies
sudo -u malinfo python3 -m venv /opt/malinfo/venv
sudo -u malinfo /opt/malinfo/venv/bin/pip install -r /opt/malinfo/backend/requirements.txt --break-system-packages

# 3. Copy application code
sudo cp -r backend/* /opt/malinfo/backend/
sudo cp .env /opt/malinfo/.env
sudo chown -R malinfo:malinfo /opt/malinfo/backend /opt/malinfo/.env

# 4. Install systemd services
sudo cp deploy/malinfo-*.service /etc/systemd/system/
sudo cp deploy/logrotate/malinfo /etc/logrotate.d/malinfo

# 5. Start services
sudo systemctl daemon-reload
sudo systemctl enable --now malinfo-backend malinfo-icap malinfo-monitor

# 6. Configure nginx (separate installation)
sudo cp deploy/nginx.prod.conf /etc/nginx/nginx.conf
sudo nginx -t && sudo systemctl reload nginx
```

---

## 2. Scaling Runbook

### 2.1 Horizontal Scaling (Docker Compose)

```bash
# Scale backend workers
docker compose -f docker-compose.prod.yml up -d --scale backend=6

# Scale with specific resource limits
# Edit docker-compose.prod.yml backend service:
# deploy:
#   resources:
#     limits:
#       memory: 4G
#       cpus: "2"
#     reservations:
#       memory: 2G
#       cpus: "1"
```

### 2.2 Horizontal Scaling (Kubernetes)

```bash
# Scale backend deployment
kubectl scale deployment malinfo-backend --replicas=6 -n malinfo

# Configure HPA (Horizontal Pod Autoscaler)
kubectl autoscale deployment malinfo-backend \
  --cpu-percent=70 --min=3 --max=10 -n malinfo

# Scale nginx
kubectl scale deployment malinfo-nginx --replicas=4 -n malinfo
```

### 2.3 Vertical Scaling

```bash
# Increase memory/CPU limits in docker-compose.prod.yml or K8s manifests
# Then restart services:
make deploy-docker ACTION=restart
# Or K8s:
kubectl rollout restart deployment/malinfo-backend -n malinfo
```

### 2.4 Database Scaling

```bash
# Read replicas (PostgreSQL streaming replication)
# 1. Configure primary for replication
# 2. Create replica servers
# 3. Update DATABASE_URL for read operations

# Connection pooling (PgBouncer)
# Add to docker-compose.prod.yml:
# pgbouncer:
#   image: edoburu/pgbouncer:1.21
#   environment:
#     DATABASES_HOST: db
#     POOL_MODE: transaction
#     MAX_CLIENT_CONN: 1000
```

### 2.5 Storage Scaling

```bash
# Increase PVC size (Kubernetes)
kubectl patch pvc malinfo-storage -n malinfo -p '{"spec":{"resources":{"requests":{"storage":"500Gi"}}}}'

# Add additional storage volumes for different data types
# volumes:
#   malinfo_uploads:
#   malinfo_reports:
#   malinfo_pcaps:
```

---

## 3. Incident Response Runbook

### 3.1 Service Down

**Symptoms:** Health check fails, API returns 5xx or timeout

**Diagnosis:**
```bash
# Check service status
make status

# Check logs
make logs SERVICE=backend
make logs SERVICE=nginx
make logs SERVICE=db

# Check resource usage
docker stats
```

**Resolution:**
```bash
# 1. Restart unhealthy service
make deploy-docker ACTION=restart

# 2. If database issue:
docker compose -f docker-compose.prod.yml restart db
# Check pg_isready

# 3. If OOM kills:
# Increase memory limits in docker-compose.prod.yml
# docker compose -f docker-compose.prod.yml up -d --build

# 4. If disk full:
df -h
# Clean old logs, backups, or increase volume
```

### 3.2 High Error Rate

**Symptoms:** Alert `MalinfoHighErrorRate` firing

**Diagnosis:**
```bash
# Check error logs
make logs SERVICE=backend | grep -i error

# Check metrics
curl -s https://localhost:9090/api/v1/query?query=rate\(http_requests_total\{status\=~\"5..\"\}[5m]\)
```

**Resolution:**
```bash
# Common causes:
# 1. Database connection pool exhausted
#    -> Increase pool size or add PgBouncer
# 2. Sandbox timeout
#    -> Check CAPEv2 cluster health
# 3. Upstream API failures (threat intel)
#    -> Check API key validity, rate limits
# 4. Memory pressure
#    -> Scale up or optimize queries
```

### 3.3 Analysis Pipeline Stuck

**Symptoms:** Queue depth growing, samples not completing

**Diagnosis:**
```bash
# Check queue
curl -s https://localhost/api/monitoring/status | jq .pending_queue_size

# Check for stuck workers
docker compose -f docker-compose.prod.yml exec backend ps aux
```

**Resolution:**
```bash
# Restart analysis workers
docker compose -f docker-compose.prod.yml restart backend

# Clear stuck queue (if needed)
docker compose -f docker-compose.prod.yml exec backend python -c "
from app.analysis.pipeline import clear_stuck_queue
clear_stuck_queue()
"
```

### 3.4 Threat Intel Feed Failures

**Symptoms:** Alert `MalinfoThreatIntelSyncFailure` firing

**Diagnosis:**
```bash
# Check feed status
curl -s https://localhost/api/threat-intel/providers | jq .

# Check logs
make logs SERVICE=backend | grep -i "threat.intel\|feed"
```

**Resolution:**
```bash
# 1. Verify API keys still valid
# 2. Check rate limits (VT, OTX, AbuseIPDB)
# 3. Check network connectivity to feed endpoints
# 4. Manually trigger sync:
curl -X POST https://localhost/api/threat-intel/feeds/sync
```

---

## 4. Backup & Recovery Runbook

### 4.1 Scheduled Backups

```bash
# Add to crontab (run daily at 2 AM)
0 2 * * * /opt/malinfo/scripts/backup.sh >> /var/log/malinfo/backup.log 2>&1

# Or use systemd timer:
# [Unit]
# Description=MALINFO Daily Backup
# [Timer]
# OnCalendar=daily
# Persistent=true
# [Install]
# WantedBy=timers.target
```

### 4.2 Manual Backup

```bash
# Full backup
make backup

# Or directly:
/opt/malinfo/scripts/backup.sh

# Backup location: /opt/malinfo/backups/malinfo_backup_YYYYMMDD_HHMMSS_*
```

### 4.3 Recovery Procedures

**Full Recovery:**
```bash
# 1. Identify backup
ls -la /opt/malinfo/backups/malinfo_backup_*_manifest.json

# 2. Restore
make restore BACKUP_FILE=/opt/malinfo/backups/malinfo_backup_20240115_020000.tar.gz

# 3. Verify
make health
```

**Database-Only Recovery:**
```bash
# 1. Stop services
make deploy-docker ACTION=down

# 2. Restore database
gunzip -c /opt/malinfo/backups/db_20240115_020000.sql.gz | \
  docker compose -f docker-compose.prod.yml exec -T db psql -U malinfo malinfo

# 3. Start services
make deploy-docker ACTION=up
```

**Point-in-Time Recovery (PITR):**
```bash
# Requires PostgreSQL WAL archiving configured
# 1. Stop writes to database
# 2. Restore base backup
# 3. Replay WAL files to desired timestamp
# 4. Promote replica
```

---

## 5. Maintenance Runbook

### 5.1 Weekly Maintenance

```bash
# 1. Update system packages
apt-get update && apt-get upgrade -y

# 2. Update Docker images
docker compose -f docker-compose.prod.yml pull
docker compose -f docker-compose.prod.yml up -d --build

# 3. Rotate logs (automatic via logrotate)

# 4. Check disk space
df -h /opt/malinfo/storage

# 5. Verify backups
ls -la /opt/malinfo/backups/ | tail -10
```

### 5.2 Monthly Maintenance

```bash
# 1. Rotate secrets (if not using secrets manager)
make secrets
# Update .env and restart services

# 2. Update YARA rules
make update-yara

# 3. Update threat intel feeds
make update-feeds

# 4. Generate SBOM
make sbom

# 5. Security scan
make security

# 6. Review alerting rules
# Check Prometheus alerts for noise
```

### 5.3 Certificate Renewal

```bash
# Let's Encrypt (automatic via certbot cron)
# Manual renewal:
certbot renew --quiet --post-hook "cp /etc/letsencrypt/live/yourdomain.com/*.pem /opt/malinfo/deploy/certs/ && docker compose -f /opt/malinfo/docker-compose.prod.yml restart nginx"

# Verify certificate
openssl x509 -in /opt/malinfo/deploy/certs/fullchain.pem -text -noout | grep -A2 "Validity"
```

### 5.4 Database Maintenance

```bash
# Vacuum and analyze
docker compose -f docker-compose.prod.yml exec db psql -U malinfo malinfo -c "VACUUM ANALYZE;"

# Check index usage
docker compose -f docker-compose.prod.yml exec db psql -U malinfo malinfo -c "
SELECT schemaname, tablename, indexname, idx_scan
FROM pg_stat_user_indexes
ORDER BY idx_scan ASC;
"

# Check table sizes
docker compose -f docker-compose.prod.yml exec db psql -U malinfo malinfo -c "
SELECT schemaname, tablename, pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as size
FROM pg_tables
WHERE schemaname = 'public'
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;
"
```

---

## 6. Security Incident Runbook

### 6.1 Suspected Compromise

**Immediate Actions:**
```bash
# 1. Isolate affected systems
#    - Block external access at firewall
#    - Disable compromised accounts

# 2. Preserve evidence
#    - Snapshot affected containers/VMs
#    - Export logs: make logs SERVICE=backend > incident_backend_$(date +%s).log

# 3. Check for indicators
#    - Review audit logs: curl -s https://localhost/api/audit/logs | jq .
#    - Check for unauthorized access patterns
#    - Review API key usage
```

### 6.2 Credential Rotation

```bash
# 1. Generate new secrets
make secrets

# 2. Update in secrets manager
# 3. Update .env
# 4. Rotate database password
docker compose -f docker-compose.prod.yml exec db psql -U malinfo -c "ALTER USER malinfo PASSWORD 'new_password';"
# 5. Update .env with new password
# 6. Restart services
make deploy-docker ACTION=restart

# 7. Revoke all sessions
curl -X POST https://localhost/api/auth/logout-all \
  -H "Authorization: Bearer $ADMIN_TOKEN"

# 8. Rotate API keys
# Via API or admin UI
```

### 6.3 Malicious Sample Handling

```bash
# 1. Quarantine sample
#    - Sample already in isolated storage

# 2. Deep analysis
#    - Trigger sandbox: curl -X POST https://localhost/api/sandbox/detonate -d '{"sample_id": "..."}'
#    - Full static + dynamic + network analysis

# 3. Extract IOCs
#    - curl https://localhost/api/reports/{id} | jq .iocs

# 4. Block IOCs
#    - Add to firewall/IDS
#    - Push to MISP
#    - Update threat intel feeds

# 5. Hunt for IOCs in environment
#    - SIEM query for IPs, domains, hashes
#    - EDR scan for file hashes
```

### 6.4 Post-Incident

```bash
# 1. Document timeline
# 2. Root cause analysis
# 3. Update detection rules
# 4. Update runbooks
# 5. Report to authorities (if required)
# 6. Review and improve security posture
```

---

## Quick Reference Commands

| Task | Command |
|------|---------|
| Check health | `make health` |
| View logs | `make logs [SERVICE=backend]` |
| Service status | `make status` |
| Scale backend | `docker compose -f docker-compose.prod.yml up -d --scale backend=6` |
| Backup | `make backup` |
| Restore | `make restore BACKUP_FILE=...` |
| Update YARA | `make update-yara` |
| Update feeds | `make update-feeds` |
| Generate SBOM | `make sbom` |
| Security scan | `make security` |
| Run tests | `make test` |

---

## Contacts

| Role | Contact | Escalation |
|------|---------|------------|
| Platform Owner | platform-owner@example.gov | Level 1 |
| Security Team | security@example.gov | Level 2 |
| Infrastructure | infra@example.gov | Level 2 |
| Vendor Support | vendor-support@example.com | Level 3 |

---

*Last Updated: $(date)*
*Version: 1.0.0-pilot*