# MALINFO — Production Deployment Guide

This guide covers deploying MALINFO to **free/low-cost hosting platforms** suitable for government and high-model agency use. MALINFO is a national malware analysis & C2 intelligence platform with static analysis, dynamic sandbox detonation, network forensics, and public threat reporting.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                        MALINFO Platform                              │
├─────────────────────────────────────────────────────────────────────┤
│  Frontend (Static)     │  Backend API (FastAPI)                    │
│  - HTML/CSS/JS         │  - Static Analysis (PE/ELF/APK/Mach-O)    │
│  - SPA with WebSocket  │  - YARA Rule Engine                       │
│                        │  - IOC Extraction & Enrichment            │
│  Nginx (Reverse Proxy) │  - Threat Intel (VT, OTX, AbuseIPDB, MISP)│
│  - Rate Limiting       │  - Dynamic Sandbox (CAPEv2 / Built-in VM) │
│  - TLS Termination     │  - Network Forensics (PCAP/DNS/HTTP)      │
│  - Security Headers    │  - Public Reporting & Agency Notifications│
├────────────────────────┼────────────────────────────────────────────┤
│  PostgreSQL 16         │  Redis 7 (Caching/Sessions/Rate Limit)   │
│  - Async (asyncpg)     │  - Sessions & Token Revocation            │
│  - Alembic Migrations  │  - API Rate Limiting                      │
└────────────────────────┴────────────────────────────────────────────┘
```

## Prerequisites

- **Domain name** (e.g., `malinfo.yourdomain.gov`)
- **TLS certificates** (Let's Encrypt or your CA)
- **SMTP credentials** for agency notifications
- **Threat intelligence API keys** (VirusTotal, OTX, AbuseIPDB, MISP) — optional but recommended
- **Docker & Docker Compose** installed on target server

---

## Quick Start (Automated)

The easiest way to deploy MALINFO is using the included deployment script:

```bash
# Make executable (first time only)
chmod +x deploy.sh

# Self-hosted (your own VM/VPS) - FULL CONTROL, KVM SUPPORT
./deploy.sh selfhosted malinfo.yourdomain.gov admin@yourdomain.gov "SecurePass123!"

# Fly.io - FREE TIER WITH KVM (only free option with dynamic sandbox)
./deploy.sh fly malinfo.yourdomain.gov

# Railway - EASIEST, NO KVM (static analysis only)
./deploy.sh railway malinfo.yourdomain.gov
```

**What the script does automatically:**
1. ✅ Prompts for admin credentials (or accepts as arguments)
2. ✅ Generates secure secrets (SECRET_KEY, DB passwords, etc.)
3. ✅ Creates `.env` template with all required variables
4. ✅ Sets up Docker storage directories
5. ✅ Generates TLS certificates (self-signed for testing, Let's Encrypt for prod)
6. ✅ Builds and starts all services via Docker Compose
7. ✅ Creates the initial **admin user** with your credentials
8. ✅ Prints access URLs and next steps

**After deployment:**
- Login at `https://yourdomain.gov` with your admin credentials
- Navigate to **Users** page to create analyst/viewer accounts
- Edit `.env` to add SMTP credentials for agency notifications
- Add threat intel API keys (VT, OTX, AbuseIPDB, MISP) in `.env`

---

## Option 1: Railway (Easiest - Free Tier Available)

Railway provides a generous free tier ($5/month credit) with PostgreSQL, Redis, and automatic HTTPS.

### 1. Fork/Clone Repository

```bash
git clone https://github.com/your-org/malinfo.git
cd malinfo
```

### 2. Configure Environment Variables

In Railway dashboard, add these environment variables:

**Required:**
```
ENVIRONMENT=production
DEBUG=false
SECRET_KEY=<generate with: openssl rand -base64 32>
POSTGRES_PASSWORD=<railway-provided>
GRAFANA_PASSWORD=<generate secure password>
DATABASE_URL=postgresql+asyncpg://postgres:${POSTGRES_PASSWORD}@postgres.railway.internal:5432/railway
REDIS_URL=redis://default:${REDIS_PASSWORD}@redis.railway.internal:6379/0
ALLOWED_ORIGINS=["https://malinfo.yourdomain.gov"]
```

**Agency Notifications (Required for Government Use):**
```
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-gmail@gmail.com
SMTP_PASSWORD=your-16-char-app-password
SMTP_TLS=true
NOTIFICATION_FROM_EMAIL=noreply@malinfo.yourdomain.gov
AGENCY_NOTIFICATION_EMAIL=your-agency@gov.in
```

**Threat Intel (Optional but Recommended):**
```
VIRUSTOTAL_API_KEY=your-vt-key
OTX_API_KEY=your-otx-key
ABUSEIPDB_API_KEY=your-abuseipdb-key
MISP_URL=https://your-misp-instance
MISP_API_KEY=your-misp-key
MISP_VERIFY_SSL=true
```

### 3. Create Railway Services

Create 4 services in Railway project:

1. **PostgreSQL** - Use Railway's managed PostgreSQL
2. **Redis** - Use Railway's managed Redis
3. **Backend** - Dockerfile from `backend/Dockerfile.prod`
4. **Frontend** - Nginx serving `frontend/` directory

### 4. Deploy

```bash
# Install Railway CLI
npm install -g @railway/cli

# Login and deploy
railway login
railway link <project-id>
railway up
```

### 5. Custom Domain

In Railway dashboard → Settings → Domains → Add `malinfo.yourdomain.gov`
Railway auto-provisions TLS via Let's Encrypt.

---

## Option 2: Render (Free Tier + PostgreSQL)

Render offers free PostgreSQL for 90 days, then $7/month. Good free tier for web services.

### 1. Create Services on Render Dashboard

**PostgreSQL Database:**
- Name: `malinfo-db`
- Database: `malinfo`
- User: `malinfo`
- Region: Choose closest to users

**Redis:**
- Name: `malinfo-redis`
- Region: Same as DB

**Backend Web Service:**
- Name: `malinfo-api`
- Runtime: Docker
- Dockerfile: `backend/Dockerfile.prod`
- Build Context: `./backend`
- Environment Variables: (Same as Railway)
- Health Check Path: `/api/health`
- Port: 8000

**Frontend Static Site:**
- Name: `malinfo-frontend`
- Build Command: (none - static files)
- Publish Directory: `frontend`
- Routes: `/* → /index.html` (SPA support)

### 2. Configure Custom Domain

Settings → Custom Domains → Add `malinfo.yourdomain.gov`
Render provisions TLS automatically.

### 3. Nginx Config for Render

Render's static sites don't support custom nginx config. Use backend CORS settings:

```python
# In backend/app/config.py - ALLOWED_ORIGINS
ALLOWED_ORIGINS = ["https://malinfo.yourdomain.gov", "https://malinfo-frontend.onrender.com"]
```

---

## Option 3: Fly.io (Best for VM Orchestration)

Fly.io is the **only free-tier platform supporting KVM/QEMU** — essential for MALINFO's built-in VM orchestrator (dynamic sandbox).

### 1. Install Fly CLI

```bash
# Windows
iwr https://fly.io/install.ps1 -useb | iex

# Linux/macOS
curl -L https://fly.io/install.sh | sh
```

### 2. Create Fly Apps

```bash
# Authenticate
fly auth login

# Create PostgreSQL cluster
fly postgres create --name malinfo-db --region <region> --initial-cluster-size 1

# Create Redis
fly redis create --name malinfo-redis --region <region>

# Create backend app (with KVM support)
fly apps create malinfo-api --org personal

# Create frontend app
fly apps create malinfo-frontend --org personal
```

### 3. Configure Backend for KVM (`fly.toml`)

```toml
# fly.toml (backend)
app = "malinfo-api"
primary_region = "iad"  # or your region

[build]
  dockerfile = "Dockerfile.prod"

[env]
  ENVIRONMENT = "production"
  DEBUG = "false"
  API_PREFIX = "/api"
  DATABASE_URL = "postgresql+asyncpg://malinfo:PASSWORD@malinfo-db.internal:5432/malinfo"
  REDIS_URL = "redis://default:PASSWORD@malinfo-redis.internal:6379/0"
  VM_ORCHESTRATOR_ENABLED = "true"
  LIBVIRT_URI = "qemu:///system"

[http_service]
  internal_port = 8000
  force_https = true
  auto_stop_machines = false  # Keep running for VM orchestrator
  min_machines_running = 1

[mounts]
  source = "malinfo_storage"
  destination = "/app/storage"

[vm]
  memory = "4gb"
  cpus = 2
  # Enable KVM for VM orchestration
  enable_kvm = true

[processes]
  app = "gunicorn app.main:app --workers 4 --worker-class uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000 --timeout 300"
```

### 4. Deploy Backend

```bash
# Create volume for storage
fly volumes create malinfo_storage --size 20 --app malinfo-api

# Deploy
fly deploy --app malinfo-api
```

### 5. Deploy Frontend

```toml
# fly.toml (frontend)
app = "malinfo-frontend"

[build]
  image = "nginx:1.27-alpine"
  # Or use static buildpack

[http_service]
  internal_port = 8080
  force_https = true

[mounts]
  source = "frontend_dist"
  destination = "/usr/share/nginx/html"
```

### 6. Configure Custom Domain + TLS

```bash
fly certs create malinfo.yourdomain.gov --app malinfo-frontend
fly certs create api.malinfo.yourdomain.gov --app malinfo-api
```

---

## Option 4: Self-Hosted on VM (Maximum Control)

For full government-grade deployment with complete isolation.

### Server Requirements

- **CPU**: 4+ cores (for VM orchestration)
- **RAM**: 16 GB minimum (32 GB recommended)
- **Storage**: 100 GB+ SSD
- **OS**: Ubuntu 22.04 LTS or Rocky Linux 9
- **Network**: Static IP, firewall configured

### 1. Install Dependencies

```bash
# Docker & Compose
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER

# QEMU/KVM for VM Orchestrator
sudo apt-get update && sudo apt-get install -y \
  qemu-kvm libvirt-daemon-system libvirt-clients bridge-utils \
  virtinst cpu-checker

# Verify KVM
kvm-ok
```

### 2. Configure KVM for Non-Root

```bash
# Add user to groups
sudo usermod -aG kvm,libvirt $USER

# Configure libvirt for unprivileged access
sudo sed -i 's/#unix_sock_group = "libvirt"/unix_sock_group = "libvirt"/' /etc/libvirt/libvirtd.conf
sudo sed -i 's/#unix_sock_rw_perms = "0770"/unix_sock_rw_perms = "0770"/' /etc/libvirt/libvirtd.conf
sudo systemctl restart libvirtd
```

### 3. Clone & Configure

```bash
git clone https://github.com/your-org/malinfo.git /opt/malinfo
cd /opt/malinfo
cp .env.example .env
# EDIT .env with ALL production values
```

### 4. Generate TLS Certificates

```bash
# Using Let's Encrypt (certbot)
sudo apt-get install certbot
sudo certbot certonly --standalone -d malinfo.yourdomain.gov -d api.malinfo.yourdomain.gov

# Copy to deploy/certs/
sudo mkdir -p /opt/malinfo/deploy/certs
sudo cp /etc/letsencrypt/live/malinfo.yourdomain.gov/fullchain.pem /opt/malinfo/deploy/certs/
sudo cp /etc/letsencrypt/live/malinfo.yourdomain.gov/privkey.pem /opt/malinfo/deploy/certs/
sudo chown -R $USER:$USER /opt/malinfo/deploy/certs
```

### 5. Deploy with Docker Compose

```bash
cd /opt/malinfo

# Production deployment with monitoring
docker compose -f docker-compose.prod.yml --profile monitoring --profile icap --profile monitor up -d --build

# Verify
docker compose -f docker-compose.prod.yml ps
curl -k https://localhost/api/health
```

### 6. Systemd Service for Auto-Start

```bash
sudo tee /etc/systemd/system/malinfo.service > /dev/null <<EOF
[Unit]
Description=MALINFO Malware Analysis Platform
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/malinfo
ExecStart=/usr/bin/docker compose -f docker-compose.prod.yml --profile monitoring up -d
ExecStop=/usr/bin/docker compose -f docker-compose.prod.yml down
TimeoutStartSec=300

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl enable malinfo
sudo systemctl start malinfo
```

### 7. Configure Auto-Renewal for TLS

```bash
# Add to crontab
sudo crontab -e

# Add:
0 3 * * * certbot renew --quiet --deploy-hook "cp /etc/letsencrypt/live/malinfo.yourdomain.gov/* /opt/malinfo/deploy/certs/ && docker compose -f /opt/malinfo/docker-compose.prod.yml restart nginx"
```

---

## Security Hardening Checklist (Government-Grade)

### Network Security
- [ ] **WAF** in front (Cloudflare WAF, AWS WAF, or ModSecurity)
- [ ] **Rate limiting** on all public endpoints (configured in nginx)
- [ ] **IP allowlisting** for admin panel (`/api/auth/users`, `/api/audit`)
- [ ] **Network segmentation** - backend DB/Redis not internet-accessible
- [ ] **Egress filtering** - sandbox VMs have NO internet (use INetSim/FakeNet-NG)

### Application Security
- [ ] **Strong SECRET_KEY** (32+ bytes, generated via `openssl rand -base64 32`)
- [ ] **MFA enforced** for all admin/analyst accounts
- [ ] **Account lockout** after 5 failed attempts (configured)
- [ ] **Audit logging** enabled with 365-day retention
- [ ] **CORS** restricted to exact production domain only
- [ ] **Security headers** (HSTS, CSP, X-Frame-Options) — nginx config has these

### Data Protection
- [ ] **TLS 1.2+** everywhere (enforced in nginx)
- [ ] **Database encryption at rest** (PostgreSQL TDE or volume encryption)
- [ ] **Secrets in vault** (HashiCorp Vault, AWS Secrets Manager, NOT .env)
- [ ] **Backup encryption** (GPG-encrypt database dumps)
- [ ] **Data retention policy** implemented

### Operational Security
- [ ] **SIEM integration** (forward audit logs to Splunk/ELK/Graylog)
- [ ] **Vulnerability scanning** (Trivy in CI/CD, scheduled scans)
- [ ] **SBOM generation** (CycloneDX via `make sbom`)
- [ ] **Incident response plan** documented
- [ ] **Regular penetration testing** scheduled

---

## Post-Deployment Verification

```bash
# 1. Health check
curl -k https://malinfo.yourdomain.gov/api/health
# Expected: {"status":"ok","app":"MALINFO","environment":"production",...}

# 2. Frontend loads
curl -k https://malinfo.yourdomain.gov/
# Should return HTML with MALINFO title

# 3. Authentication flow
# - Visit https://malinfo.yourdomain.gov
# - Login with admin credentials
# - Verify MFA setup works

# 4. Upload test file
# - Use EICAR test file: curl -o eicar.com https://secure.eicar.org/eicar.com
# - Upload via UI or API
# - Verify analysis completes

# 5. Public reporting
curl -k -X POST https://malinfo.yourdomain.gov/api/public/report/details \
  -H "Content-Type: application/json" \
  -d '{"report_type":"url","description":"Test phishing URL report","submitted_value":"http://malicious.example.com/phish"}'
# Should return reference code

# 6. Agency notification
# Check email at AGENCY_NOTIFICATION_EMAIL for notification

# 7. Metrics
curl -k https://malinfo.yourdomain.gov/metrics
# Should return Prometheus metrics
```

---

## Scaling Considerations

| Component | Free Tier Limit | Scale Strategy |
|-----------|-----------------|----------------|
| API Workers | 4 (gunicorn) | Increase `--workers` + add machines |
| PostgreSQL | 1 GB RAM | Read replicas, connection pooling (PgBouncer) |
| Redis | 256 MB | Cluster mode, separate cache/queue instances |
| VM Orchestrator | Limited by host CPU/RAM | Dedicated bare-metal or GPU instances |
| Storage | Volume size | S3-compatible (MinIO, R2, S3) for reports/uploads |

---

## Troubleshooting

### Backend Won't Start
```bash
docker compose logs backend
# Common: DATABASE_URL wrong, SECRET_KEY missing, migration failed
```

### VM Orchestrator Fails
```bash
# Check KVM access
docker exec -it malinfo-backend kvm-ok
# Check libvirt
docker exec -it malinfo-backend virsh -c qemu:///system list
```

### Frontend Shows "Cannot connect to backend"
- Check `ALLOWED_ORIGINS` includes frontend domain
- Verify nginx proxy_pass points to correct backend service name
- Check browser console for CORS errors

### Rate Limited Immediately
- Verify `X-Forwarded-For` header passed by proxy
- Check nginx `limit_req_zone` uses `$binary_remote_addr`

---

## Support & Maintenance

- **Logs**: `docker compose logs -f backend`
- **Metrics**: `https://malinfo.yourdomain.gov/metrics` (Prometheus)
- **Grafana**: `https://malinfo.yourdomain.gov:3000` (if monitoring profile enabled)
- **Backups**: `make backup` (stores to `/opt/malinfo/backups/`)
- **Updates**: `git pull && docker compose -f docker-compose.prod.yml up -d --build`

---

## Cost Summary (Monthly Estimates)

| Platform | Free Tier | Production Estimate |
|----------|-----------|---------------------|
| Railway | $5 credit/mo | $10-20/mo |
| Render | 90 days free DB | $15-25/mo |
| Fly.io | 3 shared-cpu VMs | $20-40/mo (with KVM) |
| Self-Hosted | Hardware only | $0 (existing infra) |

**For Government Use**: Self-hosted on approved infrastructure or Fly.io (only option with KVM for dynamic analysis) is recommended for data sovereignty and compliance.

---

## License & Compliance

MALINFO is designed for **authorized use only** on infrastructure the deploying authority legally controls. The ICAP gateway and file monitoring features require explicit legal authorization per jurisdiction.

**Never** deploy MALINFO to inspect traffic you don't own/operate. This violates wiretap laws in most jurisdictions.

---

*Last updated: 2025*  
*MALINFO v1.0.0-pilot — National Malware Analysis & C2 Intelligence Platform*