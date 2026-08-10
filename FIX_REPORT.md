# MALINFO CI/CD Fix Report

## Summary
Fixed critical CI/CD pipeline failures and security configuration issues. All changes pushed to `main` branch.

---

## 🔧 Fixes Applied (Auto-Deployed)

### 1. **GitHub Actions Workflow Fix** (`.github/workflows/security.yml`)
**Problem**: Invalid `timeout` input in `docker/build-push-action@v5`  
**Error**: `Warning: Unexpected input(s) 'timeout', valid inputs are [...]`  
**Fix**: Removed the invalid `timeout: 1800` parameter from the build step. The action uses `timeout-minutes` at job level (already set to 60).

### 2. **libvirt-python Build Compatibility** (All Dockerfiles + requirements)
**Problem**: `libvirt-python==10.6.0` requires libvirt C library >= 10.0.0, but Debian Bookworm (base image) ships libvirt 9.x  
**Error**: `Package 'libvirt', required by 'virtual:world', not found` and generator failures  
**Fix**: 
- Downgraded to `libvirt-python==9.13.0` (compatible with libvirt 9.x)
- Added `PKG_CONFIG_PATH` environment variable to all builder stages
- Applied to: `Dockerfile`, `Dockerfile.prod`, `Dockerfile.icap`, `Dockerfile.monitor`

### 3. **Missing Auth Package Init** (`backend/app/auth/__init__.py`)
**Problem**: Missing `__init__.py` caused import failures  
**Fix**: Created package init with all exports from `rbac.py`

### 4. **Dependency Sync**
**Problem**: `requirements.txt` and `pyproject.toml` had conflicting libvirt-python versions  
**Fix**: Synced both to `libvirt-python==9.13.0`

---

## ⚠️ CRITICAL: Actions Required from YOU (Before Production)

### 1. **Generate Production Secrets** (MUST DO)
Run the secrets generator and store in your secrets manager:
```bash
cd /path/to/MALINFOx
chmod +x scripts/generate-secrets.sh
./scripts/generate-secrets.sh
```
**Save these securely** (HashiCorp Vault, AWS Secrets Manager, GitHub Secrets):
- `SECRET_KEY` - JWT signing key (32+ chars)
- `POSTGRES_PASSWORD` - Database password
- `GRAFANA_PASSWORD` - Grafana admin password

### 2. **Configure Threat Intelligence API Keys** (REQUIRED for full functionality)
Add to your `.env` or secrets manager:
```bash
VIRUSTOTAL_API_KEY=your_key_here
OTX_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here
MISP_URL=https://your-misp-instance.com
MISP_API_KEY=your_key_here
```

### 3. **Configure SMTP for Agency Notifications** (REQUIRED for CERT-In/Cyber Crime Cell alerts)
```bash
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=your-16-char-app-password
SMTP_TLS=true
NOTIFICATION_FROM_EMAIL=noreply@yourdomain.gov.in
AGENCY_NOTIFICATION_EMAIL=cert-in@yourdomain.gov.in
```

### 4. **Generate TLS Certificates** (REQUIRED for HTTPS)
**For Production (Let's Encrypt):**
```bash
sudo ./scripts/generate-certs.sh ./deploy/certs letsencrypt malinfo.yourdomain.gov.in admin@yourdomain.gov.in
```

**For Staging/Testing (Self-Signed):**
```bash
./scripts/generate-certs.sh ./deploy/certs selfsigned malinfo.yourdomain.gov.in
```

### 5. **Set GitHub Repository Secrets** (REQUIRED for CI/CD)
Go to **Settings → Secrets and variables → Actions** and add:
| Secret Name | Value |
|-------------|-------|
| `POSTGRES_PASSWORD` | From step 1 |
| `GRAFANA_PASSWORD` | From step 1 |
| `SECRET_KEY` | From step 1 |
| `DOCKER_REGISTRY_TOKEN` | (Optional) For external registry |

### 6. **Configure Domain & DNS** (REQUIRED)
- Point `malinfo.yourdomain.gov.in` to your server IP
- Update `.env.example` `ALLOWED_ORIGINS` with your domain
- Update `deploy/nginx.prod.conf` `server_name` if using direct TLS

### 7. **Oracle Cloud Free Tier Setup** (If using Oracle Cloud)
```bash
# On your Oracle Cloud ARM instance (4 OCPU, 24GB RAM)
# 1. Enable KVM nested virtualization
echo "options kvm_intel nested=1" | sudo tee /etc/modprobe.d/kvm.conf
echo "options kvm_amd nested=1" | sudo tee -a /etc/modprobe.d/kvm.conf
sudo update-initramfs -u && sudo reboot

# 2. Install Docker & Docker Compose
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
# Log out/in

# 3. Deploy MALINFO
git clone https://github.com/xC0D3F4TH3R/MALINFOx.git
cd MALINFOx
cp .env.example .env
# EDIT .env with ALL values from steps 1-3
make prod
```

### 8. **Cloudflare Tunnel Setup** (FREE TLS/WAF/DDoS)
```bash
# Install cloudflared
wget https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb
sudo dpkg -i cloudflared-linux-amd64.deb

# Authenticate
cloudflared tunnel login

# Create tunnel
cloudflared tunnel create malinfo

# Configure tunnel (create config.yml)
tunnel: <tunnel-id>
credentials-file: /home/user/.cloudflared/<tunnel-id>.json
ingress:
  - hostname: malinfo.yourdomain.gov.in
    service: http://localhost:80
  - service: http_status:404

# Run as service
sudo cloudflared service install
sudo systemctl start cloudflared
```

---

## 📋 Post-Deployment Verification

Run the verification script after deployment:
```bash
cd /path/to/MALINFOx
python3 scripts/verify-deployment.py --url https://malinfo.yourdomain.gov.in --json
```

Expected checks:
- ✅ TLS Certificate valid
- ✅ Security Headers present (HSTS, CSP, etc.)
- ✅ API Health endpoint responding
- ✅ Authentication working
- ✅ Rate limiting active
- ✅ Static analysis pipeline functional
- ✅ YARA rules loaded
- ✅ Prometheus metrics exposed
- ✅ WebSocket functional
- ✅ Docker services healthy
- ✅ Disk space adequate

---

## 🏗️ Architecture Overview for Government Agencies

```
┌─────────────────────────────────────────────────────────────────┐
│                    MALINFO PRODUCTION STACK                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐      │
│  │   Cloudflare │───▶│    Nginx     │───▶│   Backend    │      │
│  │   Tunnel     │    │  (TLS Term)  │    │  (FastAPI)   │      │
│  │  (WAF/DDoS)  │    │  Rate Limit  │    │  Port 8000   │      │
│  └──────────────┘    └──────────────┘    └──────┬───────┘      │
│                                                 │              │
│                    ┌──────────────┐    ┌────────┴────────┐    │
│                    │  PostgreSQL  │    │     Redis       │    │
│                    │   (Port 5432)│    │   (Port 6379)   │    │
│                    └──────────────┘    └─────────────────┘    │
│                                                 │              │
│                    ┌──────────────┐    ┌────────┴────────┐    │
│                    │   libvirt/   │    │   Monitoring    │    │
│                    │    QEMU/KVM  │    │   (Optional)    │    │
│                    │  (VM Sandbox)│    │                 │    │
│                    └──────────────┘    └─────────────────┘    │
│                                                                  │
│  Optional Profiles: --profile monitoring --profile icap         │
│  (Prometheus, Grafana, ICAP Gateway, File Monitor)              │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🔐 Security Hardening Checklist (Verify Each)

- [ ] `SECRET_KEY` is 32+ random chars (not placeholder)
- [ ] `DATABASE_URL` uses PostgreSQL (not SQLite)
- [ ] `ALLOWED_ORIGINS` only your domain(s)
- [ ] TLS certificates valid & auto-renewing
- [ ] SMTP configured with app password (not account password)
- [ ] Threat intel API keys configured
- [ ] Database password rotated from default
- [ ] Grafana admin password changed
- [ ] Cloudflare WAF rules enabled (if using tunnel)
- [ ] Firewall: only 80/443 inbound, 53/123 outbound
- [ ] KVM nested virtualization enabled (for VM orchestrator)
- [ ] Non-root Docker containers (already configured)
- [ ] Read-only root filesystem where possible (already configured)

---

## 🚀 Deployment Commands Quick Reference

| Command | Description |
|---------|-------------|
| `make init` | Initialize directories & config |
| `make dev` | Start dev environment (hot reload) |
| `make staging` | Deploy staging (Docker Compose) |
| `make prod` | Deploy production (all profiles) |
| `make certs MODE=letsencrypt DOMAIN=... EMAIL=...` | Generate TLS certs |
| `make secrets` | Generate production secrets |
| `make health` | Run health checks |
| `make logs SERVICE=backend` | Follow service logs |
| `make backup` | Full backup (DB + storage + config) |
| `make test` | Run test suite |
| `make lint` | Run linters (ruff, mypy, bandit) |
| `make security` | Run security scans |
| `make sbom` | Generate Software Bill of Materials |

---

## 📞 Support & Next Steps

1. **After deploying**: Run `python3 scripts/verify-deployment.py --url https://yourdomain.gov.in`
2. **Create admin user**: The deploy script does this automatically, or use API:
   ```bash
   curl -X POST https://yourdomain.gov.in/api/auth/users \
     -H "Authorization: Bearer <admin-token>" \
     -d '{"username":"admin","email":"admin@yourdomain.gov.in","full_name":"Admin","role":"admin","password":"SecurePass123!","is_active":true,"is_verified":true}'
   ```
3. **Add users**: Login as admin → navigate to `/#users` → Create analysts/viewers
4. **Enable MFA**: Required for all accounts (Settings → MFA)
5. **Schedule feeds**: `make update-yara` and `make update-feeds` (add to cron)

---

## 📁 Files Modified in This Fix

```
.github/workflows/security.yml          # Fixed invalid timeout input
backend/Dockerfile                       # Added PKG_CONFIG_PATH, libvirt note
backend/Dockerfile.prod                  # Added PKG_CONFIG_PATH, libvirt note
backend/Dockerfile.icap                  # Added PKG_CONFIG_PATH
backend/Dockerfile.monitor               # Added PKG_CONFIG_PATH
backend/requirements.txt                 # libvirt-python 9.13.0
backend/pyproject.toml                   # libvirt-python 9.13.0
backend/app/auth/__init__.py             # NEW: Package init file
```

**Commit**: `1963e12` — "Fix CI/CD pipeline: remove invalid timeout input, fix libvirt-python build compatibility, add PKG_CONFIG_PATH"

---

## ❗ If Build Still Fails

Check GitHub Actions logs for:
1. **Docker layer caching issues** - The `CACHE_BUST` build arg should force rebuild
2. **libvirt version mismatch** - Ensure base image has libvirt-dev 9.x
3. **Network issues** - GitHub Actions may have pkg-config lookup delays

If persistent, consider using `docker/build-push-action@v6` (newer) or building locally and pushing:
```bash
docker build -t ghcr.io/xc0d3f4th3r/malinfox/backend:latest -f backend/Dockerfile.prod backend/
docker push ghcr.io/xc0d3f4th3r/malinfox/backend:latest
```

---

**Status**: ✅ CI/CD Pipeline Fixed | ⚠️ Production Secrets Required | 🚀 Ready for Deployment