# MALINFO — National Malware Analysis & Threat Intelligence Platform

[![Version](https://img.shields.io/badge/version-1.0.0--pilot-blue.svg)](https://github.com/your-org/malinfo)
[![License](https://img.shields.io/badge/license-Government%20Use%20Authorized-green.svg)](LICENSE)
[![Build](https://img.shields.io/badge/build-passing-brightgreen.svg)]()
[![Security](https://img.shields.io/badge/security-hardened-critical.svg)]()
[![Deployment](https://img.shields.io/badge/deployment-Docker%20%7C%20K8s%20%7C%20systemd-orange.svg)]()

> **Government-grade malware analysis platform** with static analysis, dynamic sandbox detonation, network forensics, real-time monitoring, and public threat reporting — designed for CERTs, SOCs, and national cyber defense operations.

---

## 🎯 Overview

MALINFO is a comprehensive, production-ready malware analysis platform built for government and enterprise environments. It provides end-to-end analysis capabilities from file ingestion through deep static/dynamic analysis to actionable intelligence reporting.

### Key Capabilities

| Domain | Capabilities |
|--------|--------------|
| **Static Analysis** | PE/ELF/Mach-O/APK/OLE/Script deep analysis, YARA scanning, IOC extraction, entropy analysis, risk scoring |
| **Dynamic Analysis** | CAPEv2 integration with Volatility3 memory analysis, API monitoring, MITRE ATT&CK mapping, process trees |
| **Network Forensics** | PCAP parsing, JA3/JA3S TLS fingerprinting, DGA detection, C2 protocol parsing, beaconing analysis |
| **Threat Intelligence** | STIX/TAXII 2.1 server, MISP sync, actor/campaign profiling, ATT&CK Navigator, feed management |
| **Real-Time Monitoring** | ICAP gateway (REQMOD/RESPMOD), filesystem monitoring, network flow analysis, auto-analysis pipeline |
| **Authentication** | JWT + MFA, RBAC (5 roles, 20+ permissions), audit logging, API keys, session management |
| **Reporting** | Executive summary, technical deep-dive, MITRE matrix, kill chain, IOC packages (STIX/MISP/CSV/PDF) |

---

## 🏗 Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              MALINFO Platform                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │   Analyst    │  │   Public     │  │   Network    │  │   Email/     │  │
│  │  Dashboard   │  │  Reporting   │  │  Gateway     │  │   Proxy      │  │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  │
│         │                 │                 │                 │          │
│         ▼                 ▼                 ▼                 ▼          │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │                    NGINX Reverse Proxy (TLS)                        │  │
│  └────────────────────────────┬───────────────────────────────────────┘  │
│                               │                                           │
│         ┌─────────────────────┼─────────────────────┐                   │
│         ▼                     ▼                     ▼                   │
│  ┌─────────────┐      ┌─────────────┐      ┌─────────────┐             │
│  │   Backend   │      │   Backend   │      │   Backend   │             │
│  │   (API)     │      │   (ICAP)    │      │  (Monitor)  │             │
│  └──────┬──────┘      └──────┬──────┘      └──────┬──────┘             │
│         │                    │                    │                      │
│         └────────────────────┼────────────────────┘                      │
│                              ▼                                           │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │                    PostgreSQL + Redis                               │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│                              │                                           │
│         ┌────────────────────┼────────────────────┐                      │
│         ▼                    ▼                    ▼                      │
│  ┌─────────────┐      ┌─────────────┐      ┌─────────────┐             │
│  │   Static    │      │  Sandbox    │      │   Network   │             │
│  │  Analysis   │      │ (CAPEv2)    │      │  Forensics  │             │
│  └─────────────┘      └─────────────┘      └─────────────┘             │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Technology Stack

| Layer | Technologies |
|-------|--------------|
| **API** | FastAPI, Uvicorn, Pydantic, SQLAlchemy 2.0, AsyncPG |
| **Frontend** | Vanilla ES Modules, CSS Custom Properties, WebSocket |
| **Database** | PostgreSQL 16 (async), Redis 7 (caching/sessions) |
| **Analysis** | pefile, pyelftools, macholib, androguard, yara-python, scapy |
| **Sandbox** | CAPEv2 REST API, Volatility3 integration |
| **Monitoring** | Prometheus, Grafana, OpenTelemetry-ready |
| **Deployment** | Docker Compose, Kubernetes (Helm-ready), systemd |
| **Security** | JWT HS256, bcrypt, pyotp, TLS 1.2/1.3, CSP, HSTS |

---

## 🚀 Quick Start

### Prerequisites

- Docker 24+ and Docker Compose 2+
- 16GB+ RAM, 4+ CPU cores
- 200GB+ disk space
- TLS certificates (Let's Encrypt or CA-issued)

### 1. Initialize Project

```bash
git clone https://github.com/your-org/malinfo.git
cd malinfo
make init
```

### 2. Generate Secrets

```bash
make secrets
# Output example:
# SECRET_KEY=K8s9Xm2P... (save this!)
# POSTGRES_PASSWORD=aB3xY7zL... (save this!)
# GRAFANA_PASSWORD=pQ9rT2wE... (save this!)
# VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
# OTX_API_KEY=your_otx_api_key_here
# ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
# MISP_URL=https://your-misp-instance.example.com
# MISP_API_KEY=your_misp_api_key_here
```

> **Critical**: Store all secrets in your secrets manager (HashiCorp Vault, AWS Secrets Manager, etc.)

### 3. Configure Environment

```bash
cp .env.example .env
# Edit .env with ALL required values:
#   - SECRET_KEY (from step 2)
#   - POSTGRES_PASSWORD (from step 2)
#   - GRAFANA_PASSWORD (from step 2)
#   - ALLOWED_ORIGINS=https://malinfo.yourdomain.gov
#   - Threat intel API keys
```

### 4. Generate TLS Certificates

```bash
# Staging (self-signed)
make certs MODE=selfsigned DOMAIN=malinfo-staging.example.com

# Production (Let's Encrypt)
make certs MODE=letsencrypt DOMAIN=malinfo.example.gov EMAIL=admin@example.gov
```

### 5. Deploy

```bash
# Full production stack with all profiles
make prod

# Or deploy specific profiles
make deploy-docker ACTION=up PROFILE=all
```

### 6. Verify Deployment

```bash
make health
make status
```

**Access Points:**
- **Dashboard**: `https://malinfo.yourdomain.gov`
- **API**: `https://malinfo.yourdomain.gov/api`
- **Metrics**: `https://malinfo.yourdomain.gov:9090` (Prometheus)
- **Grafana**: `https://malinfo.yourdomain.gov:3000` (admin / GRAFANA_PASSWORD)

---

## 📦 Deployment Options

### Docker Compose (Recommended)

```bash
# Development
make dev

# Staging
make staging

# Production
make prod

# With specific profiles
docker compose -f docker-compose.prod.yml --profile monitoring --profile icap --profile monitor up -d
```

**Profiles:**
| Profile | Services | Use Case |
|---------|----------|----------|
| (default) | db, redis, backend, nginx | Core platform |
| `monitoring` | prometheus, grafana, exporters | Observability |
| `icap` | icap gateway | Network content inspection |
| `monitor` | file transfer monitor | Real-time filesystem monitoring |
| `all` | All above | Full production |

### Kubernetes

```bash
# 1. Apply manifests
kubectl apply -f deploy/kubernetes/malinfo-platform.yaml

# 2. Create secrets
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

# 4. Verify
kubectl get all -n malinfo
```

### systemd (Bare Metal)

```bash
# 1. Create user and directories
sudo useradd -r -s /bin/bash -d /opt/malinfo malinfo
sudo mkdir -p /opt/malinfo/{backend,storage/{uploads,reports,pcaps},logs}
sudo chown -R malinfo:malinfo /opt/malinfo

# 2. Install Python dependencies
sudo -u malinfo python3 -m venv /opt/malinfo/venv
sudo -u malinfo /opt/malinfo/venv/bin/pip install -r backend/requirements.txt

# 3. Copy application
sudo cp -r backend/* /opt/malinfo/backend/
sudo cp .env /opt/malinfo/.env
sudo chown -R malinfo:malinfo /opt/malinfo/backend /opt/malinfo/.env

# 4. Install services
sudo cp deploy/malinfo-*.service /etc/systemd/system/
sudo cp deploy/logrotate/malinfo /etc/logrotate.d/malinfo

# 5. Start
sudo systemctl daemon-reload
sudo systemctl enable --now malinfo-backend malinfo-icap malinfo-monitor
```

---

## ⚙️ Configuration

### Required Environment Variables

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `SECRET_KEY` | JWT signing key (32+ chars) | **YES** | — |
| `DATABASE_URL` | PostgreSQL connection string | **YES** | — |
| `REDIS_URL` | Redis connection string | **YES** | — |
| `POSTGRES_PASSWORD` | Database password | **YES** | — |
| `ALLOWED_ORIGINS` | CORS origins (JSON array) | **YES** | — |
| `GRAFANA_PASSWORD` | Grafana admin password | **YES** | — |
| `ENVIRONMENT` | deployment environment | No | `production` |
| `DEBUG` | Debug mode | No | `false` |
| `MAX_UPLOAD_SIZE_MB` | Max file upload size | No | `250` |

### Optional Integrations

| Variable | Description | Required If |
|----------|-------------|-------------|
| `VIRUSTOTAL_API_KEY` | VirusTotal v3 API key | Using VT enrichment |
| `OTX_API_KEY` | AlienVault OTX API key | Using OTX enrichment |
| `ABUSEIPDB_API_KEY` | AbuseIPDB API key | Using AbuseIPDB enrichment |
| `MISP_URL` / `MISP_API_KEY` | MISP instance | Using MISP sync |
| `SANDBOX_ENABLED` | Enable CAPEv2 | `true` |
| `SANDBOX_API_URL` | CAPEv2 controller URL | Sandbox enabled |
| `ICAP_ENABLED` | Enable ICAP gateway | `true` |
| `MONITOR_ENABLED` | Enable file monitoring | `true` |
| `MONITOR_WATCH_PATHS` | Paths to watch (JSON array) | Monitor enabled |
| `GHIDRA_PATH` | Ghidra installation path | Using decompiler |
| `RETDEC_PATH` | Retdec installation path | Using decompiler fallback |

### YARA Rules

```bash
# Directory structure (auto-created)
/opt/malinfo/rules/yara/
├── sources/           # Source .yar files
│   ├── official/      # Curated MALINFO rulesets
│   ├── feeds/         # Auto-pulled from feeds
│   │   ├── yara-rules/
│   │   ├── malwarebazaar/
│   │   └── custom-org/
│   └── local/         # Analyst-created rules
├── compiled/          # Compiled .yarac files
├── feeds/             # Feed configurations
├── test_cases/        # Positive/negative test samples
├── metadata.sqlite    # Rule metadata DB
└── performance.sqlite # Performance tracking DB
```

### CAPEv2 Sandbox

Configure in `.env`:
```bash
SANDBOX_ENABLED=true
SANDBOX_API_URL=http://cape-controller.internal:8000
SANDBOX_API_TOKEN=your_api_token_if_required
SANDBOX_PROFILES={"windows": "win10-x64-clean", "linux": "ubuntu22-x64-clean", "android": "android13-x86-clean"}
```

**Network Isolation (MANDATORY):**
- Use INetSim or FakeNet-NG
- No direct internet egress from analysis VMs
- Dedicated isolated network segment

---

## 🔌 API Reference

### Base URL
```
https://malinfo.yourdomain.gov/api
```

### Authentication

```bash
# Login
curl -X POST https://malinfo.example.gov/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "analyst", "password": "secret", "mfa_code": "123456"}'

# Response
{
  "access_token": "eyJ...",
  "refresh_token": "eyJ...",
  "token_type": "bearer",
  "expires_in": 28800
}

# Use token
curl -H "Authorization: Bearer eyJ..." https://malinfo.example.gov/api/reports
```

### Core Endpoints

| Category | Endpoint | Method | Description |
|----------|----------|--------|-------------|
| **Auth** | `/auth/login` | POST | Login with MFA |
| | `/auth/refresh` | POST | Refresh access token |
| | `/auth/me` | GET | Current user profile |
| | `/auth/mfa/setup` | POST | Setup MFA (QR code) |
| **Samples** | `/upload` | POST | Upload file for analysis |
| | `/reports` | GET | List samples (paginated) |
| | `/reports/{id}` | GET | Get sample details |
| | `/reports/{id}/html` | GET | View HTML report |
| | `/reports/{id}/download` | GET | Download JSON report |
| **Sandbox** | `/sandbox/profiles` | GET | Available VM profiles |
| | `/sandbox/detonate` | POST | Submit to sandbox |
| | `/sandbox/status/{id}` | GET | Task status |
| | `/sandbox/report/{id}` | GET | Sandbox report |
| **Monitoring** | `/monitoring/status` | GET | Service status |
| | `/monitoring/transfers` | GET | File transfer events |
| | `/monitoring/network/flows` | GET | Network flows |
| | `/monitoring/stats` | GET | Statistics |
| **Threat Intel** | `/threat-intel/providers` | GET | Configured providers |
| | `/threat-intel/lookup/hash/{hash}` | POST | Hash reputation |
| | `/threat-intel/lookup/ip/{ip}` | POST | IP reputation |
| | `/threat-intel/enrich/sample/{id}` | POST | Enrich sample |
| **YARA** | `/yara/rulesets` | GET | List rulesets |
| | `/yara/rulesets` | POST | Create ruleset |
| | `/yara/rulesets/{id}/compile` | POST | Compile ruleset |
| | `/yara/feeds/sync` | POST | Sync feeds |
| **Decompiler** | `/decompiler/analyze` | POST | Start decompilation |
| | `/decompiler/tasks/{id}` | GET | Task status |
| | `/decompiler/tasks/{id}/functions` | GET | Decompiled functions |
| **Public** | `/public/report` | POST | Citizen report submission |
| **Health** | `/health` | GET | System health |
| **Metrics** | `/metrics` | GET | Prometheus metrics |

### Rate Limits

| Endpoint | Limit | Window |
|----------|-------|--------|
| General API | 100 req/s | 1s |
| Public Report | 5 req/m | 1m |
| File Upload | 10 req/m | 1m |
| Login | 5 req/m | 1m |

---

## 📊 Reporting

### Report Types

| Type | Format | Description |
|------|--------|-------------|
| **Executive Summary** | HTML, PDF | 1-2 pages, verdict, risk score, key IOCs, recommendations |
| **Technical Deep-Dive** | HTML, PDF, JSON | Full static/dynamic/network analysis, evidence |
| **MITRE ATT&CK Matrix** | HTML, JSON | Technique heatmap, tactic summary |
| **Kill Chain Timeline** | HTML, JSON | Lockheed Martin / ATT&CK phases |
| **IOC Package** | STIX 2.1, MISP, CSV | Structured indicators with metadata |

### Export Formats

```bash
# Via API
curl -H "Authorization: Bearer $TOKEN" \
  "https://malinfo.example.gov/api/reports/{id}/download?format=pdf"

# Supported: html, pdf, json, stix, misp, csv
```

### Report Templates

Customizable Jinja2 templates in `backend/app/reporting/templates/`:
- `executive_summary.html` — Executive summary
- `technical_deep_dive.html` — Full technical report
- `report_style.css` — Shared styling

---

## 🛡 Security Hardening

### Network
- TLS 1.2/1.3 only (TLS 1.0/1.1 disabled)
- HSTS with preload
- CSP, X-Frame-Options, X-Content-Type-Options
- Rate limiting on all endpoints
- ICAP gateway only on authorized infrastructure

### Application
- JWT HS256 with 8hr access / 30d refresh tokens
- bcrypt (cost=12) for password hashing
- TOTP MFA with QR code setup
- RBAC with 5 roles, 20+ granular permissions
- Comprehensive audit logging (tamper-evident)
- API keys with scoped permissions
- Session management with revocation

### Infrastructure (systemd)
```ini
# Example hardening directives
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
```

### Supply Chain
- SBOM generation (CycloneDX) via `make sbom`
- Dependency scanning (Safety, Trivy) via `make security`
- Container signing ready (cosign)
- SLSA Level 3 build pipeline ready

---

## 📈 Monitoring & Observability

### Prometheus Metrics

Key metrics exposed at `/metrics`:

| Metric | Type | Description |
|--------|------|-------------|
| `http_requests_total` | Counter | HTTP requests by method/handler/status |
| `http_request_duration_seconds` | Histogram | Request latency |
| `malinfo_analysis_queue_depth` | Gauge | Static analysis queue |
| `malinfo_analysis_completed_total` | Counter | Completed analyses by verdict |
| `malinfo_sandbox_malscore` | Histogram | Sandbox malScore distribution |
| `malinfo_yara_matches_total` | Counter | YARA rule matches |
| `malinfo_transfer_alerts_total` | Counter | File transfer alerts |

### Grafana Dashboards

Pre-provisioned dashboards:
- **System Overview** — Service health, API rates, resources
- **Analysis Pipeline** — Queue depth, duration, verdicts, MITRE techniques

### Alerting Rules

Critical alerts in `deploy/prometheus/alerts.yml`:
- Service down (backend, nginx, db, redis)
- High error rate (>5%)
- High latency (p95 > 5s)
- Analysis queue backlog
- Sandbox unavailable
- Disk space < 15%
- TLS certificate expiry

---

## 🔧 Operations

### Common Commands

```bash
# Health check
make health

# View logs
make logs SERVICE=backend

# Service status
make status

# Scale backend
docker compose -f docker-compose.prod.yml up -d --scale backend=6

# Backup
make backup

# Restore
make restore BACKUP_FILE=/opt/malinfo/backups/malinfo_backup_20240115_020000.tar.gz

# Update YARA rules
make update-yara

# Update threat intel feeds
make update-feeds

# Generate SBOM
make sbom

# Security scan
make security

# Run tests
make test
```

### Backup Strategy

Automated daily backup at 2 AM via cron:
```bash
0 2 * * * /opt/malinfo/scripts/backup.sh >> /var/log/malinfo/backup.log 2>&1
```

**Backup includes:**
- PostgreSQL database (pg_dump)
- Redis RDB snapshot
- Storage volumes (uploads, reports, pcaps)
- Configuration files

### Disaster Recovery

```bash
# Full recovery
make restore BACKUP_FILE=/opt/malinfo/backups/malinfo_backup_20240115_020000.tar.gz

# Database only
gunzip -c backups/db_20240115_020000.sql.gz | docker compose exec -T db psql -U malinfo malinfo
```

---

## 🧪 Testing

### Unit Tests

```bash
cd backend
python -m pytest tests/ -v --tb=short
```

### Standalone Smoke Test (No Dependencies)

```bash
cd backend
python tests/test_analysis_standalone.py
# 24/24 checks passed
```

### Security Testing

```bash
# Bandit static analysis
make security

# Dependency audit
make security

# Container scan
trivy image malinfo/backend:latest
```

---

## 📚 Documentation

| Document | Location |
|----------|----------|
| **API Reference** | This README (above) |
| **Deployment Guide** | `docs/DEPLOYMENT.md` |
| **Operations Runbooks** | `docs/RUNBOOKS.md` |
| **Analyst Guide** | `docs/ANALYST_GUIDE.md` |
| **Admin Guide** | `docs/ADMIN_GUIDE.md` |
| **Architecture** | `SPEC.md` |

---

## 🤝 Contributing

### Development Setup

```bash
make dev
# Starts development stack with hot reload
```

### Code Standards

- **Type Hints**: 100% coverage (mypy strict)
- **Documentation**: Google-style docstrings
- **Testing**: pytest, >90% coverage
- **Security**: Bandit, semgrep, dependabot
- **Linting**: ruff

### Git Workflow

1. Fork repository
2. Create feature branch
3. Write tests
4. Ensure all checks pass
5. Submit PR

---

## 📄 License

Government use authorized. See [LICENSE](LICENSE) for details.

---

## 📞 Support

| Channel | Contact |
|---------|---------|
| **Security Issues** | security@malinfo.example.gov |
| **Platform Support** | platform@malinfo.example.gov |
| **Documentation** | docs@malinfo.example.gov |

---

## 🗺 Roadmap

See [SPEC.md](SPEC.md) for detailed enhancement specification targeting government/enterprise-grade delivery:

- **Phase 1** (Weeks 1-4): Core Analysis Depth
- **Phase 2** (Weeks 5-8): Intelligence & Detection
- **Phase 3** (Weeks 9-12): Threat Intel & Reporting
- **Phase 4** (Weeks 13-16): Platform Hardening
- **Phase 5** (Weeks 17-20): Testing & Delivery

---

## 🏷 Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0-pilot | 2026-08-02 | Initial production pilot release |

---

**MALINFO v1.0.0-pilot** — Built for national cyber defense 🛡️