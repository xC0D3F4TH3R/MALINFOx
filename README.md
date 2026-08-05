# MALINFO — National Malware Analysis & Threat Intelligence Platform

[![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)](https://github.com/your-org/malinfo)
[![License](https://img.shields.io/badge/license-Government%20Use%20Authorized-green.svg)](LICENSE)
[![Build](https://img.shields.io/badge/build-passing-brightgreen.svg)]()
[![Security](https://img.shields.io/badge/security-hardened-critical.svg)]()
[![Deployment](https://img.shields.io/badge/deployment-Docker%20%7C%20K8s%20%7C%20systemd-orange.svg)]()

> **Government-grade malware analysis platform** with **built-in dynamic sandbox**, static analysis, network forensics, real-time monitoring, and public threat reporting — designed for CERTs, SOCs, and national cyber defense operations.

---

## 🎯 Overview

MALINFO v2.0.0 is a comprehensive, production-ready malware analysis platform built for government and enterprise environments. It provides **end-to-end analysis capabilities** from file ingestion through deep static/dynamic analysis to actionable intelligence reporting — **without requiring external infrastructure** for dynamic analysis.

### Key Capabilities

| Domain | Capabilities |
|--------|--------------|
| **Static Analysis** | PE/ELF/Mach-O/APK/OLE/Script deep analysis, YARA scanning, IOC extraction, entropy analysis, risk scoring |
| **Dynamic Analysis** | **Built-in VM orchestrator** with libvirt/QEMU, ISO upload & VM templates, real-time behavioral monitoring via guest agent, API monitoring, process tree, network forensics, MITRE ATT&CK mapping |
| **Network Forensics** | PCAP parsing, JA3/JA3S TLS fingerprinting, DGA detection, C2 protocol parsing, beaconing analysis |
| **Threat Intelligence** | STIX/TAXII 2.1 server, MISP sync, actor/campaign profiling, ATT&CK Navigator, feed management |
| **Real-Time Monitoring** | ICAP gateway (REQMOD/RESPMOD), filesystem monitoring, network flow analysis, auto-analysis pipeline |
| **Authentication** | JWT + MFA, RBAC (5 roles, 20+ permissions), audit logging, API keys, session management |
| **Reporting** | Executive summary, technical deep-dive, MITRE matrix, kill chain, IOC packages (STIX/MISP/CSV/PDF) |

---

## 🏗 Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              MALINFO Platform                               │
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
│  │   Backend   │      │   Backend   │      │  Backend    │             │
│  │   (API)     │      │   (ICAP)    │      │ (Monitor)   │             │
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
│  │   Static    │      │    Built-in │      │   Network   │             │
│  │  Analysis   │      │   VM Sandbox│      │  Forensics  │             │
│  └─────────────┘      │  (libvirt)  │      └─────────────┘             │
│                       └─────────────┘                                    │
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
| **Dynamic Sandbox** | **libvirt/QEMU (built-in)**, Guest Agent (real-time monitoring) |
| **Monitoring** | Prometheus, Grafana, OpenTelemetry-ready |
| **Deployment** | Docker Compose, Kubernetes (Helm-ready), systemd |
| **Security** | JWT HS256, bcrypt, pyotp, TLS 1.2/1.3, CSP, HSTS |

---

## 🚀 Quick Start

### Prerequisites

- Docker 24+ and Docker Compose 2+
- 16GB+ RAM, 4+ CPU cores (for VM sandbox)
- 200GB+ disk space
- **Linux host with KVM support** (for VM sandbox)
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
#   - VM_ORCHESTRATOR_ENABLED=true
#   - LIBVIRT_URI=qemu:///system
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
# Full production stack with all profiles (includes VM sandbox)
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
- **VM Management**: `https://malinfo.yourdomain.gov/#/vm`
- **Metrics**: `https://malinfo.yourdomain.gov:9090` (Prometheus)
- **Grafana**: `https://malinfo.yourdomain.gov:3000` (admin / GRAFANA_PASSWORD)

---

## 🖥 VM Sandbox — Self-Contained Dynamic Analysis

### Key Innovation: No External CAPEv2 Required

MALINFO v2.0.0 includes a **built-in VM orchestrator** using libvirt/QEMU:

1. **Admin uploads ISO** (Windows 10/11, Ubuntu 22.04/24.04, Android 13/14, macOS on Apple Silicon)
2. **Create VM templates** via web UI — auto-installs OS, guest agent, creates clean snapshot
3. **Analyst submits sample** — selects template, configures timeout/options
4. **Real-time monitoring** — WebSocket updates show: process tree, API calls, network, files, registry
5. **Complete analysis** — MITRE ATT&CK mapping, MalScore, screenshots, PCAP, dropped files

### VM Sandbox Architecture

```
┌────────────────────────────────────────────────────────────────────┐
│                    MALINFO VM Orchestrator                         │
├────────────────────────────────────────────────────────────────────┤
│                                                                    │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐           │
│  │   ISO       │───▶│  Template   │───▶│  Instance   │           │
│  │  Upload     │    │  Builder    │    │  (COW disk) │           │
│  └─────────────┘    └─────────────┘    └──────┬──────┘           │
│                                                │                  │
│  ┌────────────────────────────────────────────▼────────────────┐  │
│  │                    Guest Agent (virtio-serial)               │  │
│  │  • Process monitoring    • API call interception             │  │
│  │  • File system events    • Registry monitoring (Windows)     │  │
│  │  • Network connections   • Screenshot capture                │  │
│  │  • Sample execution      • Memory dump trigger               │  │
│  └─────────────────────────────────────────────────────────────┘  │
│                                                │                  │
│  ┌────────────────────────────────────────────▼────────────────┐  │
│  │                    Real-time WebSocket Updates               │  │
│  │  Dashboard shows: live process tree, API calls, network,    │  │
│  │  file/registry events, screenshots, MalScore progression    │  │
│  └─────────────────────────────────────────────────────────────┘  │
│                                                                    │
└────────────────────────────────────────────────────────────────────┘
```

### Admin: Creating VM Templates

1. **Navigate to VM Management → ISOs** → Upload ISO (Windows/Linux/Android/macOS)
2. **Navigate to VM Management → Templates** → Create Template
   - Name: `Windows 10 x64 Clean`
   - Base ISO: Select uploaded ISO
   - Resources: 4GB RAM, 2 vCPUs, 60GB disk
   - Network: Isolated (no internet) / Routed / NAT
3. **Template builds automatically** — installs OS, guest agent, creates clean snapshot

### Analyst: Dynamic Analysis Workflow

1. **Navigate to VM Management → Submit Analysis**
2. **Select sample** (upload new or choose from library)
3. **Select VM template** (auto-detected or manual)
4. **Configure options**: Screenshots, Memory, Network, API Monitoring
5. **Submit** → Real-time updates via WebSocket
6. **View results**: Process tree, MITRE techniques, signatures, PCAP, screenshots, HTML/JSON reports

---

## 📦 Deployment Options

### Docker Compose (Recommended)

```bash
# Development
make dev

# Staging
make staging

# Production (includes VM sandbox, monitoring, ICAP)
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
sudo mkdir -p /opt/malinfo/{backend,storage/{uploads,reports,pcaps,vms,isos},logs}
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
curl -H "Authorization: Bearer ***" https://malinfo.example.gov/api/reports
```

### Core Endpoints

| Category | Endpoint | Method | Description |
|----------|----------|--------|-------------|
| **Auth** | `/auth/login` | POST | Login with MFA |
| | `/auth/refresh` | POST | Refresh access token |
| | `/auth/me` | GET | Current user profile |
| **Samples** | `/upload` | POST | Upload file for analysis |
| | `/reports` | GET | List samples (paginated) |
| | `/reports/{id}` | GET | Get sample details |
| | `/reports/{id}/html` | GET | View HTML report |
| **VM Sandbox** | `/vm/isos` | GET/POST/DELETE | ISO management |
| | `/vm/templates` | GET/POST/DELETE | VM template management |
| | `/vm/templates/{id}/rebuild` | POST | Rebuild template |
| | `/vm/analyze` | POST | Submit sample for dynamic analysis |
| | `/vm/tasks` | GET | List analysis tasks |
| | `/vm/tasks/{id}` | GET | Get task details |
| | `/vm/tasks/{id}/status` | GET | Get task status |
| | `/vm/tasks/{id}/cancel` | POST | Cancel running task |
| | `/vm/tasks/{id}/report` | GET | Download report (json/html) |
| | `/vm/tasks/{id}/pcap` | GET | Download PCAP |
| | `/vm/tasks/{id}/screenshots` | GET | Get screenshots |
| | `/vm/ws/{task_id}` | WS | Real-time updates |
| **Monitoring** | `/monitoring/status` | GET | Service status |
| | `/monitoring/transfers` | GET | File transfer events |
| | `/monitoring/network/flows` | GET | Network flows |
| **Threat Intel** | `/threat-intel/lookup/hash/{hash}` | POST | Hash reputation |
| | `/threat-intel/lookup/ip/{ip}` | POST | IP reputation |
| | `/threat-intel/enrich/sample/{id}` | POST | Enrich sample |

### Rate Limits

| Endpoint | Limit | Window |
|----------|-------|--------|
| General API | 100 req/s | 1s |
| Public Report | 5 req/m | 1m |
| File Upload | 10 req/m | 1m |
| Login | 5 req/m | 1m |

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
# View logs
make logs SERVICE=backend

# Check status
make status

# Health check
make health

# Backup (database + storage + configs)
make backup

# Restore from backup
make restore BACKUP_FILE=/opt/malinfo/backups/malinfo_backup_20240101_120000.tar.gz

# Update YARA rules
make update-yara

# Update threat intel feeds
make update-feeds

# Generate reports for all samples
make generate-reports
```

### VM Sandbox Operations

```bash
# List VM templates
curl -H "Authorization: Bearer $TOKEN" https://malinfo.example.gov/api/vm/templates

# Rebuild a template
curl -X POST -H "Authorization: Bearer $TOKEN" \
  https://malinfo.example.gov/api/vm/templates/{template_id}/rebuild

# Cancel running analysis
curl -X POST -H "Authorization: Bearer $TOKEN" \
  https://malinfo.example.gov/api/vm/tasks/{task_id}/cancel
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
| `VM_ORCHESTRATOR_ENABLED` | Enable built-in VM sandbox | `true` |
| `LIBVIRT_URI` | libvirt connection URI | VM sandbox enabled |
| `ICAP_ENABLED` | Enable ICAP gateway | `true` |
| `MONITOR_ENABLED` | Enable file monitoring | `true` |
| `MONITOR_WATCH_PATHS` | Paths to watch (JSON array) | Monitor enabled |

---

## 📋 Acceptance Criteria (Government Delivery)

### Functional
- [ ] Analyze 1000 samples/day on 8-core/32GB reference hardware
- [ ] Static analysis < 30s for typical PE (1-10MB)
- [ ] Dynamic analysis < 5 min typical, < 15 max
- [ ] YARA scanning < 5s for 50K rules on 10MB file
- [ ] Network PCAP analysis < 60s for 100MB capture
- [ ] Report generation < 10s for technical deep-dive
- [ ] 99.9% API availability (HA mode)
- [ ] Zero data leakage between organizations (multi-tenancy)

### Security
- [ ] Penetration test: 0 critical, 0 high findings
- [ ] Dependency scan: 0 critical/High CVEs in production images
- [ ] SBOM generated for all components
- [ ] Images signed and verified (cosign)
- [ ] FIPS 140-2 mode operational
- [ ] Audit log: tamper-evident, immutable storage option
- [ ] Air-gap update verified on isolated network

### Operational
- [ ] Deployment documented for: Kubernetes, Docker Compose, bare-metal, air-gap
- [ ] Runbook for: backup/restore, failover, scaling, update, incident response
- [ ] Monitoring dashboards: system, business, security
- [ ] Alerting rules: critical paths, SLAs, anomalies
- [ ] Capacity planning guide

### Usability
- [ ] Analyst completes "triage new sample" workflow in < 5 min
- [ ] Report customization without code changes
- [ ] YARA rule creation/test/deploy in < 2 min
- [ ] Threat intel feed add/sync in < 1 min
- [ ] Case management: create, assign, track, report

---

## 📄 License

Government Use Authorized — See LICENSE file for details.

---

## 🤝 Contributing

This is a government/internal project. For contributions or issues, contact the development team.

---

## 📞 Support

- **Documentation**: https://malinfo.example.gov/docs
- **API Reference**: https://malinfo.example.gov/docs/api
- **Issues**: Internal tracking system
- **Security**: security@example.gov