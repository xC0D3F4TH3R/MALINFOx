# MALINFO — National Malware Analysis & Threat Intelligence Platform

**Version:** 1.0.0-pilot  
**Classification:** Government / Enterprise Deployment  
**Status:** Production Pilot — Ready for Operational Use  

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Problem Statement](#2-problem-statement)
3. [What Problems MALINFO Solves](#3-what-problems-malinfo-solves)
4. [Architecture Overview](#4-architecture-overview)
5. [Technology Stack](#5-technology-stack)
6. [Core Capabilities](#6-core-capabilities)
7. [Installation & Deployment](#7-installation--deployment)
8. [Configuration](#8-configuration)
9. [Working with MALINFO](#9-working-with-malinfo)
10. [API Reference](#10-api-reference)
11. [Demo Scenarios](#11-demo-scenarios)
12. [Desired vs Actual Output](#12-desired-vs-actual-output)
13. [Reporting & Output Formats](#13-reporting--output-formats)
14. [Security Hardening](#14-security-hardening)
15. [Operations & Maintenance](#15-operations--maintenance)
16. [Troubleshooting](#16-troubleshooting)
17. [Roadmap & Future Enhancements](#17-roadmap--future-enhancements)
18. [Support & Contact](#18-support--contact)
19. [License](#19-license)

---

## 1. Executive Summary

MALINFO is a **government-grade malware analysis platform** designed for CERTs, SOCs, and national cyber defense operations. It provides end-to-end analysis capabilities from file ingestion through deep static/dynamic analysis to actionable intelligence reporting — all in a single, self-hosted platform that meets government security and compliance requirements.

### Key Differentiators

| Feature | Commercial Alternatives | MALINFO |
|---------|------------------------|---------|
| **Deployment** | Cloud-only (data leaves your network) | Fully self-hosted, air-gap capable |
| **Data Sovereignty** | Vendor controls your samples | You own 100% of data & infrastructure |
| **Cost** | $50K–$500K/year licensing | Open platform, no licensing fees |
| **Customization** | Limited APIs, no source access | Full source code, plugin architecture |
| **Compliance** | Vendor-dependent | FIPS 140-2, SLSA L3, supply chain verified |
| **Integration** | Proprietary formats | STIX/TAXII, MISP, OpenIOC, CSV, JSON, PDF |

### Target Users

- **National CERTs** — Sovereign malware analysis capability
- **Government SOCs** — 24/7 threat detection & response
- **Defense Contractors** — DFARS/NIST 800-171 compliant analysis
- **Critical Infrastructure** — OT/IT convergence threat hunting
- **Law Enforcement** — Digital forensics & evidence preservation

---

## 2. Problem Statement

### 2.1 The Core Problem

**Government and critical infrastructure organizations lack a sovereign, self-hosted malware analysis platform that meets their security, compliance, and operational requirements.**

Current market solutions present fundamental conflicts:

1. **Cloud Dependency** — Major platforms (VirusTotal, Hybrid Analysis, Joe Sandbox, Any.Run) require uploading samples to external clouds, violating data sovereignty, classification handling, and air-gap requirements.

2. **Vendor Lock-in** — Proprietary formats, closed APIs, and per-sample licensing prevent integration with existing SIEM/SOAR workflows and threat intelligence platforms (MISP, OpenCTI, STIX/TAXII).

3. **Cost Prohibitive** — Enterprise licenses range from $50K–$500K/year with volume limits, making sustainable operations impossible for many agencies.

4. **Insufficient Depth** — Most platforms provide only surface-level analysis (basic static + sandbox behavioral). They lack deep binary intelligence: rich PE headers, Authenticode validation, Mach-O entitlements, APK certificate chains, ELF hardening audits, crypto constant detection, obfuscation identification, and MITRE ATT&CK mapping.

5. **No Operational Integration** — Missing real-time monitoring (ICAP gateway, filesystem watchers), threat intel enrichment pipelines, case management, analyst collaboration tools, and professional reporting (executive summaries, MITRE matrices, kill chains, STIX/MISP packages).

6. **Security Gaps** — Cloud platforms lack government-grade hardening: FIPS crypto, audit logging, RBAC with granular permissions, MFA, supply chain verification (SBOM/SLSA), and air-gap update mechanisms.

### 2.2 Operational Pain Points

| Pain Point | Current Reality | MALINFO Solution |
|------------|-----------------|------------------|
| Sample submission | Manual web upload, email, API | REST API, ICAP gateway, filesystem monitor, drag-drop UI |
| Analysis turnaround | Hours to days (queue dependent) | <30s static, <5min dynamic (local sandbox) |
| Report generation | Manual copy-paste, screenshots | Automated multi-format (HTML, PDF, STIX, MISP, CSV) |
| Threat correlation | Manual lookup in multiple portals | Automated enrichment (VT, OTX, AbuseIPDB, MISP) |
| IOC sharing | CSV/email, format inconsistency | STIX 2.1, MISP, TAXII 2.1 server |
| Case tracking | Spreadsheets, tickets | Built-in case management, evidence linking |
| Air-gap operations | Impossible with cloud tools | Signed offline update bundles, feed import/export |

---

## 3. What Problems MALINFO Solves

### 3.1 Sovereign Analysis Capability
- **Zero external dependencies** for core static analysis — runs entirely on your infrastructure
- **Air-gap deployment** — Full functionality without internet access via signed update bundles
- **Data never leaves your network** — Samples, reports, IOCs stay within your security boundary

### 3.2 Deep Binary Intelligence
- **PE Analysis**: Rich headers, Authenticode chain validation, TLS callbacks, COM registration, delay-load, CLR metadata, resource analysis, debug data (PDB), overlay extraction, ImpHash
- **ELF Analysis**: Hardening flags (RELRO, BIND_NOW), RPATH/RUNPATH audit, version definitions, build ID, ABI tag, Go/Rust binary introspection
- **Mach-O Analysis**: Code signature validation, entitlements, dyld info (rebasing, binding, exports), universal binary slices, hardened runtime flags, notarization
- **APK Analysis**: Certificate chain (v1–v4), network security config, manifest hardening, embedded SO/DEX extraction, native library recursion
- **Office/PDF/Script**: OLE/VBA/XLM macro extraction, OOXML analysis, PDF JavaScript/actions, PowerShell AST obfuscation detection, batch/JS/VBS/Python/shell obfuscation

### 3.3 Dynamic Analysis Integration
- **CAPEv2 orchestration** — Multi-OS (Windows/Linux/Android), snapshot/revert, memory forensics (Volatility3), API monitoring, process trees, MITRE mapping
- **Network forensics** — PCAP analysis with JA3/JA3S, TLS cert extraction, DGA classification (ML), C2 protocol parsers, beaconing statistics, encrypted traffic analysis
- **Automatic correlation** — Static IOCs matched against dynamic behavior, dropped files recursively analyzed

### 3.4 Threat Intelligence Platform
- **Multi-provider enrichment** — VirusTotal, OTX, AbuseIPDB, MISP, custom feeds
- **STIX/TAXII 2.1 server** — Publish/consume indicators, malware, campaigns, actors
- **MISP bidirectional sync** — Push/pull with conflict resolution
- **Actor/Campaign profiling** — TTP heatmaps, infrastructure tracking, attribution confidence
- **ATT&CK Navigator integration** — Layer generation for samples, actors, campaigns

### 3.5 Professional Reporting
| Report Type | Audience | Formats | Key Content |
|-------------|----------|---------|-------------|
| Executive Summary | Leadership, Legal | HTML, PDF | Verdict, risk score, business impact, key IOCs, 5 recommendations |
| Technical Deep-Dive | Analysts, IR Teams | HTML, PDF, JSON | Full static/dynamic/network evidence, methodology, MITRE matrix |
| MITRE ATT&CK Matrix | Detection Engineers | HTML, JSON | Technique heatmap, tactic summary, detection/mitigation gaps |
| Kill Chain Timeline | Threat Hunters | HTML, JSON | Lockheed Martin + ATT&CK phases, timestamps, artifacts |
| IOC Package | SOC, SIEM, Partners | STIX 2.1, MISP, CSV | Structured indicators with confidence, context, tags, sightings |

### 3.6 Operational Platform Features
- **Multi-tenancy** — Organizations, cases, controlled sharing
- **RBAC + MFA** — 5 roles, 20+ permissions, TOTP, audit logging
- **Real-time monitoring** — ICAP gateway (REQMOD/RESPMOD), filesystem watchers, network flow analysis
- **YARA rule management** — Feeds (MalwareBazaar, YARA-Rules), compilation caching, performance metrics, test harness
- **Decompiler integration** — Ghidra headless API, retdec fallback, FLIRT signatures, function export
- **Observability** — Prometheus metrics, Grafana dashboards, OpenTelemetry tracing, Alertmanager

---

## 4. Architecture Overview

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

### Service Components

| Component | Technology | Purpose |
|-----------|------------|---------|
| **API Backend** | FastAPI + Uvicorn | REST API, WebSocket, async task orchestration |
| **Frontend** | Vanilla ES Modules + CSS Custom Properties | Analyst console, real-time updates |
| **Database** | PostgreSQL 16 (async) + Redis 7 | Persistent storage, caching, sessions, queues |
| **Static Analysis** | pefile, pyelftools, macholib, androguard, yara-python, scapy | Deep binary inspection |
| **Sandbox** | CAPEv2 REST API + Volatility3 | Dynamic detonation, memory forensics |
| **Network Forensics** | scapy, custom ML (DGA), JA3/JA3S | PCAP analysis, C2 detection |
| **Threat Intel** | aiohttp, STIX/TAXII, MISP client | Enrichment, feed management |
| **Reporting** | Jinja2 + WeasyPrint | Multi-format professional reports |
| **Monitoring** | Prometheus, Grafana, OpenTelemetry | Observability, alerting |
| **Deployment** | Docker Compose, Kubernetes (Helm), systemd | Flexible infrastructure |

---

## 5. Technology Stack

### Backend
| Layer | Technologies | Version |
|-------|--------------|---------|
| **Web Framework** | FastAPI, Uvicorn, Pydantic, Starlette | 0.115.x, 0.30.x, 2.9.x |
| **Database** | SQLAlchemy 2.0, AsyncPG, aiosqlite (dev) | 2.0.x, 0.31.x |
| **Async/Concurrency** | asyncio, tenacity, anyio | stdlib, 9.0.x |
| **Static Analysis** | pefile, pyelftools, macholib, androguard, yara-python, ssdeep, python-magic | Latest |
| **Network** | scapy, dnspython | 2.6.x, 2.6.x |
| **Threat Intel** | aiohttp, requests, stix2, pymisp | 3.9.x, 2.32.x |
| **Reporting** | Jinja2, WeasyPrint, reportlab | 3.1.x, 62.x |
| **Auth/Security** | python-jose, passlib[bcrypt], pyotp, qrcode, email-validator | 3.3.x, 1.7.x, 2.9.x |
| **Monitoring** | watchdog, psutil, prometheus-client | 4.0.x, 5.9.x, 0.19.x |
| **Observability** | structlog, OpenTelemetry (optional) | Latest |

### Frontend
| Technology | Purpose |
|------------|---------|
| **Vanilla ES Modules** | Zero-build, framework-free, browser-native |
| **CSS Custom Properties** | Theming, dark/light mode, responsive design |
| **WebSocket** | Real-time analysis progress, alerts, sandbox updates |
| **Fetch API** | REST communication with JWT auth |
| **Chart.js (optional)** | Visualization in dashboards |

### Infrastructure
| Component | Technologies |
|-----------|--------------|
| **Containerization** | Docker, Docker Compose, Kubernetes (Helm-ready) |
| **Reverse Proxy** | NGINX (TLS termination, rate limiting, caching) |
| **Database** | PostgreSQL 16 (streaming replication for HA) |
| **Cache/Queue** | Redis 7 (Sentinel for HA) |
| **Metrics** | Prometheus 2.53, Grafana 11, Node/Postgres/Redis exporters |
| **Logging** | Structured JSON, Loki (optional), logrotate |
| **CI/CD** | GitHub Actions / GitLab CI, SLSA L3, cosign signing |
| **Secrets** | HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, or .env |

---

## 6. Core Capabilities

### 6.1 Static Analysis Engine

**File Identification & Hashing**
- SHA256, SHA1, MD5, SSDEEP (fuzzy hashing)
- MIME type detection via libmagic
- Target OS inference (Windows/Linux/macOS/Android/Unknown)

**Entropy & String Analysis**
- Shannon entropy per file/section (0.0–8.0 scale)
- High-entropy region detection (packed/encrypted sections)
- ASCII/Unicode string extraction with configurable minimum length
- String sampling for large files (first 300 strings in report)

**YARA Scanning**
- Compiled ruleset caching for performance
- Multi-ruleset support (official, feeds, local)
- Match metadata: rule name, namespace, tags, severity, MITRE
- Performance tracking per rule (match time, hit rate, false positives)

**Format-Specific Deep Analysis**

| Format | Capabilities |
|--------|-------------|
| **PE (Windows)** | DOS/NT headers, sections, imports/exports, resources, Authenticode, TLS callbacks, COM, delay-load, bound imports, CLR metadata, debug data (PDB), overlay extraction, ImpHash, section permissions audit |
| **ELF (Linux)** | Headers, sections, segments, dynamic symbols, DT_NEEDED/RPATH/RUNPATH, version definitions, build ID, ABI tag, hardening flags, interpreter, init/fini arrays, Go/Rust introspection |
| **Mach-O (macOS)** | Load commands, code signature validation, entitlements, dyld info (rebasing, binding, exports), universal binary slices, hardened runtime, notarization |
| **APK (Android)** | Manifest (permissions, components, hardening), certificate chain (v1–v4), network security config, embedded DEX/SO/JAR extraction, native library recursion |
| **OLE/Office** | CFB streams, VBA macro extraction (olevba), XLM/Excel 4.0 macros, external relationships, embedded OLE packages |
| **OOXML (docx/xlsx/pptx)** | Content types, relationships, VBA project, printer settings (CVE-2021-34527) |
| **RTF** | Object parsing, embedded OLE, hex-encoded payloads |
| **PDF** | JavaScript actions, /Launch/URI/SubmitForm, embedded files, XFA forms, JBIG2/JPXDecode |
| **Scripts (PS1/BAT/JS/VBS/PY/SH)** | AST parsing, obfuscation detection, download cradles, AMSI bypass, encoded commands, eval/Function constructor, ActiveX/WScript.Shell |

**IOC Extraction**
- Regex-based: IPv4/IPv6, domains, URLs, emails, registry keys, mutexes, file paths, Bitcoin addresses, SHA256 hashes
- Context extraction (surrounding bytes/strings)
- Private IP filtering (RFC 1918, loopback, link-local)
- C2 candidate flagging (gate.php, beacon intervals, panel references)
- Passive DNS from SSL certs (SAN), HTTP Host headers, DNS queries
- SSL certificate parsing (Subject/Issuer DN, SANs, validity, fingerprints, chain)

**Crypto Detection**
- Symmetric: AES (S-box, T-tables, round constants), DES/3DES, RC4 (KSA/PRGA), ChaCha20/Salsa20, Rabbit, Blowfish, Twofish, Camellia, SM4
- Asymmetric: RSA (modulus, exponent), ECC (curve params: secp256r1, secp384r1, secp256k1, Curve25519), DH groups
- Hash: MD5, SHA1/256/512 IVs, SHA3/Keccak, BLAKE2/3 constants
- Custom: XOR loops, rolling XOR, TEA/XTEA/XXTEA, RC4 variants
- Key extraction: hardcoded keys in .data/.rdata, stack strings, config resources, static seeds

**Obfuscation Detection**
- Control flow: opaque predicates, flattened CFG, overlapping instructions, junk code
- VM packers: VMProtect, Themida, Enigma, CodeVirtualizer, custom VMs
- String encryption: per-string keys, runtime decryption stubs, stack/heap strings
- API hashing: DJB2, FNV, CRC32, custom rotate-XOR, resolution stubs
- Import obfuscation: delay load, manual GetProcAddress/LoadLibrary, syscall direct (Hell's Gate)
- Anti-analysis: timing checks, CPUID, hardware breakpoints, NtGlobalFlag, BeingDebugged, VM artifacts, sandbox evasion

**Risk Scoring**
- Multi-factor: YARA severity, entropy, suspicious APIs, packer indicators, overlay data, Authenticode status, C2 IOCs, crypto constants, obfuscation markers
- Dynamic merge: sandbox malScore, network beaconing, C2 correlation
- Verdicts: clean (0–19), suspicious (20–59), malicious (60–100)
- Explainable: human-readable reasons for each score component
- ML-assisted (planned): trainable per organization, calibration against labeled datasets

### 6.2 Dynamic Analysis (Sandbox)

**CAPEv2 Integration**
- Task submission with profile selection (OS, architecture, network mode)
- Polling with configurable interval/timeout
- Report retrieval: signatures, dropped files, network summary, screenshots
- PCAP download for network forensics
- Memory dump acquisition (full/process)

**Volatility3 Memory Forensics**
- Process listing (pslist, pstree)
- DLL/module enumeration (dlllist)
- Handle analysis (handles)
- Code injection detection (malfind, hollowfind)
- Command line recovery (cmdline)
- Service/driver analysis (svcscan, driverirp)
- ETW tampering detection (etwtamper)
- Module anomalies (ldrmodules)
- API hooking (apihooks)
- SSDT inspection (ssdt)

**Behavioral MITRE Mapping**
- CAPEv2 signatures → ATT&CK techniques
- Tactic aggregation (Initial Access → Impact)
- Confidence scoring per technique
- Timeline correlation with static IOCs

### 6.3 Network Forensics

**PCAP Analysis**
- Connection tracking (TCP/UDP/ICMP flows)
- DNS query/response extraction
- HTTP request/response parsing (headers, body)
- TLS handshake capture (JA3/JA3S fingerprints)
- Certificate chain extraction & validation

**Advanced Detection**
- **DGA Classification**: ML model (character LSTM + n-gram) trained on Alexa 1M + known families (Necurs, Gameover ZeuS, Conficker, Matsnu, Rovnix, Suppobox, Tinba, Pykspa, Symmi, Kraken, Gozi)
- **C2 Protocol Parsers**: HTTP (GET/POST), DNS (TXT/A/AAAA/CNAME/NULL), HTTPS (SNI, cert), custom TCP/UDP, ICMP, QUIC
- **Beaconing Statistics**: Coefficient of variation, jitter, periodicity (FFT, autocorrelation), burst detection
- **Traffic Anomalies**: Long connections, high entropy payloads, non-standard ports, protocol violations, exfiltration patterns, DNS tunneling
- **Encrypted Traffic**: SNI extraction, cert fingerprinting, ALPN, cipher suite fingerprinting, TLS version distribution
- **Protocol Identification**: DPI-based (Zeek-style), statistical (port-independent)

### 6.4 Threat Intelligence Platform

**Providers**
- VirusTotal v3 (file/URL/IP/domain reputation, behavior, network)
- AlienVault OTX (pulses, indicators, malware families)
- AbuseIPDB (IP abuse confidence, reports, geolocation)
- MISP (event/attribute sync, galaxy/clusters)
- Custom feeds (STIX bundles, CSV, JSON)

**Enrichment Pipeline**
```
Raw IOC → Type Classification → Context Extraction →
  Passive DNS (local cache) →
  Threat Intel Lookup (VT, OTX, MISP, custom) →
  MITRE ATT&CK Mapping →
  Confidence Scoring →
  Correlation (sample-to-sample, sample-to-campaign) →
  Enriched IOC Store
```

**STIX/TAXII 2.1 Server**
- Collections: Indicators, Malware, Campaigns, Intrusion-Sets, Threat-Actors, Tools, Reports, Courses-of-Action, Identities, Vulnerabilities
- Discovery/Manifest/Objects endpoints
- Authentication: API keys, OAuth2, mTLS
- Filtering: added_after, match[id|type|version], limit

**MISP Synchronization**
- Push: Publish MALINFO indicators/samples to MISP (tagged with metadata)
- Pull: Scheduled sync of MISP events/attributes → MALINFO IOC store
- Bidirectional: Conflict resolution (last-write-wins with audit), attribute proposals

**Actor/Campaign Profiling**
- Actor dossier: aliases, motivation, sophistication, origin, target sectors, tools, infrastructure, TTPs (ATT&CK heatmap), campaigns
- Campaign tracking: timeline, victims, infrastructure overlap, malware families, attribution confidence

**ATT&CK Navigator Integration**
- Layer generation (JSON) for: sample behaviors, actor TTPs, campaign TTPs, defensive coverage gaps
- Export to ATT&CK Navigator web/UI

### 6.5 Real-Time Monitoring

**ICAP Gateway (RFC 3507)**
- REQMOD: Inspect/modify requests before forwarding to origin
- RESPMOD: Inspect/modify responses before delivering to client
- Integration: Squid, government secure web gateways, email gateways
- File extraction: HTTP uploads, email attachments, web downloads
- Auto-analysis pipeline: extracted files → static analysis → verdict → block/allow

**Filesystem Monitoring**
- Watchdog-based recursive directory watching
- Configurable paths: `/var/mail`, `/home/*/Downloads`, `/tmp`, custom
- Event types: create, modify, move, delete
- Auto-submit new/modified files to analysis pipeline
- Deduplication via hash (skip re-analysis)

**Network Flow Monitoring**
- Passive capture via AF_PACKET / PF_RING / DPDK
- BPF filter configuration
- Flow aggregation (5-tuple + timestamps + byte/packet counts)
- Integration with network forensics engine

### 6.6 YARA Rule Management

**Rule Organization**
```
rules/
├── compiled/           # Compiled .yarac files (per ruleset version)
├── sources/            # Source .yar files (git-tracked)
│   ├── official/       # Curated MALINFO rulesets
│   ├── feeds/          # Auto-pulled from feeds
│   │   ├── yara-rules/
│   │   ├── malwarebazaar/
│   │   └── custom-org/
│   └── local/          # Analyst-created rules
├── metadata/           # Rule metadata DB
│   ├── rule_index.db   # rule_id, name, author, severity, mitre, tags, version, hash
│   ├── performance.db  # rule_id, avg_match_time_ms, hit_rate, false_positive_count
│   └── test_cases/     # Positive/negative test samples per rule
└── feeds.yaml          # Feed configuration (URL, schedule, auth, filters)
```

**Management Features**
- Incremental compilation (only changed rules)
- Parallel compilation worker pool
- Rule versioning with rollback
- False positive tracking (analyst feedback → rule tuning)
- Performance budgets (max N ms per file, auto-disable slow rules)
- Rule tagging (MITRE, platform, family, confidence)
- Test harness with positive/negative corpora

### 6.7 Decompiler Integration

**Ghidra Headless API**
- Project management: create/import binary, auto-analysis (configurable options)
- Function analysis: list (address, name, signature, calling convention, stack frame, body), decompile (pseudocode C), xrefs (callers/callees, data refs)
- String analysis: defined strings (ASCII, Unicode, UTF-8, C-style), string xrefs
- Type system: structures, unions, enums, typedefs from PDB/DWARF/symbols
- Scripting: run custom Ghidra scripts (Python/Java), batch analysis
- Export: function list (CSV/JSON), call graph (GraphML/DOT), decompilation (per-function or full), type archive (GDT)

**Retdec Fallback**
- For architectures Ghidra doesn't support well or when Ghidra unavailable
- Raw decompilation → C-like pseudocode
- Function boundary detection

**FLIRT Signatures**
- Microsoft Visual Studio (various versions)
- GCC/Clang standard libraries
- Common third-party (OpenSSL, libcurl, Boost, Qt, etc.)
- Custom signature generation from known-good binaries

**Integration Points**
- Static analysis pipeline: auto-run on PE/ELF/Mach-O > 100KB
- Analyst UI: "Open in Decompiler" button per function
- Report: Include key function decompilations
- API: `POST /api/decompiler/analyze` → async task, poll for results

### 6.8 Reporting System

**Report Types & Formats**

| Type | HTML | PDF | JSON | STIX 2.1 | MISP | CSV | DOCX |
|------|------|-----|------|----------|------|-----|------|
| Executive Summary | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Planned |
| Technical Deep-Dive | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Planned |
| MITRE ATT&CK Matrix | ✓ | ✓ | ✓ | — | — | — | — |
| Kill Chain Timeline | ✓ | ✓ | ✓ | — | — | — | — |
| IOC Package | — | — | ✓ | ✓ | ✓ | ✓ | — |
| Evidence Appendix | ✓ | ✓ | ✓ | — | — | ✓ | — |

**Features**
- Jinja2 templates with custom filters (filesizeformat, tojson, date formatting)
- Analyst annotations (rich text, inline evidence references)
- Digital signature (PAdES-LTV for PDF)
- Custom branding (logo, classification markings: TLP, classification level)
- Redaction support (classified IOCs, PII)
- Version control (report revisions, diff view)

---

## 7. Installation & Deployment

### 7.1 Prerequisites

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| **CPU** | 4 cores | 8+ cores |
| **RAM** | 16 GB | 32+ GB |
| **Disk** | 200 GB SSD | 500+ GB NVMe |
| **Docker** | 24+ | Latest |
| **Docker Compose** | 2+ | Latest |
| **OS** | Linux (Ubuntu 22.04+, RHEL 9+, Debian 12+) | Any Docker-compatible Linux |

**Optional (for full capability):**
- **CAPEv2 Sandbox Cluster** — Separate infrastructure (see `backend/app/sandbox/README.md`)
- **TLS Certificates** — Let's Encrypt or CA-issued for production
- **Threat Intel API Keys** — VirusTotal, OTX, AbuseIPDB, MISP
- **Ghidra** — `/opt/ghidra` for decompiler integration
- **Retdec** — `/usr/bin/retdec-decompiler` fallback

### 7.2 Quick Start (Docker Compose) — 5 Minutes

```bash
# 1. Clone repository
git clone https://github.com/your-org/malinfo.git
cd malinfo

# 2. Initialize project structure
make init

# 3. Generate production secrets (SAVE THESE SECURELY!)
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

# 4. Configure environment
cp .env.example .env
# Edit .env with ALL required values:
#   - SECRET_KEY (from step 3)
#   - POSTGRES_PASSWORD (from step 3)
#   - GRAFANA_PASSWORD (from step 3)
#   - ALLOWED_ORIGINS=https://malinfo.yourdomain.gov
#   - Threat intel API keys (optional but recommended)

# 5. Generate TLS certificates
# For staging/development:
make certs MODE=selfsigned DOMAIN=malinfo-staging.example.com

# For production (requires domain + email):
make certs MODE=letsencrypt DOMAIN=malinfo.example.gov EMAIL=admin@example.gov

# 6. Deploy full production stack
make prod
# Or deploy specific profiles:
make deploy-docker ACTION=up PROFILE=all

# 7. Verify deployment
make health
make status
```

**Access Points:**
- **Dashboard**: `https://malinfo.yourdomain.gov`
- **API**: `https://malinfo.yourdomain.gov/api`
- **API Docs (Swagger)**: `https://malinfo.yourdomain.gov/api/docs`
- **Metrics**: `https://malinfo.yourdomain.gov:9090` (Prometheus)
- **Grafana**: `https://malinfo.yourdomain.gov:3000` (admin / GRAFANA_PASSWORD)

### 7.3 Development Environment

```bash
# Start development stack with hot reload
make dev

# Access at http://localhost
# API at http://localhost/api
# Auto-reloads on code changes
```

### 7.4 Kubernetes Deployment (Production/HA)

```bash
# 1. Apply manifests
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

# 4. Verify
kubectl get all -n malinfo
kubectl logs -f deployment/malinfo-backend -n malinfo
```

### 7.5 Bare Metal / systemd Deployment

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

# 5. Start services
sudo systemctl daemon-reload
sudo systemctl enable --now malinfo-backend malinfo-icap malinfo-monitor

# 6. Configure nginx separately
sudo cp deploy/nginx.prod.conf /etc/nginx/nginx.conf
sudo nginx -t && sudo systemctl reload nginx
```

### 7.6 Air-Gap Deployment

```bash
# 1. On internet-connected machine, build images and create bundle
make sbom
docker save malinfo/backend:latest malinfo/frontend:latest postgres:16-alpine redis:7-alpine ... > malinfo-images.tar
tar czf malinfo-airgap-bundle.tar.gz malinfo-images.tar .env.example deploy/ scripts/ backend/requirements.txt

# 2. Transfer bundle to air-gapped network (approved removable media)

# 3. On air-gapped machine, load images and deploy
docker load < malinfo-images.tar
# Configure .env with local registry / no external deps
make prod
```

---

## 8. Configuration

### 8.1 Required Environment Variables

| Variable | Description | Required | Example |
|----------|-------------|----------|---------|
| `SECRET_KEY` | JWT signing key (32+ chars) | **YES** | `openssl rand -base64 48` |
| `DATABASE_URL` | PostgreSQL connection string | **YES** | `postgresql+asyncpg://malinfo:pass@db:5432/malinfo` |
| `REDIS_URL` | Redis connection string | **YES** | `redis://redis:6379/0` |
| `POSTGRES_PASSWORD` | Database password | **YES** | (from `make secrets`) |
| `ALLOWED_ORIGINS` | CORS origins (JSON array) | **YES** | `["https://malinfo.example.gov"]` |
| `GRAFANA_PASSWORD` | Grafana admin password | **YES** | (from `make secrets`) |
| `ENVIRONMENT` | Deployment environment | No | `production` |
| `DEBUG` | Debug mode | No | `false` |
| `MAX_UPLOAD_SIZE_MB` | Max file upload size | No | `250` |

### 8.2 Optional Integrations

| Variable | Description | Required If |
|----------|-------------|-------------|
| `VIRUSTOTAL_API_KEY` | VirusTotal v3 API key | Using VT enrichment |
| `OTX_API_KEY` | AlienVault OTX API key | Using OTX enrichment |
| `ABUSEIPDB_API_KEY` | AbuseIPDB API key | Using AbuseIPDB enrichment |
| `MISP_URL` / `MISP_API_KEY` | MISP instance | Using MISP sync |
| `SANDBOX_ENABLED` | Enable CAPEv2 | `true` |
| `SANDBOX_API_URL` | CAPEv2 controller URL | Sandbox enabled |
| `SANDBOX_API_TOKEN` | CAPEv2 API token | Sandbox requires auth |
| `ICAP_ENABLED` | Enable ICAP gateway | `true` |
| `MONITOR_ENABLED` | Enable file monitoring | `true` |
| `MONITOR_WATCH_PATHS` | Paths to watch (JSON array) | Monitor enabled |
| `GHIDRA_PATH` | Ghidra installation path | Using decompiler |
| `RETDEC_PATH` | Retdec installation path | Using decompiler fallback |

### 8.3 YARA Rules Configuration

```bash
# Directory structure (auto-created by make init)
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

**Feed Configuration** (`feeds.yaml`):
```yaml
feeds:
  - name: yara-rules
    url: https://github.com/YARA-Rules/rules/archive/master.zip
    schedule: "0 3 * * *"  # Daily at 3 AM
    auth: none
    filters:
      - "*.yar"
      - "!test*"
  
  - name: malwarebazaar
    url: https://bazaar.abuse.ch/export/yara/
    schedule: "0 */6 * * *"  # Every 6 hours
    auth: none
    filters:
      - "*.yar"
```

### 8.4 CAPEv2 Sandbox Configuration

```bash
# In .env
SANDBOX_ENABLED=true
SANDBOX_API_URL=http://cape-controller.internal:8000
SANDBOX_API_TOKEN=your_api_token_if_required
SANDBOX_POLL_INTERVAL_SEC=15
SANDBOX_TIMEOUT_SEC=600

# Sandbox profiles (VM templates in your CAPEv2 cluster)
SANDBOX_PROFILES='{"windows": "win10-x64-clean", "linux": "ubuntu22-x64-clean", "android": "android13-x86-clean"}'
```

**Network Isolation (MANDATORY):**
- Use INetSim or FakeNet-NG for simulated internet
- No direct internet egress from analysis VMs
- Dedicated isolated network segment
- Legal authorization for any live C2 observation

---

## 9. Working with MALINFO

### 9.1 Web Dashboard (Analyst Console)

**Navigation:**
- **Dashboard** — Overview, statistics, recent analyses, threat feed summary
- **Samples** — Upload, list, filter, search, bulk actions
- **Sandbox** — Submit to dynamic analysis, monitor tasks, view behavioral reports
- **Reports** — View/download reports (HTML, PDF, JSON, STIX, MISP, CSV)
- **Monitoring** — File transfers, network flows, alerts, statistics
- **Network** — PCAP analysis, flow visualization, C2 detection
- **Threat Intel** — Provider status, enrichment lookups, feed management
- **IOCs** — Search, export, correlate indicators
- **Users** — Admin: user management, roles, permissions, audit logs
- **Audit** — Comprehensive audit trail with filtering
- **Settings** — Profile, MFA, API keys, preferences

**Key Workflows:**

#### Upload & Analyze Sample
1. Navigate to **Samples** → Click **Upload Sample**
2. Drag & drop or browse for file (max 250 MB)
3. Click **Upload & Analyze**
4. Real-time progress: Queued → Static Running → Static Done → Sandbox Running → Network Analysis → Complete
5. View report: **Reports** → Click sample → Choose format

#### Submit to Sandbox
1. From sample detail or **Sandbox** page
2. Select profile: Windows 10/11, Ubuntu 22.04, Android 13, macOS (Apple Silicon only)
3. Configure options: memory dump, process dump, network capture, API monitor
4. Submit → Monitor progress via WebSocket
5. View behavioral report with MITRE mapping, process tree, dropped files, screenshots

#### Threat Intel Enrichment
1. Navigate to **Threat Intel** → **Lookup**
2. Enter hash, IP, domain, or URL
3. Select providers (VT, OTX, AbuseIPDB, MISP)
4. View enriched results with confidence scores
5. Push to MISP or export as STIX/CSV

#### Generate Professional Report
1. From sample detail: **Download Report** → Select format
2. Or **Reports** page → Bulk export
3. Formats: Executive Summary (PDF), Technical Deep-Dive (HTML/PDF), MITRE Matrix, Kill Chain, IOC Package (STIX/MISP/CSV)

### 9.2 REST API (Programmatic Access)

**Authentication:**
```bash
# Login with MFA
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

**Core Endpoints:**

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
| | `/reports/{id}/download` | GET | Download report (format=json\|pdf\|stix\|misp\|csv) |
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

**Rate Limits:**
| Endpoint | Limit | Window |
|----------|-------|--------|
| General API | 100 req/s | 1s |
| Public Report | 5 req/m | 1m |
| File Upload | 10 req/m | 1m |
| Login | 5 req/m | 1m |

### 9.3 CLI / Scripting Examples

**Batch Upload & Analysis:**
```bash
#!/bin/bash
# batch_analyze.sh - Analyze all files in a directory

API_URL="https://malinfo.example.gov/api"
TOKEN="your_access_token"

for file in /path/to/samples/*; do
  echo "Uploading: $file"
  response=$(curl -s -X POST "$API_URL/upload" \
    -H "Authorization: Bearer $TOKEN" \
    -F "file=@$file")
  sample_id=$(echo $response | jq -r .sample_id)
  echo "Submitted: $sample_id"
  
  # Poll for completion
  while true; do
    status=$(curl -s -H "Authorization: Bearer $TOKEN" \
      "$API_URL/reports/$sample_id" | jq -r .status)
    echo "Status: $status"
    [[ "$status" == "complete" ]] && break
    [[ "$status" == "failed" ]] && break
    sleep 30
  done
  
  # Download report
  curl -s -H "Authorization: Bearer $TOKEN" \
    "$API_URL/reports/$sample_id/download?format=pdf" \
    -o "report_${sample_id}.pdf"
done
```

**Automated IOC Enrichment:**
```python
#!/usr/bin/env python3
# enrich_iocs.py - Enrich IOCs from MALINFO via API

import asyncio
import aiohttp
import json

API_URL = "https://malinfo.example.gov/api"
TOKEN = "your_access_token"

async def enrich_iocs(iocs):
    headers = {"Authorization": f"Bearer {TOKEN}"}
    async with aiohttp.ClientSession() as session:
        for ioc in iocs:
            if ioc["type"] == "hash":
                url = f"{API_URL}/threat-intel/lookup/hash/{ioc['value']}"
            elif ioc["type"] == "ip":
                url = f"{API_URL}/threat-intel/lookup/ip/{ioc['value']}"
            elif ioc["type"] == "domain":
                url = f"{API_URL}/threat-intel/lookup/domain/{ioc['value']}"
            else:
                continue
            
            async with session.post(url, headers=headers) as resp:
                result = await resp.json()
                print(f"{ioc['type']}:{ioc['value']} -> {json.dumps(result, indent=2)}")

# Example usage
iocs = [
    {"type": "hash", "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
    {"type": "ip", "value": "185.220.101.42"},
    {"type": "domain", "value": "malicious-c2.example.com"},
]
asyncio.run(enrich_iocs(iocs))
```

---

## 10. Demo Scenarios

### Demo 1: Ransomware Sample Analysis

**Scenario:** Analyst receives suspicious executable via email attachment.

**Steps:**
1. **Upload** — Drag `invoice.exe` to dashboard upload zone
2. **Static Analysis** (auto, ~15s):
   - PE Deep Analysis: Rich header (VS 2019), Authenticode invalid (self-signed, expired), TLS callbacks present, overlay data (encrypted payload)
   - YARA: 12 matches including `Ransomware_LockBit_Characteristics`, `Suspicious_Crypto_Constants_AES`
   - IOCs: 3 IPs, 5 domains, 2 Bitcoin addresses, 1 mutex (`Global\\LockBit_Mutex`)
   - Crypto: AES-256 constants detected in .text, hardcoded RSA-2048 public key
   - Obfuscation: API hashing (DJB2), flattened CFG, string encryption (per-string keys)
   - Risk Score: 87/100 → **VERDICT: MALICIOUS**

3. **Dynamic Analysis** (optional, sandbox enabled, ~3min):
   - CAPEv2 Windows 10 profile
   - Behavior: Shadow copy deletion (vssadmin), file encryption (.lockbit extension), ransom note drop, C2 beaconing to 185.220.101.42:443
   - MITRE: T1486 (Data Encrypted), T1490 (Inhibit Recovery), T1071.001 (Web Protocols), T1573.002 (Asymmetric Crypto)
   - MalScore: 95/100
   - PCAP captured for network forensics

4. **Network Forensics** (from PCAP):
   - JA3 fingerprint matches LockBit TLS client
   - TLS cert: self-signed, CN=lockbit-c2, valid 365 days
   - Beaconing: 60s interval, 10% jitter, HTTPS POST to `/gate.php`
   - C2 protocol: Custom JSON over HTTPS, AES-256 encrypted payloads

5. **Threat Intel Enrichment:**
   - VT: 45/72 detections, LockBit 3.0 family
   - OTX: Pulse "LockBit 3.0 Infrastructure Aug 2024"
   - MISP: Existing event with same C2 IP
   - Attribution: LockBit ransomware group (high confidence)

6. **Report Generation:**
   - Executive Summary (PDF) → Leadership briefing
   - Technical Deep-Dive (HTML/PDF) → IR team handoff
   - IOC Package (STIX 2.1) → SIEM ingestion
   - MITRE Matrix → Detection engineering
   - Kill Chain Timeline → Threat hunting

**Time to Complete Analysis:** ~5 minutes (static) + 3 minutes (dynamic) = **8 minutes total**

### Demo 2: APT Campaign Investigation

**Scenario:** Multiple suspicious documents received across organization.

**Steps:**
1. **Bulk Upload** — 15 documents (docx, pdf, rtf) via API script
2. **Static Analysis Pipeline:**
   - OLE/VBA extraction: 3 docs with malicious macros (XLM/Excel 4.0)
   - PDF JavaScript: 2 PDFs with `/Launch` action to PowerShell download cradle
   - RTF: 1 with CVE-2017-11882 exploit (Equation Editor)
   - IOCs: Shared C2 domain (`apt29-update.example.org`), same mutex (`Global\\APT29_Mutex`)
   - YARA: APT29/Cozy Bear family rules triggered

3. **Correlation:**
   - Same certificate chain across 3 payloads (self-signed, CN=Microsoft Update)
   - Identical ImpHash for 2 PE droppers
   - Shared infrastructure: 2 IPs, 1 domain across samples

4. **Threat Intel:**
   - MISP: Matches existing APT29 campaign "GhostWriter"
   - Actor Profile: APT29 (Cozy Bear), Russia, espionage, targets: gov/defense/energy
   - TTPs: T1566.001 (Spearphishing Attachment), T1059.001 (PowerShell), T1055 (Process Injection)

5. **Case Management:**
   - Create case "APT29 GhostWriter - Aug 2024"
   - Link all 15 samples, IOCs, reports
   - Assign to threat hunting team
   - Export IOC package (STIX) for organization-wide blocking

**Time to Complete:** ~20 minutes for 15 samples + correlation

### Demo 3: Real-Time Gateway Inspection (ICAP)

**Scenario:** Email gateway integrates with MALINFO via ICAP to inspect attachments before delivery.

**Flow:**
1. User receives email with attachment `proposal.pdf`
2. Email gateway (Squid/ICAP client) sends REQMOD request to MALINFO ICAP service
3. MALINFO extracts PDF, runs static analysis (~2s)
4. **Verdict: CLEAN** (risk score 5) → ICAP 204 No Modifications → Email delivered
5. **Verdict: MALICIOUS** (risk score 78, CVE-2021-34527 exploit) → ICAP 403 Forbidden → Email quarantined, alert sent to SOC

**Latency:** <2 seconds added to email delivery for clean files

### Demo 4: Filesystem Monitoring

**Scenario:** Monitor `/home/*/Downloads` for suspicious files.

**Configuration:**
```bash
MONITOR_ENABLED=true
MONITOR_WATCH_PATHS='["/home/*/Downloads", "/var/mail", "/tmp"]'
MONITOR_AUTO_ANALYZE=true
```

**Flow:**
1. User downloads `free_game.exe` to `~/Downloads`
2. Watchdog detects CREATE event
3. File submitted to analysis pipeline automatically
4. Analysis completes: **VERDICT: SUSPICIOUS** (info stealer, risk 45)
5. Alert: WebSocket notification to analyst dashboard + email/webhook
6. Analyst reviews, pushes IOCs to MISP, blocks hash at EDR

---

## 11. Desired vs Actual Output

### 11.1 Static Analysis Output

| Component | Desired Output | Actual Output (v1.0.0-pilot) | Status |
|-----------|----------------|------------------------------|--------|
| **File Hashes** | SHA256, SHA1, MD5, SSDEEP | ✅ All implemented | Complete |
| **File Type/MIME** | Accurate identification via libmagic | ✅ `filetype.identify_file()` | Complete |
| **Target OS** | Windows/Linux/macOS/Android/Unknown | ✅ Signature-based detection | Complete |
| **Entropy** | Shannon entropy 0.0-8.0, per-section | ✅ `strings_entropy.file_entropy()` | Complete |
| **Strings** | ASCII/Unicode, configurable min length | ✅ `extract_strings()` with sampling | Complete |
| **YARA Matches** | Rule name, namespace, tags, meta, severity, MITRE | ✅ Full match metadata | Complete |
| **PE Deep Analysis** | Rich header, Authenticode, TLS, COM, delay-load, CLR, resources, debug, overlay, ImpHash | ✅ `pe_deep_analysis.py` | Complete |
| **ELF Deep Analysis** | Hardening flags, RPATH, version info, build ID, Go/Rust | ✅ `elf_deep_analysis.py` | Complete |
| **Mach-O Deep Analysis** | Codesign, entitlements, dyld, universal, hardened runtime | ✅ `macho_deep_analysis.py` | Complete |
| **APK Deep Analysis** | Cert chain v1-v4, network config, manifest hardening, embedded payloads | ✅ `apk_deep_analysis.py` | Complete |
| **Office/PDF/Script** | OLE/VBA, OOXML, RTF, PDF JS, PS/BAT/JS/VBS/PY/SH | ✅ `ole_analysis.py`, `script_analysis.py` | Complete |
| **IOC Extraction** | IP, domain, URL, email, registry, mutex, filepath, BTC, hash | ✅ 12+ IOC types with context | Complete |
| **C2 Flagging** | Gate.php, beacon, panel detection | ✅ `flag_likely_c2()` | Complete |
| **Crypto Detection** | AES, DES, RC4, ChaCha, RSA, ECC, hash constants, key extraction | ✅ `crypto_detector.py` | Complete |
| **Obfuscation Detection** | CFG, VM packs, string crypto, API hash, anti-analysis | ✅ `obfuscation_detector.py` | Complete |
| **Risk Scoring** | Multi-factor, explainable, dynamic merge, verdicts | ✅ `risk_scoring.py` | Complete |

### 11.2 Dynamic Analysis Output

| Component | Desired Output | Actual Output | Status |
|-----------|----------------|---------------|--------|
| **CAPEv2 Submit** | Profile selection, options, task ID | ✅ `capev2_client.py` | Complete |
| **Polling** | Configurable interval/timeout, terminal states | ✅ `orchestrator.py` | Complete |
| **Report Retrieval** | Signatures, dropped files, network, screenshots | ✅ Normalized report dict | Complete |
| **PCAP Download** | Full capture for network forensics | ✅ `get_pcap()` | Complete |
| **Volatility3** | pslist, pstree, dlllist, malfind, hollowfind, apihooks | ⚠️ Planned (Phase 2) | In Progress |
| **MITRE Mapping** | Signatures → techniques → tactics | ✅ Basic mapping in orchestrator | Partial |
| **Process Tree** | Parent-child, cmdline, integrity, token | ⚠️ Planned (Phase 2) | In Progress |
| **Memory Dumps** | Full/process dumps for offline analysis | ⚠️ Requires CAPEv2 config | Infrastructure |

### 11.3 Network Forensics Output

| Component | Desired Output | Actual Output | Status |
|-----------|----------------|---------------|--------|
| **PCAP Parsing** | Flows, DNS, HTTP, TLS | ✅ `pcap_analyzer.py` | Complete |
| **JA3/JA3S** | Client/server TLS fingerprints | ✅ Implemented | Complete |
| **TLS Cert Extraction** | Full chain, validation, pinning detection | ✅ Implemented | Complete |
| **DGA Classification** | ML model (LSTM + n-gram) | ⚠️ Stub in `c2_detection.py` | Phase 2 |
| **C2 Protocol Parsers** | HTTP, DNS, HTTPS, custom TCP/UDP, ICMP, QUIC | ⚠️ Basic HTTP/DNS | Phase 2 |
| **Beaconing Stats** | CoV, jitter, FFT, autocorrelation, bursts | ⚠️ Basic interval detection | Phase 2 |
| **Traffic Anomalies** | Long conn, high entropy, non-std ports, exfil, DNS tunnel | ⚠️ Planned | Phase 2 |
| **Encrypted Traffic** | SNI, cert fingerprint, ALPN, cipher suite, TLS version | ⚠️ Basic SNI/cert | Phase 2 |

### 11.4 Threat Intelligence Output

| Component | Desired Output | Actual Output | Status |
|-----------|----------------|---------------|--------|
| **VT Enrichment** | File/URL/IP/domain reputation, behavior, network | ✅ `integration.py` | Complete |
| **OTX Enrichment** | Pulses, indicators, malware families | ✅ Implemented | Complete |
| **AbuseIPDB** | IP abuse confidence, reports, geo | ✅ Implemented | Complete |
| **MISP Sync** | Push/pull events/attributes, galaxies | ✅ Basic push/pull | Partial |
| **STIX/TAXII 2.1** | Server with collections, discovery, objects | ⚠️ Planned (Phase 3) | In Progress |
| **Actor Profiling** | Dossiers, TTP heatmaps, infrastructure | ⚠️ Planned (Phase 3) | In Progress |
| **ATT&CK Navigator** | Layer JSON export | ⚠️ Planned (Phase 3) | In Progress |
| **Feed Management** | Scheduling, dedup, scoring, aging | ✅ `feeds.yaml` config | Partial |

### 11.5 Reporting Output

| Format | Desired Output | Actual Output | Status |
|--------|----------------|---------------|--------|
| **Executive Summary (HTML/PDF)** | 1-2 pages, verdict, risk, key IOCs, recs | ✅ `executive_summary.html` template | Complete |
| **Technical Deep-Dive (HTML/PDF/JSON)** | Full evidence, methodology, MITRE matrix | ✅ `technical_deep_dive.html` template | Complete |
| **MITRE Matrix (HTML/JSON)** | Technique heatmap, tactic summary, gaps | ⚠️ Template exists, data integration partial | Partial |
| **Kill Chain (HTML/JSON)** | Lockheed Martin + ATT&CK phases, timeline | ⚠️ Template exists, data integration partial | Partial |
| **IOC Package (STIX 2.1)** | Bundle: malware + indicators + relationships | ✅ `export_stix()` | Complete |
| **IOC Package (MISP)** | Event JSON with attributes, tags | ✅ `export_misp()` | Complete |
| **IOC Package (CSV)** | Type, value, confidence, source, context, tags | ✅ `export_csv()` | Complete |
| **Evidence Appendix** | Hashes, YARA, strings, imports, sections, flows | ✅ Included in deep-dive | Complete |
| **PAdES-LTV PDF Signing** | Digital signature for legal evidence | ⚠️ Planned | In Progress |
| **Redaction** | Classified IOC/PII removal | ⚠️ Planned | In Progress |

### 11.6 Platform Capabilities

| Feature | Desired | Actual | Status |
|---------|---------|--------|--------|
| **Multi-tenancy** | Orgs, cases, controlled sharing | ⚠️ Schema ready, API partial | Phase 4 |
| **RBAC + MFA** | 5 roles, 20+ perms, TOTP, audit | ✅ `auth.py`, `rbac.py` | Complete |
| **ICAP Gateway** | REQMOD/RESPMOD, file extraction, verdict | ✅ `icap_server.py` | Complete |
| **Filesystem Monitor** | Watchdog, recursive, auto-analyze, dedup | ✅ `transfer_monitor.py` | Complete |
| **Network Monitor** | AF_PACKET, BPF, flow aggregation | ⚠️ Basic structure | Phase 2 |
| **YARA Management** | Feeds, compilation, versioning, perf, test | ✅ `yara_manager.py` | Complete |
| **Decompiler** | Ghidra headless, retdec, FLIRT, export | ⚠️ API structure ready, impl partial | Phase 3 |
| **Case Management** | Create, assign, track, link evidence | ⚠️ Schema ready, UI partial | Phase 3 |
| **Observability** | Prometheus, Grafana, OpenTelemetry, alerts | ✅ Metrics, dashboards, alerts | Complete |
| **Air-gap Updates** | Signed bundles, feed import/export, model updates | ⚠️ Design ready | Phase 4 |

---

## 12. Reporting & Output Formats

### 12.1 Report Templates (Jinja2)

Located in `backend/app/reporting/templates/`:

| Template | Purpose | Key Sections |
|----------|---------|--------------|
| `report.html.j2` | Main technical report layout | Tabs: Overview, Static, Dynamic, Network, IOCs, MITRE, Kill Chain, Evidence |
| `executive_summary.html` | Leadership briefing | Verdict badge, risk gauge, key findings, top 5 IOCs, 5 recommendations |
| `technical_deep_dive.html` | Analyst deep-dive | All tabs with full detail, expandable JSON sections, string search |
| `report_style.css` | Shared styling | Dark/light mode, print-optimized, responsive, TLP colors |

### 12.2 Export Formats

**API Usage:**
```bash
# Download any format
curl -H "Authorization: Bearer $TOKEN" \
  "https://malinfo.example.gov/api/reports/{id}/download?format=pdf"

# Supported formats: html, pdf, json, stix, misp, csv
```

**Programmatic (Python):**
```python
from app.reporting.report_generator import ReportGenerator

generator = ReportGenerator(tlp="amber")
report = generator.build_full_report(sample, static, sandbox, network, ti)

# Export all formats at once
results = generator.save_all_formats(report, Path("/output/report_base"))
# Returns: {"html": ..., "executive_html": ..., "pdf": ..., "json": ..., "stix": ..., "misp": ..., "csv": ...}
```

### 12.3 STIX 2.1 Bundle Structure

```json
{
  "type": "bundle",
  "id": "bundle--uuid",
  "spec_version": "2.1",
  "objects": [
    {
      "type": "malware",
      "spec_version": "2.1",
      "id": "malware--uuid",
      "created": "2024-08-03T12:00:00Z",
      "modified": "2024-08-03T12:00:00Z",
      "name": "invoice.exe",
      "description": "MALINFO analysis of invoice.exe",
      "malware_types": ["trojan"],
      "is_family": false,
      "labels": ["malicious"]
    },
    {
      "type": "indicator",
      "spec_version": "2.1",
      "id": "indicator--uuid",
      "created": "2024-08-03T12:00:00Z",
      "modified": "2024-08-03T12:00:00Z",
      "name": "ipv4: 185.220.101.42",
      "description": "C2 server from static analysis",
      "indicator_types": ["malicious-activity"],
      "pattern": "[ipv4-addr:value = '185.220.101.42']",
      "pattern_type": "stix",
      "valid_from": "2024-08-03T12:00:00Z",
      "confidence": 90,
      "labels": ["malicious-activity"]
    },
    {
      "type": "relationship",
      "spec_version": "2.1",
      "id": "relationship--uuid",
      "created": "2024-08-03T12:00:00Z",
      "modified": "2024-08-03T12:00:00Z",
      "relationship_type": "indicates",
      "source_ref": "indicator--uuid",
      "target_ref": "malware--uuid"
    }
  ]
}
```

### 12.4 MISP Event Structure

```json
{
  "Event": {
    "info": "MALINFO Analysis - invoice.exe",
    "date": "2024-08-03",
    "threat_level_id": "1",
    "analysis": 2,
    "distribution": 3,
    "Attribute": [
      {
        "type": "ip-dst",
        "value": "185.220.101.42",
        "comment": "C2 server from static analysis",
        "to_ids": true,
        "confidence": 90
      }
    ],
    "Tag": [
      {"name": "tlp:amber"},
      {"name": "malinfo:verdict=malicious"}
    ]
  }
}
```

---

## 13. Security Hardening

### 13.1 Network Security
- **TLS 1.2/1.3 only** — TLS 1.0/1.1 disabled
- **HSTS with preload** — `max-age=31536000; includeSubDomains; preload`
- **C