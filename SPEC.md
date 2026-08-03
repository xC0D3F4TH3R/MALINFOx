# MALINFO — Government-Grade Platform Enhancement Specification

**Version:** 2.0.0-target  
**Classification:** Government / Enterprise Delivery  
**Status:** Design Phase → Implementation

---

## 1. Executive Summary

MALINFO v1.0.0-pilot provides a solid foundation. This specification defines the enhancements required to achieve **government/enterprise-grade readiness** — a platform that professional malware analysts, reverse engineers, and threat hunters would choose over commercial alternatives (IDA Pro, Binary Ninja, Cuckoo, Joe Sandbox, Hybrid Analysis, VirusTotal Enterprise).

**Target Delivery:** Air-gapped CERT deployments, SOC operations centers, national CERTs, defense contractors.

---

## 2. Gap Analysis: Current vs. Required

| Domain | Current State | Government-Grade Requirement |
|--------|--------------|------------------------------|
| **PE Analysis** | Basic headers, imports, sections, entropy | Rich headers, certificates (Authenticode chain validation), TLS callbacks, COM registrations, delay-load, bound imports, CLR metadata, resource analysis, version info, debug data (PDB path, GUID, age), overlay extraction |
| **ELF Analysis** | Basic headers, sections, dynamic symbols | DT_NEEDED/RPATH/RUNPATH, version definitions/requirements (gnu.version), .note.gnu.build-id, .note.ABI-tag, DT_FLAGS_1, dynamic segment hardening flags (BIND_NOW, NODELETE), interpreter path, RPATH security audit |
| **Mach-O Analysis** | Basic headers, load commands | Code signature validation (requirement & entitlements), dyld info (rebasing, binding, weak binding, lazy binding, exports), __LINKEDIT analysis, universal binary slice analysis, hardened runtime flags |
| **APK Analysis** | Manifest, permissions, components, DEX presence | Certificate chain validation (expiry, self-signed, v1/v2/v3 signing), network security config, manifest hardening (debuggable, allowBackup, exported components), embedded SO/DEX/JAR extraction, native library analysis |
| **YARA Rules** | 4 static .yar files | Rule management system: feeds (MalwareBazaar, YARA-Rules, custom), versioning, compilation caching, performance metrics, rule testing harness, false positive tracking |
| **IOC Extraction** | Basic regex (IP, domain, URL, email, registry, mutex) | Passive DNS enrichment, SSL cert pin extraction, DGA detection, MITRE ATT&CK mapping, C2 framework fingerprinting (Cobalt Strike, Sliver, Mythic, Brute Ratel), artifact correlation |
| **Risk Scoring** | Static weights (YARA, entropy, APIs, IOCs) | ML-assisted scoring (trainable per org), dynamic feature weights, analyst feedback loop, calibration against labeled datasets, explainability |
| **Crypto Detection** | None | Algorithm constant detection (AES S-box, RC4 KSA, ChaCha20, RSA moduli), hardcoded key extraction, entropy per section, encrypted payload carving |
| **Obfuscation Detection** | Basic packer section names, high entropy | Control flow graph analysis, opaque predicate detection, virtual machine packer ID (VMProtect, Themida, Enigma, custom), API hashing detection, string encryption identification |
| **CAPEv2 Integration** | Basic task submit/status/report | Memory dump analysis (Volatility3 integration), API call timeline with args, behavioral MITRE mapping, process tree visualization, dropped file auto-extraction, network IOC correlation |
| **Network Forensics** | PCAP parsing, connections, DNS, HTTP, beaconing | JA3/JA3S fingerprinting, TLS certificate extraction/validation, DGA classification (ML), C2 protocol parsing (HTTP, DNS, custom), encrypted traffic analysis (TLS SNI, cert pinning), protocol anomaly detection |
| **Threat Intelligence** | 4 providers (VT, OTX, AbuseIPDB, MISP) | STIX/TAXII 2.1 client/server, MISP sync (push/pull), actor/campaign profiling, ATT&CK navigator integration, threat feed management, indicator aging/scoring |
| **Reporting** | Basic HTML/JSON | Executive summary, technical deep-dive, MITRE ATT&CK matrix, kill chain timeline, IOC packages (STIX/CSV/MISP), evidence appendix, analyst annotations, custom templates |
| **Decompiler Integration** | None | Ghidra headless API (function listing, decompilation, xrefs, strings), retdec fallback, function signature matching (FLIRT), call graph export |
| **Platform Hardening** | Basic RBAC, audit log | Multi-tenancy (organizations/cases), air-gap deployment mode (offline updates), HA/DR (active-passive), secrets rotation, FIPS 140-2 crypto, supply chain verification (SBOM, SLSA) |

---

## 3. Enhancement Categories

### 3.1 Static Analysis Engine — Deep Binary Intelligence

#### 3.1.1 PE Analysis Enhancement (`pe_analysis.py` → `pe_deep_analysis.py`)

**New Capabilities:**
- **Rich Header Parsing** — Visual Studio build tools, linker version, compilation timestamps
- **Authenticode Signature Chain Validation** — Full PKCS#7 verification, timestamp validation, revocation checking (CRL/OCSP offline cache), countersignatures
- **TLS Callbacks** — `.tls` directory enumeration, callback address resolution, anti-debug detection
- **COM Registration** — `DllRegisterServer`/`DllUnregisterServer` detection, CLSID extraction, typelib resources
- **Delay-Load Imports** — `__delayLoadHelper2` analysis, delay import descriptors
- **Bound Imports** — Timestamp verification against target DLLs
- **CLR/.NET Metadata** — Assembly name, version, public key token, module GUID, type references, method signatures, resource manifests
- **Resource Analysis** — Icons, manifests, version info (CompanyName, FileDescription, ProductVersion, OriginalFilename, InternalName, LegalCopyright), string tables, RT_MANIFEST (UAC, DPI awareness, compatibility)
- **Debug Data** — PDB path (raw & GUID/age), CodeView (RSDS), Pogo, FPO, feature strings
- **Overlay Extraction** — Carve appended data, recursive analysis of embedded payloads (PE-in-PE, ZIP, shellcode)
- **Section Permissions Audit** — RWX detection, executable .data, writable .text
- **Import Hash (ImpHash)** — Fuzzy import similarity for family clustering

#### 3.1.2 ELF Analysis Enhancement (`elf_analysis.py` → `elf_deep_analysis.py`)

**New Capabilities:**
- **Dynamic Segment Hardening** — `DT_FLAGS_1` (NOW, GLOBAL, GROUP, NODELETE, NOOPEN, ORIGIN, INTERPOSE, NODEFLIB, FILTER), `DT_BIND_NOW`, RELRO (full/partial)
- **RPATH/RUNPATH Security** — `$ORIGIN` expansion, relative path audit, library hijacking risk
- **Version Info** — `gnu.version`, `gnu.version_d`, `gnu.version_r` — symbol versioning audit
- **Build ID** — `.note.gnu.build-id` extraction, debug file correlation
- **ABI Tag** — `.note.ABI-tag` kernel/OS version targeting
- **Interpreter Analysis** — `ld-linux` path, custom loader detection
- **Symbol Visibility** — `STV_HIDDEN`, `STV_INTERNAL`, `STV_PROTECTED` — stripped vs. hidden
- **Init/Fini Arrays** — Constructor/destructor function enumeration
- **Dynamic Relocations** — RELA/REL analysis, GOT/PLT inspection
- **GOBinaries** — Go version, module path, build info, dependencies (via `runtime.buildVersion`, `runtime.modInfo`)
- **Rust Binaries** — Version, crate metadata, panic strategy

#### 3.1.3 Mach-O Analysis Enhancement (`macho_analysis.py` → `macho_deep_analysis.py`)

**New Capabilities:**
- **Code Signature Validation** — CMS blob parsing, requirement set (designated requirement), entitlements dictionary, team ID, bundle ID, platform, code directory hash algorithm, signing identifier
- **Hardened Runtime Flags** — Library validation, DYLD env var restrictions, JIT disable, unsigned executable memory
- **Dyld Info** — Rebase opcodes, bind opcodes (lazy/weak/regular), lazy bind, weak bind, export trie
- **Universal Binary** — Slice enumeration, architecture-specific analysis, fat header validation
- **Load Command Deep Dive** — `LC_DYLD_INFO_ONLY`, `LC_BUILD_VERSION` (SDK/min OS), `LC_SOURCE_VERSION`, `LC_MAIN`, `LC_DATA_IN_CODE`, `LC_DYLD_EXPORTS_TRIE`, `LC_DYLD_CHAINED_FIXUPS`
- **Entitlements** — Full plist parsing, critical entitlements (com.apple.security.cs.*, get-task-allow, debug)
- **Notarization** — Ticket stub detection, notarization status

#### 3.1.4 APK Analysis Enhancement (`apk_analysis.py` → `apk_deep_analysis.py`)

**New Capabilities:**
- **Certificate Chain** — v1 (JAR), v2 (APK Signing Block), v3 (key rotation), v4 (incremental) — full chain validation, expiry, self-signed detection, key algorithm/size, subject DN
- **Network Security Config** — `network_security_config.xml` parsing, cleartext traffic, certificate pinning, domain config
- **Manifest Hardening** — `android:debuggable`, `allowBackup`, `fullBackupContent`, exported components (activities, services, receivers, providers), permissions with `protectionLevel`, `sharedUserId`
- **Embedded Payload Extraction** — Secondary DEX (`classes2.dex`+), native libraries (`lib/arch/*.so` — recursive PE/ELF analysis), JAR assets, raw resources
- **DEX Analysis** — Class/method count, string references, API usage (reflection, dynamic loading, native methods), obfuscation markers (ProGuard/DexGuard mapping)
- **Certificate Transparency** — CT log inclusion check (if online)

#### 3.1.5 New: Office Document Analysis (`ole_analysis.py`)

- **OLE/CFB** — Stream/directory enumeration, VBA macro extraction (olevba integration), XLM/Excel 4.0 macro detection
- **OOXML (docx/xlsx/pptx)** — `[Content_Types].xml`, relationships, VBA project (`vbaProject.bin`), external relationships (OLE objects, hyperlinks), printer settings (CVE-2021-34527), embedded OLE packages
- **RTF** — Object parsing, OLE embedded objects, hex-encoded payloads
- **PDF** — JavaScript actions (`/JS`, `/JavaScript`), `/Launch`, `/URI`, `/SubmitForm`, embedded files (`/EmbeddedFiles`), XFA forms, JBIG2/JPXDecode streams

#### 3.1.6 New: Script Analysis (`script_analysis.py`)

- **PowerShell** — AST parsing (System.Management.Automation.Language), obfuscation detection (string encoding, command compression, Invoke-Obfuscation markers), AMSI bypass patterns, encoded commands, download cradles
- **Batch/CMD** — Variable obfuscation, delayed expansion tricks, FOR loop encoding
- **JavaScript/VBScript** — AST (Acorn/Esprima), eval/Function constructor, ActiveXObject/WScript.Shell, ADODB.Stream, obfuscation (JSFuck, AAEncode, custom)
- **Python** — AST, marshal/pickle deserialization, base64/zlib layers, PyInstaller/py2exe detection
- **Shell (bash/sh)** — Obfuscation (base64, eval, $(...), ${...}, heredocs), reverse shells, curl/wget download-execute

---

### 3.2 YARA Rule Management System (`yara_manager.py`)

**Architecture:**
```
rules/
├── compiled/           # Compiled .yarac files (per ruleset version)
├── sources/            # Source .yar files (git-tracked)
│   ├── official/       # Curated MALINFO rulesets
│   ├── feeds/          # Auto-pulled from external feeds
│   │   ├── yara-rules/
│   │   ├── malwarebazaar/
│   │   └── custom-org/
│   └── local/          # Analyst-created rules
├── metadata/           # Rule metadata DB (SQLite/PostgreSQL)
│   ├── rule_index.db   # rule_id, name, author, severity, mitre, tags, version, hash
│   ├── performance.db  # rule_id, avg_match_time_ms, hit_rate, false_positive_count
│   └── test_cases/     # Positive/negative test samples per rule
└── feeds.yaml          # Feed configuration (URL, schedule, auth, filters)
```

**API Endpoints:**
- `GET /api/yara/rulesets` — List available rulesets with metadata
- `POST /api/yara/rulesets` — Create ruleset (name, description, source rules)
- `POST /api/yara/rulesets/{id}/compile` — Trigger compilation
- `GET /api/yara/rulesets/{id}/performance` — Match time stats, hit rates
- `POST /api/yara/rulesets/{id}/test` — Run against test corpus
- `POST /api/yara/feeds/sync` — Pull latest from configured feeds
- `POST /api/yara/rules/validate` — Syntax check before commit

**Features:**
- Incremental compilation (only changed rules)
- Parallel compilation worker pool
- Rule versioning with rollback
- False positive tracking (analyst feedback → rule tuning)
- Performance budgets (max N ms per file, auto-disable slow rules)
- Rule tagging (MITRE, platform, family, confidence)

---

### 3.3 Advanced IOC Extraction & Enrichment (`ioc_extraction_v2.py`)

**Extraction Enhancements:**
- **Passive DNS** — Extract domains from SSL certs (SAN), HTTP Host headers, DNS queries in PCAP
- **SSL Certificate Parsing** — Subject/Issuer DN, SANs, validity, public key algorithm, fingerprint (SHA256), self-signed detection, cert chain extraction from PKCS#7
- **DGA Detection** — Entropy-based, n-gram, ML classifier (character-level LSTM) for algorithmically generated domains
- **C2 Framework Fingerprints** — Cobalt Strike (malleable profile, watermark), Sliver (implant config), Mythic, Brute Ratel, PoshC2, Empire, Metasploit (stager signatures)
- **File Format IOCs** — Embedded PE/ELF/Mach-O/DEX in resources, overlays, archives
- **Registry/Filesystem Artifacts** — MITRE-mapped (Run keys, services, scheduled tasks, WMI, startup folder, browser extensions)
- **Memory IOCs** — Injected shellcode (RWX pages, unbacked memory), hollowed process (PEB mismatch), reflective loader stubs

**Enrichment Pipeline:**
```
Raw IOC → Type Classification → Context Extraction → 
  Passive DNS (local cache) → 
  Threat Intel Lookup (VT, OTX, MISP, custom) → 
  MITRE ATT&CK Mapping → 
  Confidence Scoring → 
  Correlation (sample-to-sample, sample-to-campaign) → 
  Enriched IOC Store
```

**Output Formats:** STIX 2.1 (indicator, malware, campaign, intrusion-set), MISP JSON, CSV, OpenIOC

---

### 3.4 Crypto & Obfuscation Detection (`crypto_detector.py`, `obfuscation_detector.py`)

**Crypto Detection:**
- **Algorithm Constants** — AES (S-box, T-tables, round constants), DES/3DES (S-boxes, IP/FP), RC4 (KSA/PRGA patterns), ChaCha20 (sigma constants), Salsa20, Rabbit, Blowfish (P-array, S-boxes), Twofish, Camellia, SM4
- **Asymmetric** — RSA (modulus size, public exponent 65537/3), ECC (curve parameters: secp256r1, secp384r1, secp256k1, Curve25519), Diffie-Hellman (group parameters)
- **Hash** — MD5 (initialization vector), SHA1/256/512 (IVs), SHA3/Keccak (round constants), BLAKE2/3
- **Custom/Proprietary** — XOR loops (key length detection), rolling XOR, RC4 variants, TEA/XTEA/XXTEA constants
- **Key Extraction** — Hardcoded keys in .data/.rdata, stack strings, imported from config resources, derived from static seeds

**Obfuscation Detection:**
- **Control Flow** — Opaque predicates (always-true/false conditions), flattened CFG (dispatcher loop), overlapping instructions, junk code insertion
- **VM Packers** — VMProtect (handler table, custom bytecode), Themida (VM entry, mutation), Enigma Protector, CodeVirtualizer, custom VMs
- **String Encryption** — Per-string keys, runtime decryption stubs, stack strings, heap strings
- **API Hashing** — Common hash algorithms (DJB2, FNV, CRC32, custom rotate-XOR), resolution stubs
- **Import Obfuscation** — Delay load, manual `GetProcAddress`/`LoadLibrary`, syscall direct (Hell's Gate, Halos Gate)
- **Anti-Analysis** — Timing checks (RDTSC, QueryPerformanceCounter), CPUID, hardware breakpoints (DR registers), `NtGlobalFlag`, `BeingDebugged`, heap flags, `IsDebuggerPresent`/`CheckRemoteDebuggerPresent`/`NtQueryInformationProcess`, VM artifacts (CPUID hypervisor bit, MAC OUI, disk/PCI devices), sandbox evasion (mouse movement, user interaction, sleep acceleration)

---

### 3.5 CAPEv2 Deep Integration (`sandbox_deep_integration.py`)

**Extended CAPEv2 Client:**
- **Task Submission** — Profile selection (OS, architecture, network mode: routed/isolated/INetSim/FakeNet), timeout, priority, tags, custom options (memory dump, process dump, network capture, API monitor)
- **Memory Analysis** — Volatility3 plugin integration: `windows.pslist`, `windows.pstree`, `windows.dlllist`, `windows.handles`, `windows.malfind`, `windows.hollowfind`, `windows.cmdline`, `windows.svcscan`, `windows.driverirp`, `windows.etwtamper`, `windows.ldrmodules`, `windows.apihooks`, `windows.ssdt`
- **API Monitor** — Full call trace with arguments (serialized), return values, timing; filter by module/category
- **Behavioral MITRE Mapping** — CAPEv2 signatures → MITRE ATT&CK techniques (T1055, T1027, T1547, etc.), tactic aggregation
- **Dropped File Extraction** — Auto-submit to static analysis pipeline, correlation with parent sample
- **Process Tree** — Parent-child relationships, command lines, integrity levels, token elevation
- **Network IOC Correlation** — PCAP → static IOC match (C2 IPs/domains in binary strings), JA3 fingerprinting
- **Artifacts** — Screenshots (timeline), memory dumps (full/process), registry hives, file system changes, WMI repository

**Orchestrator Enhancements:**
- Multi-profile detonation (Windows 10/11 x64, Ubuntu 22.04/24.04, Android 13/14, macOS on Apple Silicon)
- Retry logic with exponential backoff
- Resource quotas (concurrent VMs per profile)
- Result caching (hash-based deduplication)

---

### 3.6 Network Forensics Enhancement (`network_forensics_v2.py`)

**PCAP Analysis Extensions:**
- **JA3/JA3S** — TLS client/server fingerprinting, fingerprint database (malware families, legitimate software)
- **TLS Certificate Extraction** — Full chain, validation (expiry, self-signed, hostname mismatch, weak key, deprecated algorithm), cert pinning detection
- **DGA Classification** — ML model (character LSTM + n-gram features) trained on Alexa top 1M + known DGA families (Necurs, Gameover ZeuS, Conficker, Matsnu, Rovnix, Suppobox, Tinba, Pykspa, Symmi, Kraken, Gozi)
- **C2 Protocol Parsers** — HTTP (GET/POST, headers, body), DNS (TXT, A, AAAA, CNAME, NULL), HTTPS (SNI, cert), custom TCP/UDP (length-prefixed, delimiter, protobuf), ICMP, QUIC
- **Beaconing Statistics** — Coefficient of variation, jitter analysis, periodicity detection (FFT, autocorrelation), burst detection
- **Traffic Anomaly Detection** — Long connections, high entropy payloads, non-standard ports, protocol violations, data exfiltration patterns (large uploads, DNS tunneling)
- **Encrypted Traffic Analysis** — SNI extraction, certificate fingerprinting, ALPN, cipher suite fingerprinting, TLS version distribution
- **Protocol Identification** — DPI-based (Zeek-style), statistical (port-independent)

**Output:** Network report with flows, IOCs, anomalies, MITRE-mapped behaviors, PCAP slices for analyst review

---

### 3.7 Threat Intelligence Platform (`threat_intel_platform.py`)

**STIX/TAXII 2.1 Server:**
- **Collections** — Indicators, Malware, Campaigns, Intrusion-Sets, Threat-Actors, Tools, Reports, Courses-of-Action, Identities, Vulnerabilities
- **Discovery/Manifest/Objects Endpoints** — Full TAXII compliance
- **Authentication** — API keys, OAuth2, mTLS

**MISP Synchronization:**
- **Push** — Publish MALINFO indicators/samples to MISP (tagged, tagged with MALINFO metadata)
- **Pull** — Scheduled sync of MISP events/attributes → MALINFO IOC store
- **Bidirectional** — Conflict resolution (last-write-wins with audit), attribute proposal workflow

**Actor/Campaign Profiling:**
- **Actor Dossier** — Aliases, motivation, sophistication, origin, target sectors, known tools/malware, infrastructure (IPs, domains, ASNs, hosting), TTPs (ATT&CK heatmap), associated campaigns
- **Campaign Tracking** — Timeline, victims, infrastructure overlap, malware families used, attribution confidence

**ATT&CK Navigator Integration:**
- Layer generation (JSON) for: sample behaviors, actor TTPs, campaign TTPs, defensive coverage gaps
- Export to ATT&CK Navigator web/UI

**Feed Management:**
- Commercial (VT, OTX, AbuseIPDB, AlienVault, IBM X-Force, CrowdStrike, FireEye, Recorded Future)
- Open (Abuse.ch URLhaus/SSLBL/FeodoTracker, Spamhaus, Emerging Threats, Cisco Talos, Microsoft Threat Intel)
- Custom (internal MISP, ISAC/ISAO feeds, vendor-specific)
- Scheduling, deduplication, scoring, aging (indicator half-life)

---

### 3.8 Professional Reporting System (`reporting_pro.py`)

**Report Types:**
1. **Executive Summary** — 1-2 pages: verdict, risk score, business impact, key IOCs, recommended actions, no technical jargon
2. **Technical Deep-Dive** — Full static/dynamic/network analysis, evidence, methodology, MITRE mapping, analyst notes
3. **MITRE ATT&CK Matrix** — Technique coverage heatmap, tactic summary, detection/mitigation gaps
4. **Kill Chain Timeline** — Lockheed Martin / MITRE ATT&CK kill chain phases with timestamps, artifacts, analyst annotations
5. **IOC Package** — STIX 2.1 bundle, MISP event, CSV (type, value, confidence, context, tags, source, first_seen, last_seen)
6. **Evidence Appendix** — File hashes, YARA matches, strings, imports, sections, network flows, sandbox signatures, screenshots

**Features:**
- Jinja2 templates with custom filters
- Analyst annotations (rich text, inline evidence references)
- Digital signature (PAdES-LTV for PDF)
- Multi-format export (HTML, PDF, DOCX, Markdown, JSON)
- Custom branding (logo, classification markings: TLP, classification level)
- Redaction support (classified IOCs, PII)
- Version control (report revisions, diff view)

---

### 3.9 Decompiler Integration (`decompiler_integration.py`)

**Ghidra Headless API:**
- **Project Management** — Create/import binary, analyze (auto-analysis with configurable options)
- **Function Analysis** — List functions (address, name, signature, calling convention, stack frame, body), decompile (pseudocode C), xrefs (callers/callees, data refs)
- **String Analysis** — Defined strings (ASCII, Unicode, UTF-8, C-style), string xrefs
- **Type System** — Structures, unions, enums, typedefs from PDB/DWARF/symbols
- **Scripting** — Run custom Ghidra scripts (Python/Java), batch analysis
- **Export** — Function list (CSV/JSON), call graph (GraphML/DOT), decompilation (per-function or full), type archive (GDT)

**Retdec Fallback:**
- For architectures Ghidra doesn't support well or when Ghidra unavailable
- Raw decompilation → C-like pseudocode
- Function boundary detection

**FLIRT Signatures:**
- Microsoft Visual Studio (various versions)
- GCC/Clang standard libraries
- Common third-party (OpenSSL, libcurl, Boost, Qt, etc.)
- Custom signature generation from known-good binaries

**Integration Points:**
- Static analysis pipeline: auto-run on PE/ELF/Mach-O > 100KB
- Analyst UI: "Open in Decompiler" button per function
- Report: Include key function decompilations
- API: `POST /api/decompiler/analyze` → async task, poll for results

---

### 3.10 Platform Hardening & Operations

**Multi-Tenancy:**
- **Organizations** — Isolated data (samples, reports, users, rulesets, API keys)
- **Cases/Investigations** — Group samples, reports, IOCs, notes, timeline
- **Cross-org Sharing** — Controlled (read-only IOC sharing, report sharing)

**Air-Gap Deployment Mode:**
- **Offline Updates** — Signed update bundles (SBOM, cosign verification), air-gap transfer via removable media
- **Feed Synchronization** — Export/import threat intel feeds (MISP, STIX bundles)
- **Model Updates** — ML model artifacts (DGA, crypto, obfuscation) as signed bundles
- **Ruleset Updates** — YARA rulesets as versioned, signed packages

**High Availability / Disaster Recovery:**
- **Active-Passive** — PostgreSQL streaming replication, Redis sentinel, shared storage (NFS/GlusterFS)
- **Backup** — Automated (pg_dump, Redis RDB, file storage), encryption, integrity verification, restore testing
- **Failover** — Health checks, automatic promotion, DNS/VIP update

**Secrets & Crypto:**
- **Secrets Rotation** — Automated (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, CyberArk), manual CLI
- **FIPS 140-2** — OpenSSL FIPS provider, Bouncy Castle FIPS, Go crypto/fips140
- **TLS Everywhere** — mTLS between services, certificate rotation (cert-manager, Let's Encrypt/internal CA)

**Supply Chain:**
- **SBOM** — CycloneDX/SPDX for all containers and Python packages (`cyclonedx-python`, `syft`)
- **SLSA Level 3** — Provenance attestations, hermetic builds, reproducible builds
- **Image Signing** — cosign/keyless, policy enforcement (Kyverno, Gatekeeper)
- **Dependency Scanning** — Trivy, Grype, OSV-Scanner in CI/CD

**Observability:**
- **Metrics** — Prometheus (analysis throughput, queue depth, error rates, resource utilization, business KPIs)
- **Logging** — Structured JSON (OpenTelemetry), correlation IDs, audit trail
- **Tracing** — OpenTelemetry (Jaeger/Tempo), distributed traces across API, workers, sandbox
- **Alerting** — Alertmanager (PagersDuty, Opsgenie, email, Slack, Teams, webhook)

---

## 4. Implementation Priority (Phased)

### Phase 1: Core Analysis Depth (Weeks 1-4)
1. PE Deep Analysis (rich headers, certs, TLS, COM, delay-load, CLR, resources, debug, overlay, imphash)
2. ELF Deep Analysis (hardening flags, RPATH, version info, build ID, GO/Rust)
3. Mach-O Deep Analysis (codesign, entitlements, dyld, universal, hardened runtime)
4. APK Deep Analysis (cert chain v1-v4, network config, manifest hardening, embedded payloads)
5. Office Document Analysis (OLE, OOXML, RTF, PDF)
6. Script Analysis (PowerShell, Batch, JS/VBS, Python, Shell)

### Phase 2: Intelligence & Detection (Weeks 5-8)
7. YARA Rule Management System (feeds, compilation, versioning, testing, performance)
8. Advanced IOC Extraction & Enrichment (passive DNS, SSL certs, DGA, C2 fingerprints, MITRE)
9. Crypto Detection (constants, keys, per-section entropy, carving)
10. Obfuscation Detection (CFG, VM packs, string encryption, API hashing, anti-analysis)
11. CAPEv2 Deep Integration (Volatility3, API monitor, MITRE mapping, dropped files)
12. Network Forensics Enhancement (JA3, TLS certs, DGA ML, C2 parsers, beaconing stats, encrypted traffic)

### Phase 3: Threat Intel & Reporting (Weeks 9-12)
13. Threat Intel Platform (STIX/TAXII server, MISP sync, actor profiling, ATT&CK Navigator)
14. Professional Reporting (executive, technical, MITRE matrix, kill chain, IOC packages, evidence)
15. Decompiler Integration (Ghidra headless, retdec, FLIRT, function analysis, export)

### Phase 4: Platform Hardening (Weeks 13-16)
16. Multi-tenancy (orgs, cases, sharing)
17. Air-gap deployment mode (offline updates, signed bundles)
18. HA/DR (replication, backup, failover)
19. Secrets rotation, FIPS 140-2, TLS everywhere
20. Supply chain (SBOM, SLSA, signing, scanning)
21. Observability (metrics, logs, traces, alerts)

### Phase 5: Testing & Delivery (Weeks 17-20)
22. Integration testing with real malware corpus (malwarebazaar, VT, internal)
23. Performance benchmarking (throughput, latency, resource usage)
24. Security assessment (penetration test, code review, dependency audit)
25. Documentation (deployment, operations, API, analyst guide, admin guide)
26. Training materials (video, hands-on labs)
27. Delivery package (signed containers, SBOM, checksums, installation media)

---

## 5. Technical Standards & Conventions

### Code Quality
- **Type Hints** — 100% coverage (mypy strict)
- **Documentation** — Google-style docstrings, module-level overview
- **Testing** — Unit (pytest, >90% coverage), integration (testcontainers), property-based (hypothesis)
- **Security** — Bandit, semgrep, dependabot, SLSA provenance
- **Performance** — Benchmarks in CI (pytest-benchmark), regression detection

### Architecture
- **Async-First** — asyncio throughout, no blocking I/O in request path
- **Worker Pattern** — Celery/Redis or custom async task queue for long-running analysis
- **Plugin System** — Analysis modules as plugins (entry points), hot-reloadable
- **Configuration** — Pydantic Settings, environment-specific, secrets via Vault
- **Database** — SQLAlchemy 2.0 async, Alembic migrations, PostgreSQL 16+ (partitioning for large tables)

### API Design
- **OpenAPI 3.1** — Full spec, examples, error schemas
- **Versioning** — URL path (`/api/v1/`, `/api/v2/`), header-based deprecation
- **Pagination** — Cursor-based for large collections
- **Filtering/Sorting** — Standardized query parameters
- **Rate Limiting** — Token bucket per API key/user, configurable tiers
- **Webhooks** — Async callbacks for long operations (analysis complete, sandbox done)

### Frontend (Analyst Console)
- **Framework** — React 18 + TypeScript + Vite (or keep vanilla ES modules if preferred)
- **State** — TanStack Query + Zustand
- **UI** — Tailwind CSS + Headless UI / Radix UI
- **Real-time** — WebSocket (analysis progress, sandbox updates, monitoring alerts)
- **Visualization** — Mermaid (graphs), Cytoscape.js (process trees, call graphs), Chart.js (metrics), Monaco Editor (YARA, scripts, reports)

---

## 6. Delivery Artifacts

| Artifact | Format | Description |
|----------|--------|-------------|
| **Platform Containers** | OCI (Docker) | `malinfo-backend`, `malinfo-frontend`, `malinfo-icap`, `malinfo-monitor`, `malinfo-worker`, `malinfo-decompiler` |
| **Helm Charts** | YAML | Kubernetes deployment (production, HA, air-gap) |
| **Systemd Units** | .service | Bare-metal/VM deployment |
| **SBOM** | CycloneDX JSON | Per container, per Python environment |
| **Provenance** | SLSA in-toto | Build attestations |
| **Checksums** | SHA256SUMS | All delivery artifacts, cosign signed |
| **Documentation** | Markdown/PDF | Deployment, operations, API, analyst, admin |
| **Test Corpus** | Encrypted archive | Benign + malware samples for validation (separate delivery) |
| **Training** | Video + Labs | Analyst onboarding, advanced workflows |

---

## 7. Acceptance Criteria (Government Delivery)

### Functional
- [ ] Analyze 1000 samples/day on 8-core/32GB reference hardware
- [ ] Static analysis < 30s for typical PE (1-10MB)
- [ ] Dynamic analysis (CAPEv2) < 5 min typical, < 15 max
- [ ] YARA scanning < 5s for 50K rules on 10MB file
- [ ] Network PCAP analysis < 60s for 100MB capture
- [ ] Report generation < 10s for technical deep-dive
- [ ] Decompilation (Ghidra) < 60s for typical binary
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

## 8. Risk Register

| Risk | Impact | Likelihood | Mitigation |
|------|--------|------------|------------|
| Ghidra headless instability | High | Medium | Retdec fallback, process isolation, timeout/retry |
| CAPEv2 version compatibility | High | Medium | Pin CAPEv2 version, integration test matrix, vendor support |
| ML model false positives (DGA/crypto) | Medium | High | Analyst feedback loop, confidence thresholds, human-in-the-loop |
| YARA rule performance regression | Medium | Medium | Compilation benchmarks, per-rule budgets, auto-disable |
| Air-gap update complexity | High | Low | Automated bundle generation, validation scripts, dry-run mode |
| Multi-tenancy data isolation bug | Critical | Low | Row-level security (PostgreSQL RLS), integration tests, audit |
| Supply chain compromise | Critical | Low | SLSA L3, reproducible builds, signature verification, SBOM scanning |

---

## 9. Team & Resources

| Role | Allocation | Skills |
|------|------------|--------|
| Lead Architect | 1.0 FTE | Systems design, security, Python, Go, Kubernetes |
| Backend Engineers | 3.0 FTE | FastAPI, SQLAlchemy, asyncio, reverse engineering, malware analysis |
| Frontend Engineer | 1.0 FTE | React/TypeScript, data visualization, real-time UX |
| Malware Analyst (SME) | 1.0 FTE | Static/dynamic analysis, YARA, CAPEv2, MITRE, threat intel |
| DevOps/SRE | 1.0 FTE | Kubernetes, CI/CD, observability, security hardening, air-gap |
| QA/Integration | 1.0 FTE | Test automation, malware corpus, performance, security testing |
| Technical Writer | 0.5 FTE | Documentation, training, runbooks, API specs |

---

## 10. Sign-Off

| Role | Name | Signature | Date |
|------|------|-----------|------|
| Program Manager | | | |
| Lead Architect | | | |
| Security Officer | | | |
| Customer Representative | | | |

---

*This specification is a living document. Updates tracked via git history and change log.*