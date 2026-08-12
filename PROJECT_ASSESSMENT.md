# MALINFO — Comprehensive Project Assessment & Improvement Roadmap

Generated: 2026-08-12

---

## Executive Summary

MALINFO is an **exceptionally well-architected government-grade malware analysis platform** with:
- **30+ static analysis modules** covering PE/ELF/Mach-O/APK/Office/Scripts/Archives/Firmware/Memory/Disk/Images/Fonts/Configs/Databases/Logs/Crypto/Windows Forensics/Apple bundles
- **Custom VM Orchestrator** using libvirt/QEMU with virtio-serial guest agent communication
- **Real-time WebSocket updates** for live analysis monitoring
- **Production-ready deployment** via Docker Compose, Kubernetes, systemd, and Oracle Cloud Free Tier
- **Agency notification system** with formal government email formatting
- **Comprehensive monitoring** (Prometheus/Grafana) and security hardening

---

## Detailed Improvement Recommendations

| # | Category | Component | Current State | Gap / Issue | Recommended Enhancement | Priority | Effort |
|---|----------|-----------|---------------|-------------|------------------------|----------|--------|
| **1** | **Dynamic Analysis** | VM Orchestrator - Template Building | Simulated (`await asyncio.sleep(5)`) | **Critical**: Template building is a placeholder — no actual OS installation, guest agent deployment, or snapshot creation | **Implement real template builder**: <br>• Use `virt-install --location <iso> --extra-args "ks=<kickstart>"` for unattended Windows/Linux install<br>• Deploy guest agent via SSH/WinRM post-install<br>• Create clean snapshot after agent verification<br>• Add progress tracking via VNC/spice | **P0 - Critical** | High |
| **2** | **Dynamic Analysis** | VM Orchestrator - Guest Agent Connection | Simulated (`time.time() - start > SIMULATED_AGENT_READY_TIME`) | **Critical**: Agent connection waits on fake timeout — no actual virtio-serial socket connection logic | **Implement real virtio-serial connection**: <br>• Connect to `/tmp/malinfo-agent-{task_id}.sock` Unix socket from host<br>• Implement message framing (newline-delimited JSON)<br>• Add hello/handshake protocol<br>• Handle connection failures gracefully | **P0 - Critical** | High |
| **3** | **Dynamic Analysis** | VM Orchestrator - Sample Injection | Stub (`async def _inject_sample: pass`) | **Critical**: No mechanism to copy sample into VM and trigger execution via agent | **Implement sample injection**: <br>• Base64-encode sample, send via agent channel<br>• Agent writes to `C:\Analysis\sample.exe` (Windows) or `/tmp/sample` (Linux)<br>• Agent executes and returns PID<br>• Track execution state via agent | **P0 - Critical** | High |
| **4** | **Dynamic Analysis** | VM Orchestrator - Execution Monitoring | Simulated loop with `time.sleep(5)` | **Critical**: No real event collection from guest agent | **Implement real event pipeline**: <br>• Agent sends batched events via Unix socket<br>• Orchestrator parses and stores process/API/file/network/registry events<br>• Map events to MITRE ATT&CK techniques in real-time<br>• Update WebSocket clients with live data | **P0 - Critical** | High |
| **5** | **Dynamic Analysis** | VM Orchestrator - Results Collection | Stub (`async def _collect_results: pass`) | **Critical**: No screenshot capture, memory dump, PCAP retrieval, or dropped file collection | **Implement collection**: <br>• Request screenshots via agent → save as PNG<br>• Trigger memory dump via agent (procdump/gcore) → pull via SSH/WinRM<br>• Capture PCAP from isolated network bridge<br>• Pull dropped files from VM's analysis directory | **P0 - Critical** | High |
| **6** | **Dynamic Analysis** | Guest Agent - API Monitoring | Simulation only (`while running: time.sleep(5)`) | **High**: ETW (Windows) and ptrace (Linux) implementations are placeholders | **Implement real API monitoring**: <br>• **Windows**: Use `python-etw` for kernel ETW tracing of Nt* APIs, or inject DLL via `CreateRemoteThread` for user-mode hooking<br>• **Linux**: Use `bpftrace`/`bcc` eBPF programs for syscall tracing, or `frida` for user-mode hooking<br>• Filter by monitored PIDs only to reduce overhead | **P1 - High** | High |
| **7** | **Dynamic Analysis** | Guest Agent - File Monitoring | `pyinotify` (Linux) + polling fallback (Windows) | **Medium**: Windows lacks native FS monitoring (FSRM/USN Journal not implemented) | **Enhance Windows file monitoring**: <br>• Implement USN Journal parsing via `win32file.ReadDirectoryChangesW`<br>• Or use `sysinternals`-style filter driver (complex)<br>• Add recursive directory watching with exclude patterns | **P2 - Medium** | Medium |
| **8** | **Dynamic Analysis** | Guest Agent - Screenshot Capture | `ImageMagick import` / `gnome-screenshot` (Linux) | **Medium**: Linux capture depends on X11 tools not always present; no Wayland support | **Improve screenshot capture**: <br>• Use `mss` (Python) for cross-platform capture<br>• Add Wayland support via `wlr-screencopy` / `pipewire`<br>• Compress screenshots (WebP) before transmission | **P2 - Medium** | Low |
| **9** | **Dynamic Analysis** | Guest Agent - Memory Dump | Stub only | **High**: No memory dump implementation | **Implement memory dump**: <br>• **Windows**: `procdump.exe -ma <pid>` or `comsvcs.dll` MiniDumpWriteDump<br>• **Linux**: `gcore <pid>` or `/proc/<pid>/mem` read<br>• Compress and stream to host | **P1 - High** | Medium |
| **10** | **Dynamic Analysis** | Guest Agent - Network Capture | None (PCAP expected from host) | **Medium**: No in-VM PCAP; relies on host bridge capture | **Add in-VM PCAP option**: <br>• Use `tcpdump`/`tshark` inside VM<br>• Or Windows `netsh trace start capture=yes`<br>• Correlate with process IDs | **P2 - Medium** | Medium |
| **11** | **Static Analysis** | Pipeline - YARA Performance | Single-threaded scan | **Medium**: Large rule sets (50K+) take >5s on 10MB files | **Optimize YARA**: <br>• Pre-compile rules to binary format (`yara -c`)<br>• Parallel scan with `multiprocessing.Pool`<br>• Add rule indexing by file type<br>• Cache compiled rules in Redis | **P2 - Medium** | Medium |
| **12** | **Static Analysis** | Pipeline - String Extraction | Loads entire file into memory for strings | **Medium**: Large files (500MB+) cause OOM | **Stream string extraction**: <br>• Process in chunks with overlap<br>• Use `strings` binary via subprocess for speed<br>• Limit extracted strings to top N per file type | **P2 - Medium** | Low |
| **13** | **Static Analysis** | Format Coverage | 25+ format handlers | **Low**: Missing handlers for: Office Open XML macros (VBA), RTF objects, OneNote, Visio, CAD, binary firmware (UEFI capsules), Android DEX (separate from APK) | **Add format handlers**: <br>• `olevba` for VBA macro extraction<br>• `rtfobj` for RTF embedded objects<br>• `uefi-firmware-parser` for UEFI capsules<br>• `dexlib2` for DEX analysis | **P3 - Low** | Medium |
| **14** | **Threat Intel** | Integration | Basic lookups (VT, OTX, AbuseIPDB, MISP) | **Medium**: No STIX/TAXII 2.1 server implementation; no ATT&CK Navigator layer export | **Enhance threat intel**: <br>• Implement TAXII 2.1 server for feed sharing<br>• Export MITRE ATT&CK Navigator JSON layers<br>• Add threat actor/campaign correlation engine<br>• Implement STIX 2.1 bundle generation for reports | **P2 - Medium** | High |
| **15** | **Frontend** | Architecture | Vanilla ES modules, manual routing | **Medium**: No framework; state management ad-hoc; no TypeScript; testing difficult | **Modernize frontend**: <br>• Migrate to **React 18 + TypeScript + Vite**<br>• Use **TanStack Query** for server state<br>• **Zustand** for client state<br>• **React Router v6** for routing<br>• **Tailwind CSS** for styling (keep design system)<br>• Add **Storybook** for component docs<br>• **Vitest + Playwright** for testing | **P1 - High** | Very High |
| **16** | **Frontend** | Real-time Updates | Single WebSocket for all events | **Medium**: No message prioritization; no reconnection state sync; no offline queue | **Improve WebSocket**: <br>• Use **Socket.io** or **SignalR** for auto-reconnect, rooms, ack<br>• Implement event prioritization (critical vs bulk)<br>• Add client-side event buffer for reconnection replay<br>• Support multiple concurrent task subscriptions | **P2 - Medium** | Medium |
| **17** | **Frontend** | Dashboard / Visualizations | Basic stat cards | **Low**: No interactive charts, timeline views, process tree graph, network graph, MITRE heatmap | **Add rich visualizations**: <br>• **Process tree**: D3.js force-directed graph<br>• **Timeline**: Visx/Recharts for event timeline<br>• **Network graph**: Cytoscape.js for C2 infrastructure<br>• **MITRE heatmap**: ATT&CK matrix with technique highlighting<br>• **MalScore gauge**: Animated radial gauge | **P2 - Medium** | High |
| **18** | **API** | Endpoints | 71 REST + 1 WS endpoints | **Medium**: No OpenAPI 3.1 spec generation; no GraphQL; no gRPC for high-throughput internal comms | **Enhance API**: <br>• Generate OpenAPI 3.1 spec from FastAPI (`fastapi.openapi()`)<br>• Add **GraphQL** endpoint (Strawberry) for flexible queries<br>• Add **gRPC** for sandbox-agent communication (protobuf)<br>• API versioning strategy (`/api/v1/`, `/api/v2/`) | **P2 - Medium** | Medium |
| **19** | **Database** | Schema | SQLAlchemy 2.0, PostgreSQL | **Medium**: No partitioning for large tables; no read replicas; no full-text search on IOCs | **Scale database**: <br>• Partition `iocs` table by `first_seen` (monthly)<br>• Add `pg_trgm` index on `iocs.value` for fuzzy search<br>• Implement read replica for reporting queries<br>• Add TimescaleDB for metrics/time-series | **P2 - Medium** | Medium |
| **20** | **Deployment** | Docker | Multi-stage builds, Compose profiles | **Medium**: No multi-arch builds (ARM64/AMD64); no SBOM in image; no signing | **Harden container images**: <br>• Use `docker buildx` for multi-arch manifests<br>• Generate SBOM (Syft) at build time<br>• Sign images with **cosign**/Sigstore<br>• Add **SLSA Level 3** provenance<br>• Distroless base images where possible | **P1 - High** | Medium |
| **21** | **Deployment** | Kubernetes | Manifests in `deploy/kubernetes/` | **Low**: No Helm chart; no Operators; no GitOps (ArgoCD/Flux) | **Add Kubernetes excellence**: <br>• Create **Helm chart** with values.yaml for all configs<br>• Add **Operator** for VM template lifecycle (CRD)<br>• GitOps with **ArgoCD** + Kustomize<br>• NetworkPolicies, PodSecurityStandards, ResourceQuotas | **P3 - Low** | High |
| **22** | **Security** | Auth | JWT + TOTP MFA + RBAC | **Medium**: No OAuth2/OIDC (Keycloak, Entra ID); no passkeys/WebAuthn; no device trust | **Enterprise auth**: <br>• Add **OIDC** integration (Keycloak, Azure AD, Okta)<br>• Implement **WebAuthn** (passkeys) for MFA<br>• Device fingerprinting + risk-based auth<br>• Session binding to IP/User-Agent | **P2 - Medium** | High |
| **23** | **Security** | Secrets | `.env` file | **High**: No secrets manager integration (Vault, AWS SM, Azure KV, GCP SM) | **Secrets management**: <br>• Add **HashiCorp Vault** agent injector<br>• Support **AWS Secrets Manager** / **Azure Key Vault**<br>• Automatic rotation for DB passwords, API keys<br>• Audit secret access | **P1 - High** | Medium |
| **24** | **Security** | Supply Chain | SBOM generation, Trivy scan | **Medium**: No SBOM signing; no VEX; no SLSA attestation in CI | **Supply chain hardening**: <br>• Sign SBOMs with cosign<br>• Generate **VEX** (Vulnerability Exploitability eXchange)<br>• **SLSA Level 3** GitHub Actions workflow<br>• **Scorecard** + **OpenSSF** best practices | **P2 - Medium** | Medium |
| **25** | **Observability** | Metrics | Prometheus + Grafana | **Medium**: No distributed tracing; no log aggregation (Loki); no SLO/SLI dashboards | **Full observability stack**: <br>• **Jaeger/Tempo** for distributed tracing<br>• **Grafana Loki** for log aggregation<br>• **SLO/SLI** dashboards (latency, error rate, availability)<br>• **Alertmanager** with PagerDuty/Slack/Email routes | **P2 - Medium** | High |
| **26** | **Observability** | Audit Logging | Tamper-evident append-only | **Medium**: No centralized audit log storage; no immutable write-once storage | **Audit log hardening**: <br>• Stream to **AWS CloudTrail** / **Azure Monitor** / **GCP Audit Logs**<br>• Write to **WORM storage** (S3 Object Lock, Azure Immutable Blob)<br>• Cryptographic chaining (hash chain) for tamper evidence | **P1 - High** | Medium |
| **27** | **Operational** | Backup/Restore | `pg_dump` + tar | **Medium**: No point-in-time recovery; no cross-region replication; no automated DR testing | **Enterprise backup**: <br>• **WAL-G** / **Barman** for PITR<br>• Cross-region replication (S3 CRR)<br>• Automated DR drills (monthly)<br>• RPO/RTO documentation | **P2 - Medium** | Medium |
| **28** | **Operational** | Case Management | None | **High**: No case/ticket system for analysts; no assignment, SLA tracking, evidence chain | **Add case management**: <br>• Cases linked to samples/reports<br>• Analyst assignment + workload balancing<br>• SLA timers (triage < 1h, analysis < 24h)<br>• Evidence chain of custody log<br>• Integration with **TheHive** / **Cortex** | **P1 - High** | High |
| **29** | **Operational** | YARA Rule Management | CLI sync from feeds | **Medium**: No rule testing UI; no version control; no false positive tracking | **YARA rule lifecycle**: <br>• Web UI for rule authoring + syntax check<br>• **Test corpus** with expected matches/non-matches<br>• Git-backed version history<br>• False positive tracking per rule<br>• Staging → production promotion | **P2 - Medium** | Medium |
| **30** | **Operational** | Public Reporting | 3 endpoints, basic | **Medium**: No CAPTCHA/rate limit hardening; no evidence upload; no status portal for reporters | **Hardened public portal**: <br>• **hCaptcha** / **Turnstile** integration<br>• Evidence file upload (drag-drop)<br>• Reporter tracking portal (tracking ID)<br>• Automated triage scoring<br>• Abuse reporting for false submissions | **P2 - Medium** | Medium |
| **31** | **AI/ML** | Intelligence | None | **Low**: No ML-assisted triage; no embedding-based similarity; no LLM report summarization | **AI augmentation**: <br>• **Embedding index** (Sentence-BERT) for sample similarity search<br>• **LLM** (local: Ollama/Llama.cpp) for report summarization<br>• **Auto-triage** classifier (static + dynamic features → verdict)<br>• **Behavior clustering** for campaign detection | **P3 - Low** | Very High |
| **32** | **Documentation** | User/Dev Docs | README + inline code | **Medium**: No API reference site; no architecture decision records (ADRs); no runbooks | **Documentation excellence**: <br>• **MkDocs Material** site with API reference (Redoc)<br>• **ADRs** in `docs/adr/` (MADR format)<br>• **Runbooks** for: deploy, backup, DR, incident response<br>• **Video demos** for key workflows | **P2 - Medium** | Medium |

---

## Quick Wins (Can be done in < 1 week each)

| # | Item | Description |
|---|------|-------------|
| QW1 | Fix `vm_orchestrator.py` template building | Replace `asyncio.sleep(5)` with real `virt-install` + kickstart/unattended.xml |
| QW2 | Implement guest agent Unix socket connection | Connect to `/tmp/malinfo-agent-{task_id}.sock` from host orchestrator |
| QW3 | Add sample injection via agent channel | Base64 encode → send JSON → agent writes to disk → executes |
| QW4 | Add real-time event parsing in orchestrator | Parse agent events → store in task object → push via WebSocket |
| QW5 | Implement screenshot capture via agent | Agent captures → base64 → host saves PNG |
| QW6 | Add memory dump trigger | Agent runs `procdump`/`gcore` → host pulls file |
| QW7 | Migrate frontend to TypeScript + Vite (no framework) | Add `tsconfig.json`, `vite.config.ts`, rename `.js` → `.ts` |
| QW8 | Generate OpenAPI 3.1 spec from FastAPI | Add `/api/openapi.json` endpoint + Redoc UI |
| QW9 | Add multi-arch Docker builds | `docker buildx build --platform linux/amd64,linux/arm64` |
| QW10 | Integrate HashiCorp Vault for secrets | Vault Agent Injector sidecar in Docker Compose |

---

## Architecture Decision Records Needed

| ADR # | Title | Status | Decision Needed |
|-------|-------|--------|-----------------|
| ADR-001 | Dynamic Analysis: CAPEv2 vs Custom VM Orchestrator | **Proposed** | Commit to custom orchestrator (current) vs CAPEv2 integration |
| ADR-002 | Guest Agent Communication: virtio-serial vs vsock vs SSH | **Proposed** | virtio-serial (current) is best for isolation; document rationale |
| ADR-003 | Frontend Framework: Vanilla JS vs React vs Vue vs Svelte | **Proposed** | React + TS recommended for team scaling |
| ADR-004 | Database: PostgreSQL vs TimescaleDB vs CockroachDB | **Proposed** | PostgreSQL + Timescale extension for metrics |
| ADR-005 | Secrets: .env vs Vault vs Cloud Provider SM | **Proposed** | Vault for self-hosted; Cloud SM for managed |
| ADR-006 | Container Runtime: Docker vs Podman vs containerd | **Proposed** | Podman rootless for security; Docker for compatibility |
| ADR-007 | Orchestration: Docker Compose vs K8s vs Nomad | **Proposed** | Compose for single-node; K8s for HA; document migration path |
| ADR-008 | ML/AI: Local (Ollama) vs Cloud API vs Hybrid | **Proposed** | Local-only for air-gap; document model choices |

---

## Recommended Implementation Order (Phased)

### Phase 1: Dynamic Analysis Core (Weeks 1-4) — **P0 Critical**
1. Real VM template builder with unattended OS install
2. Guest agent virtio-serial connection & protocol
3. Sample injection & execution via agent
4. Real-time event collection (process, file, network, registry)
5. Results collection (screenshots, memory dump, PCAP, dropped files)
6. MITRE ATT&CK mapping from behavioral events

### Phase 2: Production Hardening (Weeks 5-8) — **P1 High**
7. Multi-arch Docker builds + SBOM signing + cosign
8. HashiCorp Vault / Cloud Secrets Manager integration
9. OIDC + WebAuthn authentication
10. Case management system (analyst workflow)
11. Audit log to WORM storage
12. Distributed tracing (Tempo/Jaeger) + Loki logs

### Phase 3: Frontend Modernization (Weeks 9-14) — **P1 High**
13. React 18 + TypeScript + Vite migration
14. TanStack Query + Zustand + React Router
15. Rich visualizations (process tree, timeline, network graph, MITRE heatmap)
16. Socket.io for robust real-time updates
17. Storybook + Vitest + Playwright test suite

### Phase 4: Intelligence & Scale (Weeks 15-20) — **P2 Medium**
18. TAXII 2.1 server + STIX 2.1 bundles
19. ATT&CK Navigator layer export
20. YARA rule lifecycle UI (author, test, version, promote)
21. GraphQL + gRPC APIs
22. Database partitioning + read replicas
23. Helm chart + ArgoCD GitOps
24. Public reporting portal hardening

### Phase 5: AI Augmentation (Weeks 21+) — **P3 Low**
25. Embedding-based sample similarity search
26. Local LLM (Ollama) for report summarization
27. Auto-triage classifier
28. Behavioral clustering for campaign detection

---

## Resource Estimates

| Phase | Duration | Engineers | Infra Cost (Oracle Free Tier) |
|-------|----------|-----------|-------------------------------|
| Phase 1 | 4 weeks | 2-3 | $0 (included) |
| Phase 2 | 4 weeks | 2 | $0 (Vault OSS) |
| Phase 3 | 6 weeks | 2-3 | $0 |
| Phase 4 | 6 weeks | 2 | $0 |
| Phase 5 | 4+ weeks | 1-2 | $0 (local Ollama) |
| **Total** | **~24 weeks** | **2-3 sustained** | **$0/month** |

---

## Risk Register

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| libvirt/QEMU not available on target deployment | Medium | High | Document KVM requirement; provide nested virt fallback; test on Oracle ARM |
| Guest agent development complexity (Windows ETW, Linux eBPF) | High | High | Start with polling-based MVP; incrementally add ETW/eBPF; use Frida as bridge |
| Frontend rewrite scope creep | Medium | Medium | Strict phase gates; deliver incremental value; keep vanilla JS as fallback |
| Air-gap deployment requirements | Low | High | Design all components for offline-first; vendor all dependencies; test in isolated lab |
| Performance at scale (1000 samples/day) | Medium | High | Load test early; profile static pipeline; add Redis caching; partition DB |
| Regulatory compliance (FIPS 140-2, data sovereignty) | Low | High | Use FIPS-validated crypto modules; document data flows; legal review |

---

## Success Metrics (KPIs)

| Metric | Target | Measurement |
|--------|--------|-------------|
| Static analysis throughput | ≥1000 samples/day (8-core/32GB) | Prometheus `malinfo_analysis_completed_total` |
| Static analysis latency (1-10MB PE) | <30s p95 | Prometheus `malinfo_analysis_duration_seconds` |
| Dynamic analysis latency (typical) | <5 min p95 | Task `completed_at - started_at` |
| YARA scan (50K rules, 10MB) | <5s | Benchmark script |
| API availability | 99.9% | Uptime monitor |
| Zero critical/high CVEs in prod images | 0 | Trivy daily scan |
| Analyst triage time | <5 min | Case management timestamps |
| Report generation | <10s | API latency histogram |
| Backup RPO | <1 hour | WAL-G / Barman |
| Backup RTO | <4 hours | DR drill results |

---

*This assessment is based on code review of the MALINFO codebase as of 2026-08-12. Priorities reflect government production deployment requirements.*