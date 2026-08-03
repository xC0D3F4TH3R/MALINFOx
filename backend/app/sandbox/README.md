# Dynamic Sandbox Infrastructure — What's Actually Required

MALINFO's `capev2_client.py` and `orchestrator.py` are real, working
integration code. What they integrate *with* — an actual detonation
cluster with real VMs — is infrastructure, not something a chat session
can generate for you. Here's exactly what stands between "code" and
"a working sandbox," per target OS, so you can plan procurement honestly.

## Windows & Linux (achievable, well-trodden path)

1. Deploy **CAPEv2** (`github.com/kevoreilly/CAPEv2`, actively maintained
   fork of Cuckoo Sandbox) on a Linux controller host.
2. Provision a hypervisor (KVM/QEMU recommended over VirtualBox for
   production) with:
   - A clean Windows 10/11 guest VM, agent installed, snapshotted.
   - A clean Ubuntu/Debian guest VM, agent installed, snapshotted.
3. **Critical safety requirement**: the guest VMs' network must NOT have
   direct unrestricted internet egress. Use **INetSim** or **FakeNet-NG**
   to simulate DNS/HTTP/HTTPS/SMTP responses, OR route through a tightly
   firewalled, heavily logged egress path if you deliberately want to
   observe real C2 callbacks (only do this with legal sign-off and strict
   containment — a live C2 channel from your sandbox is a real compromise
   vector if it escapes).
4. Point `SANDBOX_API_URL` in `.env` at the CAPEv2 controller and set
   `SANDBOX_ENABLED=true`.
5. Each analysis submitted through MALINFO's `/api/sandbox/submit`
   endpoint reverts the VM to a clean snapshot after every run — CAPEv2
   handles this automatically.

**Effort estimate for a competent infra team:** 1–3 weeks for a hardened
pilot cluster (2-4 VMs), assuming hardware/cloud capacity is already
available.

## Android

Same CAPEv2 controller, using its Android/Xen or `droidbox`-style module,
or a dedicated **Android emulator (AVD) farm** with Frida-based
instrumentation for API-call tracing. Genymotion or the standard Android
Emulator both work; snapshot-and-revert the same way as the desktop VMs.

## macOS — hard legal constraint, not a technical one

Apple's macOS Software License Agreement restricts running macOS in a
virtual machine to **Apple-branded hardware** (i.e., you need real Mac
mini/Studio hosts, e.g. via `Apple Virtualization.framework` or a
provider like AWS EC2 Mac / MacStadium). You cannot legally run macOS
guests on commodity x86 cloud VMs for this purpose. Budget for physical
or Apple-cloud Mac hosts if macOS detonation is a hard requirement.

## iOS — not achievable as "run any file and watch it"

There is no general-purpose dynamic sandbox for arbitrary iOS apps/files
the way there is for Windows/Linux/Android, because:
- iOS enforces app sandboxing and code-signing at the OS level — you
  cannot simply "run" an arbitrary unsigned binary the way you can on
  Windows/Linux.
- Meaningful dynamic iOS malware analysis in industry practice relies on
  **jailbroken device farms** (e.g., Corellium, or physical jailbroken
  iPhones) with Frida/objection instrumentation — this is a specialized,
  expensive, and legally/contractually delicate capability (Corellium's
  own legal history with Apple is instructive here).
- **Recommendation:** treat iOS submissions as **static-analysis-only**
  (IPA structure, Info.plist, entitlements, embedded URLs/domains — all
  of which MALINFO's static pipeline can be extended to parse) and route
  anything suspicious to manual specialist review rather than promising
  automated detonation.

## What MALINFO does today without a sandbox cluster

Every static-analysis feature (hashing, PE/ELF/APK/Mach-O parsing,
entropy, YARA, IOC extraction, risk scoring) works standalone, right now,
with zero additional infrastructure. Dynamic detonation is additive —
wire it in once the above is provisioned. The pipeline is written so that
`SANDBOX_ENABLED=false` (the default) simply skips this stage cleanly
rather than failing.
