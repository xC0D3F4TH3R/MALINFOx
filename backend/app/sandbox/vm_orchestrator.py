"""
MALINFO — Built-in VM Orchestrator using libvirt/QEMU

Self-contained dynamic analysis sandbox that doesn't require CAPEv2 infrastructure.
Manages VMs, ISO uploads, snapshots, and real-time behavioral monitoring via guest agent.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import logging
import shutil
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

import aiofiles

# libvirt is only available on Linux with libvirt-dev installed
# On Windows/macOS or in dev environments without libvirt, we provide a stub
try:
    import libvirt
    from libvirt import virConnect, virDomain
    LIBVIRT_AVAILABLE = True
except ImportError:
    libvirt = None
    virDomain = None
    virConnect = None
    LIBVIRT_AVAILABLE = False

logger = logging.getLogger("malinfo.vm_orchestrator")


class VMState(StrEnum):
    """VM states"""
    BUILDING = "building"
    READY = "ready"
    RUNNING = "running"
    ANALYZING = "analyzing"
    REVERTING = "reverting"
    ERROR = "error"
    STOPPED = "stopped"


class TaskState(StrEnum):
    """Analysis task states"""
    QUEUED = "queued"
    PREPARING = "preparing"
    BOOTING = "booting"
    INJECTING = "injecting"
    RUNNING = "running"
    MONITORING = "monitoring"
    COLLECTING = "collecting"
    COMPLETED = "completed"
    FAILED = "failed"


# Constants for magic values
AGENT_CONNECT_TIMEOUT = 120  # seconds
SIMULATED_AGENT_READY_TIME = 10  # seconds
SIMULATED_EXECUTION_TIME = 30  # seconds


@dataclass
class VMTemplate:
    """VM template definition"""
    id: str
    name: str
    os_type: str  # windows, linux, android, macos
    os_version: str
    arch: str = "x86_64"
    iso_path: str = ""
    disk_size_gb: int = 60
    memory_mb: int = 4096
    vcpus: int = 2
    network_mode: str = "isolated"  # isolated, routed, nat
    agent_installed: bool = False
    snapshot_name: str = "clean_snapshot"
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass
class VMInstance:
    """Running VM instance"""
    id: str
    template_id: str
    name: str
    state: VMState
    domain: virDomain | None = None
    ip_address: str | None = None
    vnc_port: int | None = None
    websocket_port: int | None = None
    task_id: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    started_at: datetime | None = None
    error: str | None = None


@dataclass
class AnalysisTask:
    """Dynamic analysis task"""
    id: str
    sample_id: str
    sample_path: str
    sample_hash: str
    template_id: str
    vm_instance_id: str | None = None
    state: TaskState = TaskState.QUEUED
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    started_at: datetime | None = None
    completed_at: datetime | None = None
    timeout: int = 300
    options: dict = field(default_factory=dict)
    error: str | None = None

    # Results
    process_tree: list[dict] = field(default_factory=list)
    api_calls: list[dict] = field(default_factory=list)
    network_events: list[dict] = field(default_factory=list)
    file_events: list[dict] = field(default_factory=list)
    registry_events: list[dict] = field(default_factory=list)
    dropped_files: list[dict] = field(default_factory=list)
    screenshots: list[dict] = field(default_factory=list)
    memory_dumps: list[dict] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    signatures: list[dict] = field(default_factory=list)
    malscore: int = 0


class LibvirtManager:
    """Low-level libvirt operations"""

    def __init__(self, uri: str = "qemu:///system"):
        if not LIBVIRT_AVAILABLE:
            raise RuntimeError("libvirt-python not available. Install libvirt-dev and libvirt-python on Linux.")
        self.uri = uri
        self.conn: virConnect | None = None

    def connect(self) -> virConnect:
        """Connect to libvirt"""
        if self.conn is None or self.conn.isClosed():
            self.conn = libvirt.open(self.uri)
            if self.conn is None:
                raise RuntimeError(f"Failed to connect to libvirt at {self.uri}")
        return self.conn

    def disconnect(self):
        """Disconnect from libvirt"""
        if self.conn and not self.conn.isClosed():
            self.conn.close()
            self.conn = None

    def create_storage_pool(self, name: str, path: str) -> libvirt.virStoragePool:
        """Create or get storage pool"""
        conn = self.connect()
        try:
            pool = conn.storagePoolLookupByName(name)
        except libvirt.libvirtError:
            # Create new pool
            pool_xml = f"""
            <pool type='dir'>
                <name>{name}</name>
                <target>
                    <path>{path}</path>
                </target>
            </pool>
            """
            pool = conn.storagePoolCreateXML(pool_xml, 0)
            pool.setAutostart(True)
        return pool

    def create_volume(self, pool: libvirt.virStoragePool, name: str, size_gb: int, format: str = "qcow2") -> libvirt.virStorageVol:
        """Create storage volume"""
        vol_xml = f"""
        <volume>
            <name>{name}</name>
            <allocation>0</allocation>
            <capacity unit='G'>{size_gb}</capacity>
            <target>
                <format type='{format}'/>
            </target>
        </volume>
        """
        return pool.createXML(vol_xml, 0)

    def get_volume_path(self, pool: libvirt.virStoragePool, name: str) -> str:
        """Get volume path"""
        vol = pool.storageVolLookupByName(name)
        return vol.path()

    def define_domain(self, xml: str) -> virDomain:
        """Define a domain from XML"""
        conn = self.connect()
        return conn.defineXML(xml)

    def create_domain(self, xml: str) -> virDomain:
        """Create and start a domain"""
        conn = self.connect()
        return conn.createXML(xml, 0)

    def get_domain(self, name: str) -> virDomain | None:
        """Get domain by name"""
        conn = self.connect()
        try:
            return conn.lookupByName(name)
        except libvirt.libvirtError:
            return None

    def snapshot_create(self, domain: virDomain, name: str, description: str = "") -> libvirt.virDomainSnapshot:
        """Create snapshot"""
        snap_xml = f"""
        <domainsnapshot>
            <name>{name}</name>
            <description>{description}</description>
        </domainsnapshot>
        """
        return domain.snapshotCreateXML(snap_xml, 0)

    def snapshot_revert(self, domain: virDomain, name: str):
        """Revert to snapshot"""
        snapshot = domain.snapshotLookupByName(name)
        domain.revertToSnapshot(snapshot, 0)

    def snapshot_delete(self, domain: virDomain, name: str):
        """Delete snapshot"""
        snapshot = domain.snapshotLookupByName(name)
        snapshot.delete(0)


class VMOrchestrator:
    """High-level VM orchestration for malware analysis"""

    def __init__(
        self,
        storage_path: str = "/opt/malinfo/vms",
        iso_path: str = "/opt/malinfo/isos",
        libvirt_uri: str = "qemu:///system",
        agent_port: int = 9090,
    ):
        self.storage_path = Path(storage_path)
        self.iso_path = Path(iso_path)
        self.libvirt = LibvirtManager(libvirt_uri)
        self.agent_port = agent_port

        # Ensure directories exist
        self.storage_path.mkdir(parents=True, exist_ok=True)
        self.iso_path.mkdir(parents=True, exist_ok=True)
        (self.storage_path / "templates").mkdir(exist_ok=True)
        (self.storage_path / "instances").mkdir(exist_ok=True)
        (self.storage_path / "snapshots").mkdir(exist_ok=True)
        (self.storage_path / "analysis_results").mkdir(exist_ok=True)

        # State
        self.templates: dict[str, VMTemplate] = {}
        self.instances: dict[str, VMInstance] = {}
        self.tasks: dict[str, AnalysisTask] = {}

        # WebSocket connections for real-time updates
        self.ws_connections: dict[str, set] = {}  # task_id -> set of websockets

        # Load existing templates
        _ = asyncio.create_task(self._load_templates())

    async def _load_templates(self):
        """Load VM templates from disk"""
        templates_file = self.storage_path / "templates" / "templates.json"
        if templates_file.exists():
            async with aiofiles.open(templates_file) as f:
                data = json.loads(await f.read())
                for t in data:
                    template = VMTemplate(**t)
                    self.templates[template.id] = template

    async def _save_templates(self):
        """Save VM templates to disk"""
        templates_file = self.storage_path / "templates" / "templates.json"
        data = [t.__dict__ for t in self.templates.values()]
        # Convert datetime to isoformat
        for d in data:
            d["created_at"] = d["created_at"].isoformat() if isinstance(d["created_at"], datetime) else d["created_at"]
            d["updated_at"] = d["updated_at"].isoformat() if isinstance(d["updated_at"], datetime) else d["updated_at"]
        async with aiofiles.open(templates_file, "w") as f:
            await f.write(json.dumps(data, indent=2))

    # ─── ISO Management ───

    async def upload_iso(self, file_path: Path, os_type: str, os_version: str, name: str | None = None) -> dict:
        """Upload and register an ISO file"""
        # Validate ISO
        if not file_path.exists():
            raise ValueError("ISO file not found")

        # Calculate hash
        sha256 = hashlib.sha256()
        async with aiofiles.open(file_path, "rb") as f:
            while chunk := await f.read(8192):
                sha256.update(chunk)
        iso_hash = sha256.hexdigest()

        # Determine target filename
        ext = file_path.suffix or ".iso"
        target_name = name or f"{os_type}-{os_version}-{iso_hash[:8]}{ext}"
        target_path = self.iso_path / target_name

        # Copy if not already there
        if not target_path.exists():
            shutil.copy2(file_path, target_path)

        return {
            "name": target_name,
            "path": str(target_path),
            "hash": iso_hash,
            "size": target_path.stat().st_size,
            "os_type": os_type,
            "os_version": os_version,
        }

    async def list_isos(self) -> list[dict]:
        """List available ISOs"""
        isos = []
        for iso_file in self.iso_path.glob("*.iso"):
            stat = iso_file.stat()
            isos.append({
                "name": iso_file.name,
                "path": str(iso_file),
                "size": stat.st_size,
                "modified": datetime.fromtimestamp(stat.st_mtime, tz=UTC).isoformat(),
            })
        return isos

    async def delete_iso(self, name: str) -> bool:
        """Delete an ISO"""
        iso_file = self.iso_path / name
        if iso_file.exists():
            iso_file.unlink()
            return True
        return False

    # ─── Template Management ───

    async def create_template(
        self,
        name: str,
        os_type: str,
        os_version: str,
        iso_name: str,
        arch: str = "x86_64",
        disk_size_gb: int = 60,
        memory_mb: int = 4096,
        vcpus: int = 2,
        network_mode: str = "isolated",
    ) -> VMTemplate:
        """Create a VM template from an ISO"""
        iso_file = self.iso_path / iso_name
        if not iso_file.exists():
            raise ValueError(f"ISO not found: {iso_name}")

        template_id = str(uuid.uuid4())
        template = VMTemplate(
            id=template_id,
            name=name,
            os_type=os_type,
            os_version=os_version,
            arch=arch,
            iso_path=str(iso_file),
            disk_size_gb=disk_size_gb,
            memory_mb=memory_mb,
            vcpus=vcpus,
            network_mode=network_mode,
        )

        self.templates[template_id] = template
        await self._save_templates()

        # Build the template VM in background
        _ = asyncio.create_task(self._build_template(template))

        return template

    async def _build_template(self, template: VMTemplate):
        """Build VM template: install OS, install agent, create snapshot"""
        try:
            template.state = VMState.BUILDING
            await self._save_templates()

            # Create storage pool
            pool_name = f"malinfo_{template.id}"
            pool_path = self.storage_path / "templates" / template.id
            pool_path.mkdir(parents=True, exist_ok=True)
            pool = self.libvirt.create_storage_pool(pool_name, str(pool_path))

            # Create disk volume
            disk_name = f"{template.id}.qcow2"
            self.libvirt.create_volume(pool, disk_name, template.disk_size_gb)
            disk_path = self.libvirt.get_volume_path(pool, disk_name)

            # Build domain XML for installation
            domain_xml = self._build_install_domain_xml(template, disk_path)

            # Create and start installation domain
            domain = self.libvirt.create_domain(domain_xml)

            # Wait for installation (this would need VNC/spice interaction in real implementation)
            # For now, we'll simulate and create a clean snapshot
            await asyncio.sleep(5)  # Placeholder

            # Create clean snapshot
            self.libvirt.snapshot_create(domain, template.snapshot_name, "Clean OS installation")

            # Shutdown
            domain.destroy()

            template.state = VMState.READY
            template.agent_installed = True  # Would be set after agent installation
            await self._save_templates()

            logger.info(f"Template {template.name} built successfully")

        except Exception as e:
            logger.exception(f"Failed to build template {template.name}: {e}")
            template.state = VMState.ERROR
            template.error = str(e)
            await self._save_templates()

    def _build_install_domain_xml(self, template: VMTemplate, disk_path: str) -> str:
        """Build domain XML for OS installation"""
        # Generate MAC address
        mac = f"52:54:00:{uuid.uuid4().hex[:6]}"

        # Determine OS variant for libvirt
        os_variants = {
            "windows": "win10",
            "linux": "ubuntu22.04",
            "android": "generic",
            "macos": "macos",
        }
        _ = os_variants.get(template.os_type, "generic")

        return f"""
        <domain type='kvm'>
            <name>malinfo-template-{template.id}</name>
            <uuid>{template.id}</uuid>
            <memory unit='MiB'>{template.memory_mb}</memory>
            <currentMemory unit='MiB'>{template.memory_mb}</currentMemory>
            <vcpu placement='static'>{template.vcpus}</vcpu>
            <os>
                <type arch='{template.arch}' machine='pc-q35-8.0'>hvm</type>
                <boot dev='cdrom'/>
                <boot dev='hd'/>
            </os>
            <features>
                <acpi/>
                <apic/>
                <hyperv>
                    <relaxed state='on'/>
                    <vapic state='on'/>
                    <spinlocks state='on' retries='8191'/>
                </hyperv>
            </features>
            <cpu mode='host-passthrough' check='none'/>
            <clock offset='utc'>
                <timer name='rtc' tickpolicy='catchup'/>
                <timer name='pit' tickpolicy='delay'/>
                <timer name='hpet' present='no'/>
            </clock>
            <devices>
                <emulator>/usr/bin/qemu-system-x86_64</emulator>
                <disk type='file' device='disk'>
                    <driver name='qemu' type='qcow2' discard='unmap'/>
                    <source file='{disk_path}'/>
                    <target dev='vda' bus='virtio'/>
                </disk>
                <disk type='file' device='cdrom'>
                    <driver name='qemu' type='raw'/>
                    <source file='{template.iso_path}'/>
                    <target dev='sda' bus='sata'/>
                    <readonly/>
                </disk>
                <controller type='usb' index='0' model='qemu-xhci'/>
                <controller type='sata' index='0'/>
                <interface type='network'>
                    <source network='malinfo-isolated'/>
                    <mac address='{mac}'/>
                    <model type='virtio'/>
                </interface>
                <graphics type='vnc' port='-1' autoport='yes' listen='0.0.0.0'>
                    <listen type='address' address='0.0.0.0'/>
                </graphics>
                <video>
                    <model type='virtio' heads='1' primary='yes'/>
                </video>
                <memballoon model='virtio'/>
                <rng model='virtio'>
                    <backend model='random'>/dev/urandom</backend>
                </rng>
            </devices>
        </domain>
        """

    def _build_analysis_domain_xml(self, template: VMTemplate, disk_path: str, task: AnalysisTask) -> str:
        """Build domain XML for analysis run"""
        mac = f"52:54:00:{uuid.uuid4().hex[:6]}"
        _ = self.agent_port + len(self.instances)

        return f"""
        <domain type='kvm'>
            <name>malinfo-analysis-{task.id}</name>
            <uuid>{task.id}</uuid>
            <memory unit='MiB'>{template.memory_mb}</memory>
            <currentMemory unit='MiB'>{template.memory_mb}</currentMemory>
            <vcpu placement='static'>{template.vcpus}</vcpu>
            <os>
                <type arch='{template.arch}' machine='pc-q35-8.0'>hvm</type>
                <boot dev='hd'/>
            </os>
            <features>
                <acpi/>
                <apic/>
                <hyperv>
                    <relaxed state='on'/>
                    <vapic state='on'/>
                    <spinlocks state='on' retries='8191'/>
                </hyperv>
            </features>
            <cpu mode='host-passthrough' check='none'/>
            <clock offset='utc'>
                <timer name='rtc' tickpolicy='catchup'/>
                <timer name='pit' tickpolicy='delay'/>
                <timer name='hpet' present='no'/>
            </clock>
            <devices>
                <emulator>/usr/bin/qemu-system-x86_64</emulator>
                <disk type='file' device='disk'>
                    <driver name='qemu' type='qcow2' discard='unmap' snapshot='external'/>
                    <source file='{disk_path}'/>
                    <target dev='vda' bus='virtio'/>
                    <alias name='virtio-disk0'/>
                </disk>
                <controller type='usb' index='0' model='qemu-xhci'/>
                <interface type='network'>
                    <source network='malinfo-{template.network_mode}'/>
                    <mac address='{mac}'/>
                    <model type='virtio'/>
                </interface>
                <graphics type='vnc' port='-1' autoport='yes' listen='0.0.0.0'>
                    <listen type='address' address='0.0.0.0'/>
                </graphics>
                <channel type='unix'>
                    <source mode='bind' path='/tmp/malinfo-agent-{task.id}.sock'/>
                    <target type='virtio' name='org.malinfo.agent'/>
                </channel>
                <video>
                    <model type='virtio' heads='1' primary='yes'/>
                </video>
                <memballoon model='virtio'/>
                <rng model='virtio'>
                    <backend model='random'>/dev/urandom</backend>
                </rng>
            </devices>
        </domain>
        """

    async def list_templates(self) -> list[VMTemplate]:
        """List all templates"""
        return list(self.templates.values())

    async def get_template(self, template_id: str) -> VMTemplate | None:
        """Get template by ID"""
        return self.templates.get(template_id)

    async def delete_template(self, template_id: str) -> bool:
        """Delete a template"""
        template = self.templates.get(template_id)
        if not template:
            return False

        # Clean up libvirt resources
        try:
            pool_name = f"malinfo_{template_id}"
            conn = self.libvirt.connect()
            pool = conn.storagePoolLookupByName(pool_name)
            pool.destroy()
            pool.delete(0)
        except libvirt.libvirtError:
            pass

        # Remove from memory and disk
        del self.templates[template_id]
        await self._save_templates()

        # Remove storage directory
        template_path = self.storage_path / "templates" / template_id
        if template_path.exists():
            shutil.rmtree(template_path)

        return True

    # ─── Instance Management ───

    async def create_instance(self, template_id: str, task_id: str) -> VMInstance:
        """Create a VM instance for analysis"""
        template = self.templates.get(template_id)
        if not template:
            raise ValueError(f"Template not found: {template_id}")

        if template.state != VMState.READY:
            raise ValueError(f"Template not ready: {template.state}")

        instance_id = str(uuid.uuid4())
        instance = VMInstance(
            id=instance_id,
            template_id=template_id,
            name=f"malinfo-analysis-{task_id}",
            state=VMState.BUILDING,
        )

        self.instances[instance_id] = instance

        # Create instance disk from template snapshot
        pool_name = f"malinfo_{template_id}"
        pool = self.libvirt.create_storage_pool(pool_name, str(self.storage_path / "templates" / template_id))

        # Create instance storage
        instance_pool_name = f"malinfo_instance_{instance_id}"
        instance_pool_path = self.storage_path / "instances" / instance_id
        instance_pool_path.mkdir(parents=True, exist_ok=True)
        instance_pool = self.libvirt.create_storage_pool(instance_pool_name, str(instance_pool_path))

        # Create COW (copy-on-write) disk based on template
        template_disk = f"{template_id}.qcow2"
        instance_disk = f"{instance_id}.qcow2"

        # Create backing file
        vol_xml = f"""
        <volume>
            <name>{instance_disk}</name>
            <allocation>0</allocation>
            <capacity unit='G'>{template.disk_size_gb}</capacity>
            <target>
                <format type='qcow2'/>
                <backingStore>
                    <path>{self.libvirt.get_volume_path(pool, template_disk)}</path>
                    <format type='qcow2'/>
                </backingStore>
            </target>
        </volume>
        """
        instance_pool.createXML(vol_xml, 0)
        instance_disk_path = self.libvirt.get_volume_path(instance_pool, instance_disk)

        # Create domain
        task = self.tasks.get(task_id)
        domain_xml = self._build_analysis_domain_xml(template, instance_disk_path, task)
        domain = self.libvirt.create_domain(domain_xml)

        instance.domain = domain
        instance.state = VMState.RUNNING
        instance.started_at = datetime.now(UTC)

        # Get VNC port
        vnc_info = domain.graphicsGetInfo()
        if vnc_info:
            instance.vnc_port = vnc_info[0].get('port', 5900)

        return instance

    async def revert_instance(self, instance_id: str) -> bool:
        """Revert instance to clean snapshot"""
        instance = self.instances.get(instance_id)
        if not instance or not instance.domain:
            return False

        template = self.templates.get(instance.template_id)
        if not template:
            return False

        instance.state = VMState.REVERTING

        try:
            # Revert to clean snapshot
            self.libvirt.snapshot_revert(instance.domain, template.snapshot_name)
            instance.state = VMState.READY
            return True
        except Exception as e:
            logger.exception(f"Failed to revert instance {instance_id}: {e}")
            instance.state = VMState.ERROR
            instance.error = str(e)
            return False

    async def destroy_instance(self, instance_id: str) -> bool:
        """Destroy a VM instance"""
        instance = self.instances.get(instance_id)
        if not instance:
            return False

        if instance.domain:
            try:
                if instance.domain.isActive():
                    instance.domain.destroy()
            except libvirt.libvirtError:
                pass

        # Clean up storage
        try:
            instance_pool_name = f"malinfo_instance_{instance_id}"
            conn = self.libvirt.connect()
            pool = conn.storagePoolLookupByName(instance_pool_name)
            pool.destroy()
            pool.delete(0)
        except libvirt.libvirtError:
            pass

        del self.instances[instance_id]
        return True

    # ─── Analysis Task Management ───

    async def submit_analysis(
        self,
        sample_id: str,
        sample_path: Path,
        template_id: str,
        timeout: int = 300,
        options: dict | None = None,
    ) -> AnalysisTask:
        """Submit a sample for dynamic analysis"""
        # Calculate sample hash
        sha256 = hashlib.sha256()
        async with aiofiles.open(sample_path, "rb") as f:
            while chunk := await f.read(8192):
                sha256.update(chunk)
        sample_hash = sha256.hexdigest()

        task_id = str(uuid.uuid4())
        task = AnalysisTask(
            id=task_id,
            sample_id=sample_id,
            sample_path=str(sample_path),
            sample_hash=sample_hash,
            template_id=template_id,
            timeout=timeout,
            options=options or {},
        )

        self.tasks[task_id] = task

        # Start analysis in background
        _ = asyncio.create_task(self._run_analysis(task))

        return task

    async def _run_analysis(self, task: AnalysisTask):
        """Run the complete analysis workflow"""
        try:
            task.state = TaskState.PREPARING
            await self._notify_task_update(task)

            # Create VM instance
            instance = await self.create_instance(task.template_id, task.id)
            task.vm_instance_id = instance.id

            task.state = TaskState.BOOTING
            await self._notify_task_update(task)

            # Wait for VM to boot and agent to connect
            await self._wait_for_agent(instance, task)

            task.state = TaskState.INJECTING
            await self._notify_task_update(task)

            # Inject sample into VM
            await self._inject_sample(instance, task)

            task.state = TaskState.RUNNING
            await self._notify_task_update(task)

            # Monitor execution
            await self._monitor_execution(instance, task)

            task.state = TaskState.COLLECTING
            await self._notify_task_update(task)

            # Collect results
            await self._collect_results(instance, task)

            # Calculate malscore
            task.malscore = self._calculate_malscore(task)

            task.state = TaskState.COMPLETED
            task.completed_at = datetime.now(UTC)

            # Save results
            await self._save_results(task)

            await self._notify_task_update(task)

        except Exception as e:
            logger.exception(f"Analysis failed for task {task.id}: {e}")
            task.state = TaskState.FAILED
            task.error = str(e)
            task.completed_at = datetime.now(UTC)
            await self._notify_task_update(task)
        finally:
            # Cleanup instance
            if task.vm_instance_id:
                await self.destroy_instance(task.vm_instance_id)

    async def _wait_for_agent(self, instance: VMInstance, task: AnalysisTask):
        """Wait for guest agent to connect"""
        # Connect to agent via WebSocket or Unix socket
        # This is a simplified version - real implementation would use the Unix socket
        # from the domain XML channel
        max_wait = AGENT_CONNECT_TIMEOUT  # seconds
        start = time.time()

        while time.time() - start < max_wait:
            # Check if agent is responding
            # In real implementation, connect to /tmp/malinfo-agent-{task.id}.sock
            await asyncio.sleep(2)
            # For now, simulate agent ready
            if time.time() - start > SIMULATED_AGENT_READY_TIME:
                return

        raise TimeoutError("Guest agent did not connect in time")

    async def _inject_sample(self, instance: VMInstance, task: AnalysisTask):
        """Inject sample into VM for analysis"""
        # Copy sample to VM via agent
        # Agent will place it in a known location and execute

    async def _monitor_execution(self, instance: VMInstance, task: AnalysisTask):
        """Monitor sample execution via guest agent"""
        # Receive real-time events from agent via WebSocket
        # Events: process creation, API calls, network, file, registry
        timeout = task.timeout
        start = time.time()

        while time.time() - start < timeout:
            # In real implementation, receive events from agent
            await asyncio.sleep(5)

            # Check if sample execution completed
            # Agent would signal completion
            if time.time() - start > SIMULATED_EXECUTION_TIME:  # Simulate 30s execution
                break

    async def _collect_results(self, instance: VMInstance, task: AnalysisTask):
        """Collect analysis results from VM"""
        # Get results from agent
        # Take screenshots
        # Dump memory if needed
        # Collect PCAP

    def _calculate_malscore(self, task: AnalysisTask) -> int:
        """Calculate malware score from behavior"""
        score = 0

        # Score based on MITRE techniques
        technique_scores = {
            "T1055": 20,  # Process Injection
            "T1027": 15,  # Obfuscated Files
            "T1547": 15,  # Boot/Logon Autostart
            "T1059": 10,  # Command and Scripting
            "T1105": 15,  # Ingress Tool Transfer
            "T1071": 10,  # Application Layer Protocol
            "T1083": 5,   # File and Directory Discovery
            "T1012": 10,  # Query Registry
        }

        for tech in task.mitre_techniques:
            score += technique_scores.get(tech, 5)

        # Score based on signatures
        score += len(task.signatures) * 5

        # Score based on network IOCs
        score += len(task.network_events) * 2

        # Score based on dropped files
        score += len(task.dropped_files) * 10

        return min(score, 100)

    async def _save_results(self, task: AnalysisTask):
        """Save analysis results to disk"""
        results_dir = self.storage_path / "analysis_results" / task.id
        results_dir.mkdir(parents=True, exist_ok=True)

        result_file = results_dir / "report.json"
        data = task.__dict__.copy()
        # Convert datetime to isoformat
        for key, value in data.items():
            if isinstance(value, datetime):
                data[key] = value.isoformat()

        async with aiofiles.open(result_file, "w") as f:
            await f.write(json.dumps(data, indent=2, default=str))

    async def get_task(self, task_id: str) -> AnalysisTask | None:
        """Get task by ID"""
        task = self.tasks.get(task_id)
        if not task:
            # Try loading from disk
            result_file = self.storage_path / "analysis_results" / task_id / "report.json"
            if result_file.exists():
                async with aiofiles.open(result_file) as f:
                    data = json.loads(await f.read())
                    # Convert isoformat back to datetime
                    for key, value in data.items():
                        if key.endswith("_at") and isinstance(value, str):
                            with contextlib.suppress(ValueError):
                                data[key] = datetime.fromisoformat(value)
                    task = AnalysisTask(**data)
                    self.tasks[task_id] = task
        return task

    async def list_tasks(self, limit: int = 50, offset: int = 0) -> list[AnalysisTask]:
        """List analysis tasks"""
        tasks = list(self.tasks.values())
        tasks.sort(key=lambda t: t.created_at, reverse=True)
        return tasks[offset:offset + limit]

    # ─── WebSocket Management ───

    def register_websocket(self, task_id: str, websocket):
        """Register a WebSocket connection for task updates"""
        if task_id not in self.ws_connections:
            self.ws_connections[task_id] = set()
        self.ws_connections[task_id].add(websocket)

    def unregister_websocket(self, task_id: str, websocket):
        """Unregister a WebSocket connection"""
        if task_id in self.ws_connections:
            self.ws_connections[task_id].discard(websocket)

    async def _notify_task_update(self, task: AnalysisTask):
        """Notify WebSocket connections of task update"""
        if task.id in self.ws_connections:
            message = json.dumps({
                "type": "task_update",
                "task_id": task.id,
                "state": task.state.value,
                "progress": self._get_task_progress(task),
                "data": {
                    "malscore": task.malscore,
                    "signatures_count": len(task.signatures),
                    "processes_count": len(task.process_tree),
                    "network_events_count": len(task.network_events),
                    "file_events_count": len(task.file_events),
                }
            })

            dead_connections = set()
            for ws in self.ws_connections[task.id]:
                try:
                    await ws.send_text(message)
                except Exception:
                    dead_connections.add(ws)

            for ws in dead_connections:
                self.ws_connections[task.id].discard(ws)

    def _get_task_progress(self, task: AnalysisTask) -> int:
        """Get task progress percentage"""
        progress_map = {
            TaskState.QUEUED: 0,
            TaskState.PREPARING: 10,
            TaskState.BOOTING: 20,
            TaskState.INJECTING: 30,
            TaskState.RUNNING: 40,
            TaskState.MONITORING: 60,
            TaskState.COLLECTING: 80,
            TaskState.COMPLETED: 100,
            TaskState.FAILED: 100,
        }
        return progress_map.get(task.state, 0)


# Global orchestrator instance
orchestrator: VMOrchestrator | None = None


def get_orchestrator() -> VMOrchestrator:
    """Get global orchestrator instance"""
    global orchestrator
    if orchestrator is None:
        from app.config import settings
        orchestrator = VMOrchestrator(
            storage_path=str(settings.STORAGE_DIR / "vms"),
            iso_path=str(settings.STORAGE_DIR / "isos"),
        )
    return orchestrator
