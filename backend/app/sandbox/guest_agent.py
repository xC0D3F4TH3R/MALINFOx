#!/usr/bin/env python3
"""
MALINFO Guest Agent

Runs inside analysis VMs to provide real-time behavioral monitoring:
- Process creation/termination monitoring
- API call interception (Windows: ETW, Linux: ptrace)
- File system activity monitoring
- Registry monitoring (Windows)
- Network connection monitoring
- Memory analysis integration
- Screenshot capture
- Sample execution and control

Communicates with host orchestrator via virtio-serial channel (org.malinfo.agent)
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import logging
import os
import platform
import signal
import socket
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from io import BytesIO
from pathlib import Path
from typing import Any

import psutil

# Windows-specific imports
if platform.system() == "Windows":
    try:
        import winreg

        import win32api
        import win32con
        import win32gui
        import win32security
        import win32ui
        import wmi
    except ImportError:
        pass

# Linux-specific imports
if platform.system() == "Linux":
    with contextlib.suppress(ImportError):
        import pyinotify

from PIL import Image

logger = logging.getLogger("malinfo.agent")


@dataclass
class AgentConfig:
    """Agent configuration"""
    host_socket: str = "/tmp/malinfo-agent.sock"
    agent_id: str = ""
    sample_path: str = ""
    sample_hash: str = ""
    analysis_timeout: int = 300
    capture_screenshots: bool = True
    capture_memory: bool = True
    capture_network: bool = True
    api_monitor_enabled: bool = True
    screenshot_interval: int = 5  # seconds


@dataclass
class ProcessEvent:
    """Process event"""
    timestamp: str
    event_type: str  # create, terminate, inject
    pid: int
    ppid: int
    name: str
    path: str
    cmdline: str
    user: str
    integrity_level: str = ""


@dataclass
class APICallEvent:
    """API call event"""
    timestamp: str
    pid: int
    process_name: str
    api: str
    module: str
    category: str
    arguments: dict
    return_value: Any = None


@dataclass
class FileEvent:
    """File system event"""
    timestamp: str
    event_type: str  # create, modify, delete, rename, read, write
    pid: int
    process_name: str
    path: str
    size: int = 0


@dataclass
class NetworkEvent:
    """Network event"""
    timestamp: str
    event_type: str  # connect, listen, dns, http
    pid: int
    process_name: str
    protocol: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    extra: dict = field(default_factory=dict)


@dataclass
class RegistryEvent:
    """Registry event (Windows)"""
    timestamp: str
    event_type: str  # create, modify, delete, set_value
    pid: int
    process_name: str
    key: str
    value_name: str = ""
    value_data: str = ""


class EventCollector:
    """Collects and buffers events for transmission"""

    def __init__(self, agent: GuestAgent):
        self.agent = agent
        self.buffer: list[dict] = []
        self.buffer_lock = threading.Lock()
        self.max_buffer = 1000
        self.flush_interval = 1.0  # seconds
        self.last_flush = time.time()

    def add_event(self, event_type: str, data: dict):
        """Add event to buffer"""
        event = {
            "type": event_type,
            "timestamp": datetime.now(UTC).isoformat(),
            "data": data,
        }
        with self.buffer_lock:
            self.buffer.append(event)
            if len(self.buffer) >= self.max_buffer:
                self.flush()

    def flush(self) -> list[dict]:
        """Flush buffer and return events"""
        with self.buffer_lock:
            events = self.buffer.copy()
            self.buffer.clear()
            self.last_flush = time.time()
        return events

    async def periodic_flush(self):
        """Periodically flush buffer"""
        while self.agent.running:
            await asyncio.sleep(self.flush_interval)
            if time.time() - self.last_flush >= self.flush_interval:
                events = self.flush()
                if events:
                    await self.agent.send_events(events)


class ProcessMonitor:
    """Monitors process creation and termination"""

    def __init__(self, collector: EventCollector):
        self.collector = collector
        self.running = False
        self.known_pids: set[int] = set()

    def start(self):
        """Start monitoring"""
        self.running = True
        # Initialize known PIDs
        self.known_pids = {p.pid for p in psutil.process_iter()}
        threading.Thread(target=self._monitor_loop, daemon=True).start()

    def stop(self):
        """Stop monitoring"""
        self.running = False

    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.running:
            try:
                current_pids = {p.pid for p in psutil.process_iter()}

                # New processes
                new_pids = current_pids - self.known_pids
                for pid in new_pids:
                    try:
                        proc = psutil.Process(pid)
                        self.collector.add_event("process_create", {
                            "pid": pid,
                            "ppid": proc.ppid(),
                            "name": proc.name(),
                            "path": proc.exe() or "",
                            "cmdline": " ".join(proc.cmdline()),
                            "user": proc.username(),
                            "create_time": proc.create_time(),
                        })
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

                # Terminated processes
                terminated_pids = self.known_pids - current_pids
                for pid in terminated_pids:
                    self.collector.add_event("process_terminate", {
                        "pid": pid,
                    })

                self.known_pids = current_pids

            except Exception:
                logger.exception("Process monitor error")

            time.sleep(1)


class WindowsProcessMonitor(ProcessMonitor):
    """Windows-specific process monitoring using WMI/ETW"""

    def __init__(self, collector: EventCollector):
        super().__init__(collector)
        self.wmi = None
        self.process_watcher = None

    def start(self):
        """Start WMI monitoring"""
        if platform.system() != "Windows":
            super().start()
            return

        try:
            self.wmi = wmi.WMI()
            # Watch for process creation
            self.process_watcher = self.wmi.Win32_Process.watch_for("creation")
            self.running = True
            threading.Thread(target=self._wmi_loop, daemon=True).start()
            logger.info("Windows WMI process monitor started")
        except Exception:
            logger.exception("Failed to start WMI monitor")
            super().start()

    def _wmi_loop(self):
        """WMI event loop"""
        while self.running:
            try:
                new_process = self.process_watcher(timeout_ms=1000)
                if new_process:
                    self.collector.add_event("process_create", {
                        "pid": new_process.ProcessId,
                        "ppid": new_process.ParentProcessId,
                        "name": new_process.Name,
                        "path": new_process.ExecutablePath or "",
                        "cmdline": new_process.CommandLine or "",
                        "user": self._get_process_user(new_process.ProcessId),
                        "create_time": new_process.CreationDate,
                    })
            except wmi.x_wmi_timed_out:
                continue
            except Exception:
                logger.exception("WMI monitor error")
                time.sleep(1)

    def _get_process_user(self, pid: int) -> str:
        """Get process owner"""
        try:
            handle = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION, False, pid)
            token = win32security.OpenProcessToken(handle, win32con.TOKEN_QUERY)
            user = win32security.GetTokenInformation(token, win32security.TokenUser)
            return win32security.LookupAccountSid(None, user[0])[0]
        except Exception:
            return "unknown"


class APICallMonitor:
    """Monitors API calls - uses ETW on Windows, ptrace on Linux"""

    def __init__(self, collector: EventCollector):
        self.collector = collector
        self.running = False
        self.monitored_pids: set[int] = set()

    def start(self, pids: list[int] | None = None):
        """Start API monitoring"""
        if pids:
            self.monitored_pids.update(pids)
        self.running = True

        if platform.system() == "Windows":
            threading.Thread(target=self._etw_loop, daemon=True).start()
        else:
            threading.Thread(target=self._ptrace_loop, daemon=True).start()

    def stop(self):
        """Stop monitoring"""
        self.running = False

    def _etw_loop(self):
        """Windows ETW API monitoring"""
        # This would use ETW (Event Tracing for Windows) to capture API calls
        # For production, use a library like python-etw or implement a kernel driver
        logger.info("API monitor started (ETW simulation)")
        while self.running:
            # In real implementation, this would receive ETW events
            time.sleep(5)

    def _ptrace_loop(self):
        """Linux ptrace API monitoring"""
        # This would use ptrace to monitor syscalls
        # For production, use sysdig, falco, or a custom ptrace implementation
        logger.info("API monitor started (ptrace simulation)")
        while self.running:
            time.sleep(5)


class FileMonitor:
    """Monitors file system activity"""

    def __init__(self, collector: EventCollector):
        self.collector = collector
        self.running = False
        self.watched_paths: list[str] = []

    def start(self, paths: list[str] | None = None):
        """Start file monitoring"""
        if paths:
            self.watched_paths = paths
        # Default paths to watch
        elif platform.system() == "Windows":
            self.watched_paths = [
                r"C:\Users",
                r"C:\ProgramData",
                r"C:\Windows\Temp",
                r"C:\Temp",
            ]
        else:
            self.watched_paths = [
                "/tmp",
                "/var/tmp",
                "/home",
                "/root",
                "/etc",
            ]

        self.running = True

        if platform.system() == "Linux":
            threading.Thread(target=self._inotify_loop, daemon=True).start()
        else:
            threading.Thread(target=self._polling_loop, daemon=True).start()

    def stop(self):
        """Stop monitoring"""
        self.running = False

    def _inotify_loop(self):
        """Linux inotify monitoring"""
        try:
            import pyinotify

            class EventHandler(pyinotify.ProcessEvent):
                def __init__(self, collector):
                    self.collector = collector

                def process_IN_CREATE(self, event):
                    self._handle_event("create", event)

                def process_IN_MODIFY(self, event):
                    self._handle_event("modify", event)

                def process_IN_DELETE(self, event):
                    self._handle_event("delete", event)

                def process_IN_MOVED_FROM(self, event):
                    self._handle_event("rename_from", event)

                def process_IN_MOVED_TO(self, event):
                    self._handle_event("rename_to", event)

                def _handle_event(self, event_type, event):
                    try:
                        # Get process info (simplified)
                        self.collector.add_event("file_event", {
                            "event_type": event_type,
                            "path": event.pathname,
                            "is_directory": event.dir,
                        })
                    except Exception:
                        logger.exception("File event error")

            wm = pyinotify.WatchManager()
            mask = (
                pyinotify.IN_CREATE | pyinotify.IN_MODIFY | pyinotify.IN_DELETE |
                pyinotify.IN_MOVED_FROM | pyinotify.IN_MOVED_TO
            )

            for path in self.watched_paths:
                if Path(path).exists():
                    wm.add_watch(path, mask, rec=True)

            notifier = pyinotify.Notifier(wm, EventHandler(self.collector))
            logger.info("File monitor started (inotify)")

            while self.running:
                notifier.process_events()
                if notifier.check_events():
                    notifier.read_events()
                time.sleep(0.1)

        except ImportError:
            logger.warning("pyinotify not available, falling back to polling")
            self._polling_loop()
        except Exception:
            logger.exception("File monitor error")
            self._polling_loop()

    def _polling_loop(self):
        """Fallback polling-based file monitoring"""
        # Track file states
        file_states: dict[str, dict] = {}

        while self.running:
            for path in self.watched_paths:
                path_obj = Path(path)
                if not path_obj.exists():
                    continue
                try:
                    for root, _dirs, files in os.walk(path):
                        for f in files:
                            filepath = Path(root) / f
                            try:
                                stat = filepath.stat()
                                key = str(filepath)
                                current = {"size": stat.st_size, "mtime": stat.st_mtime}

                                if key not in file_states:
                                    file_states[key] = current
                                    self.collector.add_event("file_event", {
                                        "event_type": "create",
                                        "path": key,
                                        "size": stat.st_size,
                                    })
                                elif file_states[key]["mtime"] != current["mtime"]:
                                    file_states[key] = current
                                    self.collector.add_event("file_event", {
                                        "event_type": "modify",
                                        "path": key,
                                        "size": stat.st_size,
                                    })
                            except (OSError, PermissionError):
                                pass
                except (OSError, PermissionError):
                    pass

            # Check for deleted files
            existing = set()
            for path in self.watched_paths:
                path_obj = Path(path)
                if path_obj.exists():
                    for root, _dirs, files in os.walk(path):
                        for f in files:
                            existing.add(str(Path(root) / f))

            deleted = set(file_states.keys()) - existing
            for f in deleted:
                self.collector.add_event("file_event", {
                    "event_type": "delete",
                    "path": f,
                })
                del file_states[f]

            time.sleep(2)


class NetworkMonitor:
    """Monitors network connections"""

    def __init__(self, collector: EventCollector):
        self.collector = collector
        self.running = False
        self.known_connections: set = set()

    def start(self):
        """Start network monitoring"""
        self.running = True
        # Initialize known connections
        self._update_known_connections()
        threading.Thread(target=self._monitor_loop, daemon=True).start()

    def stop(self):
        """Stop monitoring"""
        self.running = False

    def _update_known_connections(self):
        """Update known connections"""
        self.known_connections.clear()
        for conn in psutil.net_connections(kind='inet'):
            if conn.pid:
                key = (conn.pid, conn.laddr.ip, conn.laddr.port, conn.raddr.ip if conn.raddr else "", conn.raddr.port if conn.raddr else 0)
                self.known_connections.add(key)

    def _monitor_loop(self):
        """Monitor network connections"""
        while self.running:
            try:
                current_connections = set()
                for conn in psutil.net_connections(kind='inet'):
                    if conn.pid:
                        key = (conn.pid, conn.laddr.ip, conn.laddr.port, conn.raddr.ip if conn.raddr else "", conn.raddr.port if conn.raddr else 0)
                        current_connections.add(key)

                        if key not in self.known_connections:
                            # New connection
                            proc_name = ""
                            with contextlib.suppress(psutil.NoSuchProcess, psutil.AccessDenied):
                                proc_name = psutil.Process(conn.pid).name()

                            self.collector.add_event("network_event", {
                                "event_type": "connect",
                                "pid": conn.pid,
                                "process_name": proc_name,
                                "protocol": "tcp" if conn.type == socket.SOCK_STREAM else "udp",
                                "src_ip": conn.laddr.ip,
                                "src_port": conn.laddr.port,
                                "dst_ip": conn.raddr.ip if conn.raddr else "",
                                "dst_port": conn.raddr.port if conn.raddr else 0,
                                "status": conn.status,
                            })

                # Check for closed connections
                closed = self.known_connections - current_connections
                for key in closed:
                    pid, src_ip, src_port, dst_ip, dst_port = key
                    proc_name = ""
                    with contextlib.suppress(psutil.NoSuchProcess, psutil.AccessDenied):
                        proc_name = psutil.Process(pid).name()

                    self.collector.add_event("network_event", {
                        "event_type": "disconnect",
                        "pid": pid,
                        "process_name": proc_name,
                        "protocol": "tcp",
                        "src_ip": src_ip,
                        "src_port": src_port,
                        "dst_ip": dst_ip,
                        "dst_port": dst_port,
                    })

                self.known_connections = current_connections

            except Exception:
                logger.exception("Network monitor error")

            time.sleep(1)


class RegistryMonitor:
    """Monitors Windows registry activity"""

    def __init__(self, collector: EventCollector):
        self.collector = collector
        self.running = False
        self.watched_keys: list[str] = []

    def start(self):
        """Start registry monitoring (Windows only)"""
        if platform.system() != "Windows":
            return

        self.watched_keys = [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce",
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
            r"SYSTEM\CurrentControlSet\Services",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks",
        ]

        self.running = True
        threading.Thread(target=self._monitor_loop, daemon=True).start()
        logger.info("Registry monitor started")

    def stop(self):
        """Stop monitoring"""
        self.running = False

    def _monitor_loop(self):
        """Monitor registry changes using polling"""
        # Track registry values
        reg_states: dict[str, dict] = {}

        while self.running:
            for key_path in self.watched_keys:
                try:
                    self._check_registry_key(key_path, reg_states)
                except Exception as e:
                    logger.debug("Registry check error for %s: %s", key_path, e)

            time.sleep(5)

    def _check_registry_key(self, key_path: str, reg_states: dict):
        """Check a registry key for changes"""
        try:
            parts = key_path.split("\\")
            root_name = parts[0]
            subkey = "\\".join(parts[1:])

            root_map = {
                "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE,
                "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER,
                "HKEY_CLASSES_ROOT": winreg.HKEY_CLASSES_ROOT,
                "HKEY_USERS": winreg.HKEY_USERS,
                "HKEY_CURRENT_CONFIG": winreg.HKEY_CURRENT_CONFIG,
                "SYSTEM": winreg.HKEY_LOCAL_MACHINE,  # SYSTEM is under HKLM
                "SOFTWARE": winreg.HKEY_LOCAL_MACHINE,
            }

            root = root_map.get(root_name, winreg.HKEY_LOCAL_MACHINE)

            with winreg.OpenKey(root, subkey, 0, winreg.KEY_READ) as key:
                i = 0
                while True:
                    try:
                        value_name, value_data, value_type = winreg.EnumValue(key, i)
                        full_key = f"{key_path}\\{value_name}"
                        current = {"data": str(value_data), "type": value_type}

                        if full_key not in reg_states:
                            reg_states[full_key] = current
                            self.collector.add_event("registry_event", {
                                "event_type": "create",
                                "key": key_path,
                                "value_name": value_name,
                                "value_data": str(value_data)[:1000],
                            })
                        elif reg_states[full_key]["data"] != current["data"]:
                            reg_states[full_key] = current
                            self.collector.add_event("registry_event", {
                                "event_type": "modify",
                                "key": key_path,
                                "value_name": value_name,
                                "value_data": str(value_data)[:1000],
                            })
                        i += 1
                    except OSError:
                        break
        except Exception as e:
            logger.debug("Registry key error: %s", e)


class ScreenshotCapture:
    """Captures screenshots from the VM"""

    def __init__(self, collector: EventCollector, interval: int = 5):
        self.collector = collector
        self.interval = interval
        self.running = False

    def start(self):
        """Start screenshot capture"""
        self.running = True
        threading.Thread(target=self._capture_loop, daemon=True).start()

    def stop(self):
        """Stop screenshot capture"""
        self.running = False

    def _capture_loop(self):
        """Capture screenshots periodically"""
        while self.running:
            try:
                screenshot_data = self._capture_screen()
                if screenshot_data:
                    # Convert to base64 for transmission
                    import base64
                    b64_data = base64.b64encode(screenshot_data).decode('ascii')
                    self.collector.add_event("screenshot", {
                        "data": b64_data,
                        "format": "png",
                    })
            except Exception:
                logger.exception("Screenshot error")

            time.sleep(self.interval)

    def _capture_screen(self) -> bytes | None:
        """Capture screen - platform specific"""
        if platform.system() == "Windows":
            return self._capture_windows()
        return self._capture_linux()

    def _capture_windows(self) -> bytes | None:
        """Capture screen on Windows"""
        try:
            import win32con
            import win32gui
            import win32ui
            from PIL import Image

            # Get desktop window
            hdesktop = win32gui.GetDesktopWindow()
            width = win32api.GetSystemMetrics(win32con.SM_CXVIRTUALSCREEN)
            height = win32api.GetSystemMetrics(win32con.SM_CYVIRTUALSCREEN)
            left = win32api.GetSystemMetrics(win32con.SM_XVIRTUALSCREEN)
            top = win32api.GetSystemMetrics(win32con.SM_YVIRTUALSCREEN)

            # Create device context
            desktop_dc = win32gui.GetWindowDC(hdesktop)
            img_dc = win32ui.CreateDCFromHandle(desktop_dc)
            mem_dc = img_dc.CreateCompatibleDC()

            # Create bitmap
            screenshot = win32ui.CreateBitmap()
            screenshot.CreateCompatibleBitmap(img_dc, width, height)
            mem_dc.SelectObject(screenshot)

            # Copy screen
            mem_dc.BitBlt((0, 0), (width, height), img_dc, (left, top), win32con.SRCCOPY)

            # Convert to PIL Image
            bmpinfo = screenshot.GetInfo()
            bmpstr = screenshot.GetBitmapBits(True)
            img = Image.frombuffer(
                'RGB',
                (bmpinfo['bmWidth'], bmpinfo['bmHeight']),
                bmpstr, 'raw', 'BGRX', 0, 1
            )

            # Cleanup
            mem_dc.DeleteDC()
            img_dc.DeleteDC()
            win32gui.ReleaseDC(hdesktop, desktop_dc)
            win32gui.DeleteObject(screenshot.GetHandle())

            # Save to bytes
            from io import BytesIO
            output = BytesIO()
            img.save(output, format='PNG')
            return output.getvalue()

        except Exception:
            logger.exception("Windows screenshot error")
            return None

    def _capture_linux(self) -> bytes | None:
        """Capture screen on Linux"""
        try:
            # Use scrot or imagemagick
            result = subprocess.run(
                ["import", "-window", "root", "png:-"],
                capture_output=True,
                timeout=5,
                check=False
            )
            if result.returncode == 0:
                return result.stdout
        except Exception:
            pass

        try:
            # Alternative: use gnome-screenshot
            result = subprocess.run(
                ["gnome-screenshot", "-f", "-"],
                capture_output=True,
                timeout=5,
                check=False
            )
            if result.returncode == 0:
                return result.stdout
        except Exception:
            pass

        return None


class SampleExecutor:
    """Executes the sample in the VM"""

    def __init__(self, collector: EventCollector, config: AgentConfig):
        self.collector = collector
        self.config = config
        self.process: subprocess.Popen | None = None

    def execute(self, sample_path: str, args: str = "") -> int:
        """Execute the sample"""
        try:
            # Copy sample to a working directory
            work_dir = Path(sample_path).parent

            # Determine execution method based on file type
            ext = Path(sample_path).suffix.lower()

            if platform.system() == "Windows":
                if ext in [".exe", ".bat", ".cmd", ".com", ".scr", ".pif"]:
                    cmd = [sample_path]
                    if args:
                        cmd.extend(args.split())
                elif ext in [".ps1"]:
                    cmd = ["powershell", "-ExecutionPolicy", "Bypass", "-File", sample_path]
                    if args:
                        cmd.extend(args.split())
                elif ext in [".vbs", ".js", ".jse", ".wsf", ".wsh"]:
                    cmd = ["wscript", sample_path]
                    if args:
                        cmd.extend(args.split())
                elif ext in [".py"]:
                    cmd = ["python", sample_path]
                    if args:
                        cmd.extend(args.split())
                else:
                    # Try to execute with default handler
                    cmd = ["cmd", "/c", sample_path]
                    if args:
                        cmd.append(args)
            else:
                # Linux/Android
                if ext in [".sh", ".bash"]:
                    cmd = ["bash", sample_path]
                elif ext in [".py"]:
                    cmd = ["python3", sample_path]
                elif ext in [".pl"]:
                    cmd = ["perl", sample_path]
                elif ext in [".rb"]:
                    cmd = ["ruby", sample_path]
                elif os.access(sample_path, os.X_OK):
                    cmd = [sample_path]
                else:
                    # Try to make executable and run
                    Path(sample_path).chmod(0o755)
                    cmd = [sample_path]

                if args:
                    cmd.extend(args.split())

            logger.info("Executing sample: %s", " ".join(cmd))

            # Start process
            self.process = subprocess.Popen(
                cmd,
                cwd=str(work_dir),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )

            self.collector.add_event("sample_execution", {
                "pid": self.process.pid,
                "command": " ".join(cmd),
                "sample_path": sample_path,
            })

            return self.process.pid

        except Exception:
            logger.exception("Sample execution error")
            self.collector.add_event("sample_execution_failed", {
                "error": str(sys.exc_info()[1]),
                "sample_path": sample_path,
            })
            return -1

    def wait(self, timeout: int | None = None) -> int | None:
        """Wait for process to complete"""
        if self.process:
            try:
                return self.process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                return None
        return None

    def terminate(self):
        """Terminate the sample process"""
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
            except Exception:
                pass


class GuestAgent:
    """Main guest agent class"""

    def __init__(self, config: AgentConfig):
        self.config = config
        self.running = False
        self.collector = EventCollector(self)

        # Monitors
        self.process_monitor: ProcessMonitor | None = None
        self.api_monitor: APICallMonitor | None = None
        self.file_monitor: FileMonitor | None = None
        self.network_monitor: NetworkMonitor | None = None
        self.registry_monitor: RegistryMonitor | None = None
        self.screenshot_capture: ScreenshotCapture | None = None
        self.sample_executor: SampleExecutor | None = None

        # Communication
        self.socket: socket.socket | None = None
        self.connected = False

    def start(self):
        """Start the agent"""
        logger.info("Starting MALINFO Guest Agent")
        self.running = True

        # Initialize monitors
        if platform.system() == "Windows":
            self.process_monitor = WindowsProcessMonitor(self.collector)
        else:
            self.process_monitor = ProcessMonitor(self.collector)

        self.api_monitor = APICallMonitor(self.collector)
        self.file_monitor = FileMonitor(self.collector)
        self.network_monitor = NetworkMonitor(self.collector)

        if platform.system() == "Windows":
            self.registry_monitor = RegistryMonitor(self.collector)

        if self.config.capture_screenshots:
            self.screenshot_capture = ScreenshotCapture(
                self.collector, self.config.screenshot_interval
            )

        self.sample_executor = SampleExecutor(self.collector, self.config)

        # Start monitors
        self.process_monitor.start()
        if self.config.api_monitor_enabled:
            self.api_monitor.start()
        self.file_monitor.start()
        self.network_monitor.start()

        if self.registry_monitor:
            self.registry_monitor.start()

        if self.screenshot_capture:
            self.screenshot_capture.start()

        # Connect to host
        self._connect_to_host()

        # Start event flusher
        _ = asyncio.create_task(self.collector.periodic_flush())

        logger.info("Guest Agent started successfully")

    def stop(self):
        """Stop the agent"""
        logger.info("Stopping MALINFO Guest Agent")
        self.running = False

        if self.process_monitor:
            self.process_monitor.stop()
        if self.api_monitor:
            self.api_monitor.stop()
        if self.file_monitor:
            self.file_monitor.stop()
        if self.network_monitor:
            self.network_monitor.stop()
        if self.registry_monitor:
            self.registry_monitor.stop()
        if self.screenshot_capture:
            self.screenshot_capture.stop()

        if self.socket:
            self.socket.close()

    def _connect_to_host(self):
        """Connect to host via virtio-serial socket"""
        try:
            self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.socket.connect(self.config.host_socket)
            self.connected = True
            logger.info("Connected to host at %s", self.config.host_socket)

            # Send hello message
            self._send_message({
                "type": "hello",
                "agent_id": self.config.agent_id,
                "platform": platform.system(),
                "platform_version": platform.version(),
                "hostname": socket.gethostname(),
            })

            # Start receiver thread
            threading.Thread(target=self._receive_loop, daemon=True).start()

        except Exception:
            logger.exception("Failed to connect to host")
            self.connected = False

    def _receive_loop(self):
        """Receive commands from host"""
        buffer = ""
        while self.running and self.connected:
            try:
                data = self.socket.recv(4096).decode('utf-8')
                if not data:
                    break

                buffer += data
                while '\n' in buffer:
                    line, buffer = buffer.split('\n', 1)
                    self._handle_command(json.loads(line))

            except (ConnectionError, OSError, json.JSONDecodeError):
                logger.exception("Receive error")
                break

        self.connected = False
        logger.info("Disconnected from host")

    def _handle_command(self, command: dict):
        """Handle command from host"""
        cmd_type = command.get("type")

        if cmd_type == "execute_sample":
            sample_path = command.get("sample_path", "")
            args = command.get("args", "")
            if self.sample_executor:
                pid = self.sample_executor.execute(sample_path, args)
                self._send_message({
                    "type": "execution_started",
                    "pid": pid,
                    "sample_path": sample_path,
                })

        elif cmd_type == "terminate_sample":
            if self.sample_executor:
                self.sample_executor.terminate()
                self._send_message({"type": "sample_terminated"})

        elif cmd_type == "get_status":
            self._send_message({
                "type": "status",
                "running": self.running,
                "connected": self.connected,
                "monitors": {
                    "process": self.process_monitor.running if self.process_monitor else False,
                    "api": self.api_monitor.running if self.api_monitor else False,
                    "file": self.file_monitor.running if self.file_monitor else False,
                    "network": self.network_monitor.running if self.network_monitor else False,
                    "registry": self.registry_monitor.running if self.registry_monitor else False,
                    "screenshot": self.screenshot_capture.running if self.screenshot_capture else False,
                },
            })

        elif cmd_type == "capture_screenshot":
            if self.screenshot_capture:
                # Trigger immediate screenshot
                pass

        elif cmd_type == "dump_memory":
            # Trigger memory dump
            pass

    def _send_message(self, message: dict):
        """Send message to host"""
        if self.connected and self.socket:
            try:
                data = json.dumps(message) + "\n"
                self.socket.sendall(data.encode('utf-8'))
            except Exception:
                logger.exception("Send error")
                self.connected = False

    async def send_events(self, events: list[dict]):
        """Send events to host"""
        if events:
            self._send_message({
                "type": "events",
                "events": events,
            })


def create_default_config() -> AgentConfig:
    """Create default configuration"""
    return AgentConfig(
        agent_id=str(uuid.uuid4()),
        host_socket="/tmp/malinfo-agent.sock",
        analysis_timeout=300,
        capture_screenshots=True,
        capture_memory=True,
        capture_network=True,
        api_monitor_enabled=True,
        screenshot_interval=5,
    )


async def main():
    """Main entry point"""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    config = create_default_config()

    # Override from environment
    if "MALINFO_AGENT_SOCKET" in os.environ:
        config.host_socket = os.environ["MALINFO_AGENT_SOCKET"]
    if "MALINFO_SAMPLE_PATH" in os.environ:
        config.sample_path = os.environ["MALINFO_SAMPLE_PATH"]
    if "MALINFO_TIMEOUT" in os.environ:
        config.analysis_timeout = int(os.environ["MALINFO_TIMEOUT"])

    agent = GuestAgent(config)

    # Handle signals
    def signal_handler(signum, frame):
        logger.info("Received signal %s", signum)
        agent.stop()

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    try:
        agent.start()

        # If sample path provided, execute it
        if config.sample_path and Path(config.sample_path).exists():
            if agent.sample_executor:
                pid = agent.sample_executor.execute(config.sample_path)
                logger.info("Sample executed with PID %s", pid)

                # Wait for completion or timeout
                return_code = agent.sample_executor.wait(config.analysis_timeout)
                logger.info("Sample completed with return code: %s", return_code)

        # Keep running until timeout or signal
        start_time = time.time()
        while agent.running and (time.time() - start_time) < config.analysis_timeout:
            await asyncio.sleep(1)

    finally:
        agent.stop()
        logger.info("Guest Agent stopped")


if __name__ == "__main__":
    asyncio.run(main())
