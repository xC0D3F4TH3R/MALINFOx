"""
MALINFO — Guest Agent Communication Protocol

Handles host↔guest communication via virtio-serial Unix socket.
Protocol: newline-delimited JSON messages over Unix domain socket.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import socket
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger("malinfo.agent_comm")


@dataclass
class AgentMessage:
    """Base agent message"""
    type: str
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    message_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])


@dataclass
class HelloMessage(AgentMessage):
    """Agent hello/handshake"""
    type: str = "hello"
    agent_id: str = ""
    platform: str = ""
    platform_version: str = ""
    hostname: str = ""
    capabilities: list[str] = field(default_factory=list)


@dataclass
class ExecuteSampleMessage(AgentMessage):
    """Host → Agent: execute sample"""
    type: str = "execute_sample"
    sample_b64: str = ""
    sample_hash: str = ""
    sample_name: str = ""
    args: str = ""
    options: dict = field(default_factory=dict)


@dataclass
class ExecutionStartedMessage(AgentMessage):
    """Agent → Host: execution started"""
    type: str = "execution_started"
    pid: int = 0
    sample_path: str = ""


@dataclass
class ExecutionCompletedMessage(AgentMessage):
    """Agent → Host: execution completed"""
    type: str = "execution_completed"
    pid: int = 0
    return_code: int = 0
    duration_sec: float = 0.0


@dataclass
class EventBatchMessage(AgentMessage):
    """Agent → Host: batched events"""
    type: str = "events"
    events: list[dict] = field(default_factory=list)


@dataclass
class ScreenshotMessage(AgentMessage):
    """Agent → Host: screenshot capture"""
    type: str = "screenshot"
    data_b64: str = ""
    format: str = "png"
    width: int = 0
    height: int = 0


@dataclass
class MemoryDumpMessage(AgentMessage):
    """Agent → Host: memory dump ready"""
    type: str = "memory_dump"
    pid: int = 0
    path: str = ""
    size: int = 0


@dataclass
class DroppedFileMessage(AgentMessage):
    """Agent → Host: dropped file detected"""
    type: str = "dropped_file"
    path: str = ""
    hash: str = ""
    size: int = 0


@dataclass
class StatusMessage(AgentMessage):
    """Agent → Host: status update"""
    type: str = "status"
    running: bool = True
    monitors: dict = field(default_factory=dict)


@dataclass
class ErrorMessage(AgentMessage):
    """Agent → Host: error"""
    type: str = "error"
    message: str = ""
    fatal: bool = False


# Message type registry for deserialization
MESSAGE_TYPES = {
    "hello": HelloMessage,
    "execute_sample": ExecuteSampleMessage,
    "execution_started": ExecutionStartedMessage,
    "execution_completed": ExecutionCompletedMessage,
    "events": EventBatchMessage,
    "screenshot": ScreenshotMessage,
    "memory_dump": MemoryDumpMessage,
    "dropped_file": DroppedFileMessage,
    "status": StatusMessage,
    "error": ErrorMessage,
}


class AgentConnection:
    """Manages connection to a single guest agent via Unix socket"""
    
    def __init__(self, socket_path: str, task_id: str):
        self.socket_path = socket_path
        self.task_id = task_id
        self.reader: asyncio.StreamReader | None = None
        self.writer: asyncio.StreamWriter | None = None
        self.connected = False
        self.agent_id: str | None = None
        self._receive_task: asyncio.Task | None = None
        self._event_queue: asyncio.Queue = asyncio.Queue()
        self._response_futures: dict[str, asyncio.Future] = {}
        
    async def connect(self, timeout: float = 30.0) -> bool:
        """Connect to agent Unix socket"""
        try:
            self.reader, self.writer = await asyncio.wait_for(
                asyncio.open_unix_connection(self.socket_path),
                timeout=timeout
            )
            self.connected = True
            logger.info(f"Connected to agent at {self.socket_path}")
            
            # Start receive loop
            self._receive_task = asyncio.create_task(self._receive_loop())
            
            # Wait for hello message
            hello = await self._wait_for_message_type("hello", timeout=10.0)
            if hello:
                self.agent_id = hello.agent_id
                logger.info(f"Agent handshake complete: {self.agent_id} ({hello.platform})")
                return True
            return False
            
        except Exception as e:
            logger.exception(f"Failed to connect to agent: {e}")
            self.connected = False
            return False
    
    async def disconnect(self):
        """Disconnect from agent"""
        self.connected = False
        if self._receive_task:
            self._receive_task.cancel()
            try:
                await self._receive_task
            except asyncio.CancelledError:
                pass
        if self.writer:
            self.writer.close()
            await self.writer.wait_closed()
        logger.info(f"Disconnected from agent {self.agent_id}")
    
    async def _receive_loop(self):
        """Receive and parse messages from agent"""
        buffer = ""
        try:
            while self.connected and self.reader:
                data = await self.reader.read(8192)
                if not data:
                    break
                buffer += data.decode('utf-8', errors='replace')
                
                # Split by newlines
                while '\n' in buffer:
                    line, buffer = buffer.split('\n', 1)
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        msg_data = json.loads(line)
                        msg_type = msg_data.get('type', 'unknown')
                        msg_class = MESSAGE_TYPES.get(msg_type)
                        
                        if msg_class:
                            msg = msg_class(**msg_data)
                        else:
                            msg = AgentMessage(**msg_data)
                        
                        # Handle response futures
                        msg_id = msg_data.get('message_id')
                        if msg_id and msg_id in self._response_futures:
                            self._response_futures[msg_id].set_result(msg)
                            del self._response_futures[msg_id]
                        else:
                            # Queue for event processing
                            await self._event_queue.put(msg)
                            
                    except json.JSONDecodeError:
                        logger.warning(f"Invalid JSON from agent: {line[:100]}")
                    except Exception as e:
                        logger.exception(f"Error parsing agent message: {e}")
                        
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.exception(f"Receive loop error: {e}")
        finally:
            self.connected = False
    
    async def _wait_for_message_type(self, msg_type: str, timeout: float = 5.0):
        """Wait for a specific message type"""
        try:
            while True:
                msg = await asyncio.wait_for(self._event_queue.get(), timeout=timeout)
                if msg.type == msg_type:
                    return msg
                # Put back other messages
                await self._event_queue.put(msg)
        except asyncio.TimeoutError:
            return None
    
    async def send_message(self, message: AgentMessage) -> bool:
        """Send message to agent"""
        if not self.connected or not self.writer:
            return False
        try:
            data = json.dumps(message.__dict__, default=str) + '\n'
            self.writer.write(data.encode('utf-8'))
            await self.writer.drain()
            return True
        except Exception as e:
            logger.exception(f"Send error: {e}")
            self.connected = False
            return False
    
    async def send_and_wait(self, message: AgentMessage, response_type: str, timeout: float = 30.0):
        """Send message and wait for specific response type"""
        future = asyncio.get_event_loop().create_future()
        self._response_futures[message.message_id] = future
        
        if not await self.send_message(message):
            del self._response_futures[message.message_id]
            return None
        
        try:
            response = await asyncio.wait_for(future, timeout=timeout)
            if response.type == response_type:
                return response
            # Put back if wrong type
            await self._event_queue.put(response)
            return None
        except asyncio.TimeoutError:
            return None
        finally:
            self._response_futures.pop(message.message_id, None)
    
    async def execute_sample(self, sample_path: Path, args: str = "", options: dict | None = None) -> dict:
        """Send sample to agent for execution"""
        # Read and base64 encode sample
        sample_b64 = ""
        sample_hash = ""
        try:
            import hashlib
            sha256 = hashlib.sha256()
            async with aiofiles.open(sample_path, "rb") as f:
                content = await f.read()
                sample_b64 = base64.b64encode(content).decode('ascii')
                sha256.update(content)
                sample_hash = sha256.hexdigest()
        except Exception as e:
            logger.exception(f"Failed to read sample: {e}")
            return {"success": False, "error": str(e)}
        
        msg = ExecuteSampleMessage(
            sample_b64=sample_b64,
            sample_hash=sample_hash,
            sample_name=sample_path.name,
            args=args,
            options=options or {}
        )
        
        response = await self.send_and_wait(msg, "execution_started", timeout=10.0)
        if response:
            return {"success": True, "pid": response.pid, "sample_hash": sample_hash}
        return {"success": False, "error": "Agent did not confirm execution start"}
    
    async def get_events(self, timeout: float = 1.0) -> list[dict]:
        """Get pending events from agent"""
        events = []
        try:
            while True:
                msg = await asyncio.wait_for(self._event_queue.get(), timeout=timeout)
                if msg.type == "events":
                    events.extend(msg.events)
                elif msg.type == "screenshot":
                    events.append({
                        "type": "screenshot",
                        "timestamp": msg.timestamp,
                        "data_b64": msg.data_b64,
                        "format": msg.format,
                        "width": msg.width,
                        "height": msg.height
                    })
                elif msg.type == "memory_dump":
                    events.append({
                        "type": "memory_dump",
                        "timestamp": msg.timestamp,
                        "pid": msg.pid,
                        "path": msg.path,
                        "size": msg.size
                    })
                elif msg.type == "dropped_file":
                    events.append({
                        "type": "dropped_file",
                        "timestamp": msg.timestamp,
                        "path": msg.path,
                        "hash": msg.hash,
                        "size": msg.size
                    })
                elif msg.type == "execution_completed":
                    events.append({
                        "type": "execution_completed",
                        "timestamp": msg.timestamp,
                        "pid": msg.pid,
                        "return_code": msg.return_code,
                        "duration_sec": msg.duration_sec
                    })
                elif msg.type == "error":
                    events.append({
                        "type": "error",
                        "timestamp": msg.timestamp,
                        "message": msg.message,
                        "fatal": msg.fatal
                    })
                else:
                    # Put back unhandled messages
                    await self._event_queue.put(msg)
                    break
        except asyncio.TimeoutError:
            pass
        return events
    
    async def request_screenshot(self) -> dict | None:
        """Request immediate screenshot from agent"""
        msg = AgentMessage(type="capture_screenshot")
        response = await self.send_and_wait(msg, "screenshot", timeout=10.0)
        if response:
            return {
                "data_b64": response.data_b64,
                "format": response.format,
                "width": response.width,
                "height": response.height
            }
        return None
    
    async def request_memory_dump(self, pid: int) -> dict | None:
        """Request memory dump for process"""
        msg = AgentMessage(type="dump_memory", message_id=str(uuid.uuid4())[:8])
        # Add pid to message
        msg_dict = msg.__dict__
        msg_dict['pid'] = pid
        response = await self.send_and_wait(AgentMessage(**msg_dict), "memory_dump", timeout=30.0)
        if response:
            return {
                "pid": response.pid,
                "path": response.path,
                "size": response.size
            }
        return None
    
    async def terminate_sample(self, pid: int) -> bool:
        """Terminate running sample"""
        msg = AgentMessage(type="terminate_sample", message_id=str(uuid.uuid4())[:8])
        msg_dict = msg.__dict__
        msg_dict['pid'] = pid
        response = await self.send_and_wait(AgentMessage(**msg_dict), "status", timeout=5.0)
        return response is not None


class AgentConnectionManager:
    """Manages multiple agent connections"""
    
    def __init__(self):
        self.connections: dict[str, AgentConnection] = {}
    
    async def connect_agent(self, task_id: str, socket_path: str) -> AgentConnection | None:
        """Connect to agent for a task"""
        conn = AgentConnection(socket_path, task_id)
        if await conn.connect():
            self.connections[task_id] = conn
            return conn
        return None
    
    async def disconnect_agent(self, task_id: str):
        """Disconnect agent for a task"""
        conn = self.connections.pop(task_id, None)
        if conn:
            await conn.disconnect()
    
    def get_connection(self, task_id: str) -> AgentConnection | None:
        """Get agent connection for task"""
        return self.connections.get(task_id)


# Global connection manager
_connection_manager: AgentConnectionManager | None = None


def get_connection_manager() -> AgentConnectionManager:
    """Get global connection manager"""
    global _connection_manager
    if _connection_manager is None:
        _connection_manager = AgentConnectionManager()
    return _connection_manager


# Import aiofiles at module level to avoid circular imports
import aiofiles