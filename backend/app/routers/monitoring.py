"""
Real-time monitoring API routes.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from app.auth.rbac import User, require_analyst
from app.monitoring.transfer_monitor import get_monitoring_service

router = APIRouter(prefix="/monitoring", tags=["monitoring"])


@router.get("/status")
async def monitoring_status(current_user: User = Depends(require_analyst)):
    """Get monitoring service status."""
    service = get_monitoring_service()
    if not service:
        return {"enabled": False, "message": "Monitoring not enabled"}
    
    return {
        "enabled": True,
        "filesystem_monitoring": service.fs_monitor is not None,
        "network_monitoring": service.net_monitor is not None,
        "watch_paths": service.fs_monitor.watch_paths if service.fs_monitor else [],
        "analyzer_running": service.analyzer._worker_task is not None and not service.analyzer._worker_task.done(),
        "pending_queue_size": service.analyzer.pending_queue.qsize(),
    }


@router.get("/transfers")
async def list_transfers(
    limit: int = Query(100, le=1000),
    offset: int = Query(0, ge=0),
    verdict: str | None = None,
    current_user: User = Depends(require_analyst),
):
    """List recent file transfer events."""
    service = get_monitoring_service()
    if not service:
        raise HTTPException(status_code=404, detail="Monitoring not enabled")
    
    transfers = service.get_recent_transfers(limit + offset)
    transfers = transfers[offset:offset + limit]
    
    if verdict:
        transfers = [t for t in transfers if t.verdict == verdict]
    
    return [
        {
            "event_id": t.event_id,
            "timestamp": t.timestamp.isoformat() + "Z",
            "source_path": t.source_path,
            "dest_path": t.dest_path,
            "process_name": t.process_name,
            "process_pid": t.process_pid,
            "user": t.user,
            "file_size": t.file_size,
            "file_hash": t.file_hash,
            "transfer_type": t.transfer_type,
            "network_info": t.network_info,
            "analyzed": t.analyzed,
            "verdict": t.verdict,
            "risk_score": t.risk_score,
        }
        for t in transfers
    ]


@router.get("/transfers/{event_id}")
async def get_transfer(event_id: str, current_user: User = Depends(require_analyst)):
    """Get detailed transfer event with analysis results."""
    service = get_monitoring_service()
    if not service:
        raise HTTPException(status_code=404, detail="Monitoring not enabled")
    
    # Find transfer in recent events
    transfers = service.get_recent_transfers(10000)
    transfer = next((t for t in transfers if t.event_id == event_id), None)
    
    if not transfer:
        raise HTTPException(status_code=404, detail="Transfer event not found")
    
    result = service.get_analysis_result(event_id)
    
    return {
        "event": {
            "event_id": transfer.event_id,
            "timestamp": transfer.timestamp.isoformat() + "Z",
            "source_path": transfer.source_path,
            "dest_path": transfer.dest_path,
            "process_name": transfer.process_name,
            "process_pid": transfer.process_pid,
            "user": transfer.user,
            "file_size": transfer.file_size,
            "file_hash": transfer.file_hash,
            "transfer_type": transfer.transfer_type,
            "network_info": transfer.network_info,
            "analyzed": transfer.analyzed,
            "verdict": transfer.verdict,
            "risk_score": transfer.risk_score,
        },
        "analysis": result,
    }


@router.post("/transfers/{event_id}/reanalyze")
async def reanalyze_transfer(event_id: str, current_user: User = Depends(require_analyst)):
    """Re-analyze a transfer event."""
    service = get_monitoring_service()
    if not service:
        raise HTTPException(status_code=404, detail="Monitoring not enabled")
    
    transfers = service.get_recent_transfers(10000)
    transfer = next((t for t in transfers if t.event_id == event_id), None)
    
    if not transfer:
        raise HTTPException(status_code=404, detail="Transfer event not found")
    
    # Re-queue for analysis
    transfer.analyzed = False
    transfer.verdict = "pending"
    await service.analyzer.analyze(transfer)
    
    return {"message": "Re-analysis queued", "event_id": event_id}


@router.get("/network/flows")
async def list_network_flows(
    suspicious_only: bool = Query(True),
    min_packets: int = Query(5, ge=1),
    current_user: User = Depends(require_analyst),
):
    """List detected network flows."""
    service = get_monitoring_service()
    if not service or not service.net_monitor:
        raise HTTPException(status_code=404, detail="Network monitoring not enabled")
    
    if suspicious_only:
        flows = service.get_suspicious_network_flows()
        flows = [f for f in flows if f.packet_count >= min_packets]
    else:
        flows = list(service.net_monitor.flows.values())
    
    return [
        {
            "src_ip": f.src_ip,
            "dst_ip": f.dst_ip,
            "src_port": f.src_port,
            "dst_port": f.dst_port,
            "protocol": f.protocol,
            "start_time": f.start_time.isoformat() + "Z",
            "end_time": f.end_time.isoformat() + "Z" if f.end_time else None,
            "bytes_sent": f.bytes_sent,
            "bytes_recv": f.bytes_recv,
            "packet_count": f.packet_count,
            "process_name": f.process_name,
            "process_pid": f.process_pid,
        }
        for f in flows
    ]


@router.get("/stats")
async def monitoring_stats(current_user: User = Depends(require_analyst)):
    """Get monitoring statistics."""
    service = get_monitoring_service()
    if not service:
        raise HTTPException(status_code=404, detail="Monitoring not enabled")
    
    transfers = service.get_recent_transfers(10000)
    
    total = len(transfers)
    analyzed = sum(1 for t in transfers if t.analyzed)
    malicious = sum(1 for t in transfers if t.verdict == "malicious")
    suspicious = sum(1 for t in transfers if t.verdict == "suspicious")
    clean = sum(1 for t in transfers if t.verdict == "clean")
    pending = sum(1 for t in transfers if t.verdict == "pending")
    
    return {
        "total_events": total,
        "analyzed": analyzed,
        "pending": pending,
        "verdicts": {
            "malicious": malicious,
            "suspicious": suspicious,
            "clean": clean,
            "unknown": pending,
        },
        "queue_size": service.analyzer.pending_queue.qsize(),
        "results_cached": len(service.analyzer.results),
    }