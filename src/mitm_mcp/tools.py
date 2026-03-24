"""MCP tool implementations for MITM interception.

Each function is async, returns a dict, and delegates subprocess lifecycle
to session.py. Short-lived subprocess.run calls (AP scripts) are the one
exception -- same pattern as buspirate-mcp calling esptool.
"""

import json
import subprocess
from pathlib import Path

from .session import SessionManager


async def tool_start_ap(script_path: str) -> dict:
    """Run AP toggle script with 'start' argument."""
    path = Path(script_path)
    if not path.exists():
        return {"error": f"Script not found: {script_path}"}

    try:
        result = subprocess.run(
            [str(path), "start"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            return {"error": f"Script failed (rc={result.returncode}): {result.stderr.strip()}"}
        return {"status": "started"}
    except subprocess.TimeoutExpired:
        return {"error": "Script timed out after 30 seconds"}
    except OSError as exc:
        return {"error": str(exc)}


async def tool_stop_ap(script_path: str) -> dict:
    """Run AP toggle script with 'stop' argument."""
    path = Path(script_path)
    if not path.exists():
        return {"error": f"Script not found: {script_path}"}

    try:
        result = subprocess.run(
            [str(path), "stop"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            return {"error": f"Script failed (rc={result.returncode}): {result.stderr.strip()}"}
        return {"status": "stopped"}
    except subprocess.TimeoutExpired:
        return {"error": "Script timed out after 30 seconds"}
    except OSError as exc:
        return {"error": str(exc)}


async def tool_list_clients(leases_path: str) -> dict:
    """Parse dnsmasq leases file and return connected clients.

    Lease line format: timestamp mac ip hostname *
    """
    path = Path(leases_path)
    if not path.exists():
        return {
            "clients": [],
            "hint": f"Leases file not found: {leases_path}. Is dnsmasq running?",
        }

    clients = []
    for line in path.read_text().splitlines():
        parts = line.strip().split()
        if len(parts) >= 4:
            clients.append({
                "timestamp": parts[0],
                "mac": parts[1],
                "ip": parts[2],
                "hostname": parts[3],
            })
    return {"clients": clients}


async def tool_start_proxy(
    session_manager: SessionManager,
    engagement_name: str,
    port: int = 8080,
    transparent: bool = True,
) -> dict:
    """Create a new MITM proxy session."""
    if not (1 <= port <= 65535):
        return {"error": f"Invalid port: {port}. Must be 1-65535."}

    try:
        session = session_manager.create(engagement_name, port=port, transparent=transparent)
    except RuntimeError as exc:
        return {"error": str(exc)}

    return {
        "session_id": session.session_id,
        "engagement_path": str(session.engagement_path),
        "port": session.port,
        "transparent": session.transparent,
        "flows_path": str(session.flows_path),
    }


async def tool_stop_proxy(
    session_manager: SessionManager,
    session_id: str,
) -> dict:
    """Close a MITM proxy session."""
    try:
        session_manager.close(session_id)
    except KeyError:
        return {"error": f"Session not found: {session_id}"}
    return {"closed": True}


async def tool_start_capture(
    session_manager: SessionManager,
    session_id: str,
    interface: str = "wlan0",
) -> dict:
    """Start tshark packet capture for an existing session."""
    try:
        session = session_manager.get(session_id)
    except KeyError:
        return {"error": f"Session not found: {session_id}"}

    try:
        session_manager.start_capture(session_id, interface=interface)
    except RuntimeError as exc:
        return {"error": str(exc)}

    return {"pcap_path": str(session.pcap_path)}


async def tool_stop_capture(
    session_manager: SessionManager,
    session_id: str,
) -> dict:
    """Stop tshark packet capture for an existing session."""
    try:
        session_manager.stop_capture(session_id)
    except KeyError:
        return {"error": f"Session not found: {session_id}"}
    return {"stopped": True}


async def tool_get_flows(
    flows_path: str,
    host_filter: str | None = None,
    path_filter: str | None = None,
    protocol_filter: str | None = None,
    last_n: int = 20,
) -> dict:
    """Read JSONL flow log, apply filters, return last N entries."""
    path = Path(flows_path)
    if not path.exists():
        return {"flows": [], "total": 0}

    flows = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue

        if host_filter:
            # Match against url or server field
            url = entry.get("url", "")
            server = entry.get("server", "")
            if host_filter not in url and host_filter not in server:
                continue

        if path_filter:
            url = entry.get("url", "")
            if path_filter not in url:
                continue

        if protocol_filter:
            if entry.get("type", "") != protocol_filter:
                continue

        flows.append(entry)

    total = len(flows)
    flows = flows[-last_n:]
    return {"flows": flows, "total": total}


async def tool_get_findings(flows_path: str) -> dict:
    """Read JSONL flow log, extract all findings with source context."""
    path = Path(flows_path)
    if not path.exists():
        return {"findings": []}

    findings = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue

        for finding in entry.get("findings", []):
            enriched = dict(finding)
            enriched["source_ts"] = entry.get("ts")
            enriched["source_type"] = entry.get("type")
            findings.append(enriched)

    return {"findings": findings}


async def tool_capture_status(
    session_manager: SessionManager,
    session_id: str,
) -> dict:
    """Return current status of proxy and capture for a session."""
    try:
        session = session_manager.get(session_id)
    except KeyError:
        return {"error": f"Session not found: {session_id}"}

    # Count lines in flows JSONL
    flow_count = 0
    if session.flows_path.exists():
        flow_count = sum(
            1 for line in session.flows_path.read_text().splitlines()
            if line.strip()
        )

    # Get pcap file size
    pcap_bytes = 0
    if session.pcap_path.exists():
        pcap_bytes = session.pcap_path.stat().st_size

    return {
        "proxy_running": session.proxy_running,
        "capture_running": session.capture_running,
        "flow_count": flow_count,
        "pcap_bytes": pcap_bytes,
    }
