"""Standalone mitmproxy addon for IoT security finding extraction.

IMPORTANT: This module MUST NOT import from mitm_mcp. It runs inside mitmdump's
Python environment, which may differ from the MCP server's. Communication with
the MCP server is via JSONL files only.

Entry point for mitmdump: the addons() function at module level.
Output path: MITM_FLOWS_OUTPUT env var, or 'flows.jsonl' in cwd.
"""

import json
import os
import re
import struct
from datetime import datetime, timezone
from pathlib import Path

_BODY_TRUNCATE = 1024

# Auth header prefixes that indicate credentials
_AUTH_PREFIXES = ("bearer ", "token ", "api_key ", "apikey ")

# URL query params that carry secrets
_SECRET_PARAMS = {"api_key", "token", "access_token", "secret", "key", "auth"}

# JSON body field names that contain passwords/secrets
_CRED_FIELDS = {"password", "passwd", "pass", "secret", "credential", "token"}

# Cloud key patterns (compiled once)
_RE_AWS_KEY = re.compile(r"AKIA[0-9A-Z]{16}")
_RE_AZURE_ACCOUNT_KEY = re.compile(r"AccountKey=")
_RE_AZURE_SAS = re.compile(r"SharedAccessSignature=")
_RE_AZURE_IOTHUB = re.compile(r"HostName=[\w.-]+\.azure-devices\.net")

# Interesting path segments (any of these appearing as a path component)
_INTERESTING_PATHS = {"/ota", "/update", "/firmware", "/fw", "/admin",
                      "/config", "/settings", "/upload", "/flash"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _truncate(data: bytes) -> str:
    text = data.decode("utf-8", errors="replace")
    return text[:_BODY_TRUNCATE]


def _scan_for_cloud_keys(text: str) -> list[dict]:
    findings = []
    if _RE_AWS_KEY.search(text):
        match = _RE_AWS_KEY.search(text)
        findings.append({
            "category": "cloud_keys",
            "value": match.group(0),
            "severity": "critical",
            "detail": "AWS access key ID (AKIA...) found",
        })
    if _RE_AZURE_ACCOUNT_KEY.search(text):
        findings.append({
            "category": "cloud_keys",
            "severity": "critical",
            "detail": "Azure storage AccountKey found",
        })
    if _RE_AZURE_SAS.search(text):
        findings.append({
            "category": "cloud_keys",
            "severity": "critical",
            "detail": "Azure Shared Access Signature found",
        })
    if _RE_AZURE_IOTHUB.search(text):
        findings.append({
            "category": "cloud_keys",
            "severity": "critical",
            "detail": "Azure IoT Hub hostname found",
        })
    return findings


def _scan_auth_headers(headers: dict) -> list[dict]:
    findings = []
    auth = headers.get("Authorization") or headers.get("authorization") or ""
    if auth:
        auth_lower = auth.lower()
        for prefix in _AUTH_PREFIXES:
            if auth_lower.startswith(prefix):
                value = auth[len(prefix):].strip()
                findings.append({
                    "category": "auth_token",
                    "value": value,
                    "severity": "critical",
                    "detail": f"Bearer/token credential in Authorization header",
                })
                break
    # Also scan all header values for AWS keys
    for v in headers.values():
        cloud = _scan_for_cloud_keys(str(v))
        findings.extend(cloud)
    return findings


def _scan_url(url: str) -> list[dict]:
    findings = []
    # Check query params
    if "?" in url:
        query = url.split("?", 1)[1]
        # Strip fragment
        if "#" in query:
            query = query.split("#", 1)[0]
        for part in query.split("&"):
            if "=" in part:
                k, _, v = part.partition("=")
                k_lower = k.lower()
                if k_lower in _SECRET_PARAMS and v:
                    findings.append({
                        "category": "auth_token",
                        "value": v,
                        "severity": "critical",
                        "detail": f"Credential in URL query param: {k}",
                    })
    # Cloud keys in URL
    findings.extend(_scan_for_cloud_keys(url))
    # Interesting paths
    path = url.split("?", 1)[0]
    if "://" in path:
        path = "/" + path.split("://", 1)[1].split("/", 1)[-1]
    path_lower = path.lower()
    for segment in _INTERESTING_PATHS:
        if path_lower == segment or path_lower.startswith(segment + "/") or path_lower.startswith(segment + "?"):
            findings.append({
                "category": "interesting_endpoint",
                "severity": "high",
                "detail": f"Sensitive endpoint: {path}",
            })
            break
    return findings


def _scan_body(body: bytes) -> list[dict]:
    if not body:
        return []
    findings = []
    text = body.decode("utf-8", errors="replace")
    # Cloud keys in body text
    findings.extend(_scan_for_cloud_keys(text))
    # Try to parse as JSON and look for credential fields
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            for key, val in obj.items():
                if key.lower() in _CRED_FIELDS and val:
                    findings.append({
                        "category": "credentials",
                        "value": str(val),
                        "severity": "critical",
                        "detail": f"Credential field '{key}' in request body",
                    })
    except (json.JSONDecodeError, ValueError):
        pass
    return findings


def _parse_mqtt_connect(payload: bytes) -> dict | None:
    """Parse an MQTT CONNECT packet. Returns dict with username/password or None."""
    if len(payload) < 2:
        return None
    if payload[0] != 0x10:
        return None
    # Skip fixed header (variable-length remaining length field)
    idx = 1
    multiplier = 1
    remaining = 0
    while idx < len(payload):
        byte = payload[idx]
        idx += 1
        remaining += (byte & 0x7F) * multiplier
        multiplier *= 128
        if not (byte & 0x80):
            break

    if idx + remaining > len(payload):
        return None

    data = payload[idx:]

    # Protocol name (length-prefixed string)
    if len(data) < 2:
        return None
    proto_len = struct.unpack_from(">H", data, 0)[0]
    if len(data) < 2 + proto_len + 4:
        return None
    # protocol_name = data[2:2+proto_len].decode("utf-8", errors="replace")
    pos = 2 + proto_len

    # protocol_level = data[pos]
    pos += 1
    if pos >= len(data):
        return None

    connect_flags = data[pos]
    pos += 1
    # keepalive (2 bytes)
    pos += 2

    has_username = bool(connect_flags & 0x80)
    has_password = bool(connect_flags & 0x40)

    # client id
    if pos + 2 > len(data):
        return None
    cid_len = struct.unpack_from(">H", data, pos)[0]
    pos += 2 + cid_len

    username = None
    password = None

    if has_username:
        if pos + 2 > len(data):
            return None
        ulen = struct.unpack_from(">H", data, pos)[0]
        pos += 2
        username = data[pos:pos + ulen].decode("utf-8", errors="replace")
        pos += ulen

    if has_password:
        if pos + 2 > len(data):
            return None
        plen = struct.unpack_from(">H", data, pos)[0]
        pos += 2
        password = data[pos:pos + plen].decode("utf-8", errors="replace")

    return {"username": username, "password": password}


class SecurityAddon:
    """mitmproxy addon that extracts security findings to a JSONL file."""

    def __init__(self, output_path: str | None = None):
        if output_path is not None:
            self._output_path = output_path
        else:
            env_path = os.environ.get("MITM_FLOWS_OUTPUT")
            if env_path:
                self._output_path = env_path
            else:
                self._output_path = str(Path.cwd() / "flows.jsonl")

    def _write_event(self, event: dict) -> None:
        with open(self._output_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(event) + "\n")

    def response(self, flow) -> None:
        """HTTP response hook -- analyze request and response for findings."""
        req = flow.request
        method = req.method
        url = req.pretty_url
        status = flow.response.status_code

        # Collect headers as plain dicts for serialization
        req_headers = dict(req.headers)
        res_headers = dict(flow.response.headers)

        req_body = req.get_content() or b""
        res_body = flow.response.get_content() or b""

        req_body_summary = _truncate(req_body)
        res_body_summary = _truncate(res_body)

        findings: list[dict] = []
        findings.extend(_scan_auth_headers(req_headers))
        findings.extend(_scan_url(url))
        findings.extend(_scan_body(req_body))

        event = {
            "ts": _now_iso(),
            "type": "http",
            "method": method,
            "url": url,
            "status": status,
            "req_headers": req_headers,
            "res_headers": res_headers,
            "req_body_summary": req_body_summary,
            "res_body_summary": res_body_summary,
            "findings": findings,
        }
        self._write_event(event)

    def tls_established_client(self, data) -> None:
        """TLS handshake completed. Device accepted our forged cert -- no pinning."""
        try:
            client_addr = data.context.client.peername
            server_addr = data.context.server.address
            server_str = f"{server_addr[0]}:{server_addr[1]}"
        except Exception:
            client_addr = ("unknown", 0)
            server_str = "unknown"

        findings = [{
            "category": "cert_pinning",
            "severity": "critical",
            "detail": "No certificate pinning -- device accepted MITM CA",
        }]

        event = {
            "ts": _now_iso(),
            "type": "tls",
            "server": server_str,
            "cert_pinned": False,
            "findings": findings,
        }
        self._write_event(event)

    def tcp_message(self, flow) -> None:
        """TCP message hook -- detect MQTT CONNECT packets."""
        try:
            for msg in flow.messages:
                if not msg.from_client:
                    continue
                content = msg.content
                if not content or content[0] != 0x10:
                    continue
                result = _parse_mqtt_connect(content)
                if result is None:
                    continue

                server_addr = flow.server_conn.address
                server_str = f"{server_addr[0]}:{server_addr[1]}"

                findings = []
                username = result.get("username")
                password = result.get("password")
                if username or password:
                    value = f"{username or ''}:{password or ''}"
                    findings.append({
                        "category": "credentials",
                        "value": value,
                        "severity": "critical",
                        "detail": "MQTT broker credentials in CONNECT packet",
                    })

                event = {
                    "ts": _now_iso(),
                    "type": "mqtt_connect",
                    "server": server_str,
                    "username": username,
                    "password": password,
                    "findings": findings,
                }
                self._write_event(event)
                break  # Only process first CONNECT per flow
        except Exception:
            pass  # Best-effort; don't crash mitmdump

    def error(self, flow) -> None:
        """Connection error hook -- TLS errors may indicate cert pinning."""
        try:
            url = flow.request.pretty_url
        except Exception:
            url = "unknown"

        try:
            error_msg = flow.error.msg if flow.error else ""
        except Exception:
            error_msg = ""

        findings = []
        if "tls" in error_msg.lower() or "ssl" in error_msg.lower() or "certificate" in error_msg.lower():
            findings.append({
                "category": "cert_pinning",
                "severity": "info",
                "detail": f"TLS error may indicate cert pinning: {error_msg}",
            })

        event = {
            "ts": _now_iso(),
            "type": "error",
            "url": url,
            "error": error_msg,
            "findings": findings,
        }
        self._write_event(event)


# mitmproxy entry point: module-level list of addon instances.
# mitmproxy 11.x iterates this directly (not a callable).
addons = [SecurityAddon()]
