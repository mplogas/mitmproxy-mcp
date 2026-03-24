"""Shared test fixtures for mitm-mcp tests."""

import json
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch


@pytest.fixture
def engagements_dir(tmp_path):
    """Temporary engagements directory for tests."""
    return tmp_path / "engagements"


@pytest.fixture
def mock_subprocess():
    """Mock subprocess.Popen that simulates a running process."""
    mock_proc = MagicMock()
    mock_proc.poll.return_value = None  # process is running
    mock_proc.pid = 12345
    mock_proc.returncode = None
    return mock_proc


@pytest.fixture
def sample_flows_jsonl(tmp_path):
    """Create a sample JSONL flow log for testing."""
    flows = [
        {
            "ts": "2026-03-24T14:30:00.123Z",
            "type": "http",
            "method": "POST",
            "url": "https://iot.example.com/api/telemetry",
            "status": 200,
            "req_headers": {"Authorization": "Bearer sk-abc123"},
            "res_headers": {"Content-Type": "application/json"},
            "req_body_summary": '{"temperature": 22.5}',
            "res_body_summary": '{"status": "ok"}',
            "findings": [
                {
                    "category": "auth_token",
                    "value": "sk-abc123",
                    "severity": "critical",
                    "detail": "Bearer token in Authorization header",
                }
            ],
        },
        {
            "ts": "2026-03-24T14:30:01.456Z",
            "type": "tls",
            "server": "iot.example.com:443",
            "cert_pinned": False,
            "findings": [
                {
                    "category": "cert_pinning",
                    "severity": "critical",
                    "detail": "No certificate pinning -- device accepted MITM CA",
                }
            ],
        },
        {
            "ts": "2026-03-24T14:30:02.789Z",
            "type": "http",
            "method": "GET",
            "url": "https://iot.example.com/api/config",
            "status": 200,
            "req_headers": {},
            "res_headers": {"Content-Type": "application/json"},
            "req_body_summary": "",
            "res_body_summary": '{"update_url": "https://ota.example.com/fw"}',
            "findings": [
                {
                    "category": "interesting_endpoint",
                    "severity": "high",
                    "detail": "OTA update URL discovered: https://ota.example.com/fw",
                }
            ],
        },
        {
            "ts": "2026-03-24T14:30:03.000Z",
            "type": "mqtt_connect",
            "server": "mqtt.example.com:8883",
            "username": "device-001",
            "password": "mqtt-secret-pw",
            "findings": [
                {
                    "category": "credentials",
                    "value": "device-001:mqtt-secret-pw",
                    "severity": "critical",
                    "detail": "MQTT broker credentials in CONNECT packet",
                }
            ],
        },
    ]
    jsonl_path = tmp_path / "flows.jsonl"
    with open(jsonl_path, "w") as f:
        for flow in flows:
            f.write(json.dumps(flow) + "\n")
    return jsonl_path
