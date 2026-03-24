"""Tests for the standalone mitmproxy addon.

Imports addon.py directly via importlib -- it does NOT import from mitm_mcp,
so it can run inside a separate mitmdump Python environment.
"""

import importlib.util
import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

_ADDON_PATH = Path(__file__).parent.parent / "src" / "mitm_mcp" / "addon.py"
_spec = importlib.util.spec_from_file_location("addon", _ADDON_PATH)
addon_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(addon_mod)
SecurityAddon = addon_mod.SecurityAddon


def _make_http_flow(
    method="GET",
    url="https://example.com/api",
    status=200,
    req_headers=None,
    res_headers=None,
    req_body=b"",
    res_body=b"",
):
    flow = MagicMock()
    flow.request.method = method
    flow.request.pretty_url = url
    flow.request.headers = req_headers or {}
    flow.request.get_content.return_value = req_body
    flow.response.status_code = status
    flow.response.headers = res_headers or {}
    flow.response.get_content.return_value = res_body
    return flow


def _read_jsonl(path):
    lines = path.read_text().strip().splitlines()
    return [json.loads(line) for line in lines if line.strip()]


class TestBearerToken:
    def test_bearer_token_in_auth_header(self, tmp_path):
        out = tmp_path / "flows.jsonl"
        addon = SecurityAddon(str(out))
        flow = _make_http_flow(
            req_headers={"Authorization": "Bearer sk-abc123"}
        )
        addon.response(flow)
        events = _read_jsonl(out)
        assert len(events) == 1
        findings = events[0]["findings"]
        assert any(f["category"] == "auth_token" for f in findings)
        token_finding = next(f for f in findings if f["category"] == "auth_token")
        assert "sk-abc123" in token_finding["value"]

    def test_token_prefix_in_auth_header(self, tmp_path):
        out = tmp_path / "flows.jsonl"
        addon = SecurityAddon(str(out))
        flow = _make_http_flow(
            req_headers={"Authorization": "token ghp_supersecret"}
        )
        addon.response(flow)
        events = _read_jsonl(out)
        findings = events[0]["findings"]
        assert any(f["category"] == "auth_token" for f in findings)


class TestApiKeyInUrl:
    def test_api_key_query_param(self, tmp_path):
        out = tmp_path / "flows.jsonl"
        addon = SecurityAddon(str(out))
        flow = _make_http_flow(
            url="https://api.example.com/data?api_key=secretvalue123&limit=10"
        )
        addon.response(flow)
        events = _read_jsonl(out)
        findings = events[0]["findings"]
        assert any(f["category"] == "auth_token" for f in findings)

    def test_access_token_query_param(self, tmp_path):
        out = tmp_path / "flows.jsonl"
        addon = SecurityAddon(str(out))
        flow = _make_http_flow(
            url="https://api.example.com/me?access_token=tok_live_xyz"
        )
        addon.response(flow)
        events = _read_jsonl(out)
        findings = events[0]["findings"]
        assert any(f["category"] == "auth_token" for f in findings)


class TestCredentialsInBody:
    def test_password_field_in_json_body(self, tmp_path):
        out = tmp_path / "flows.jsonl"
        addon = SecurityAddon(str(out))
        body = json.dumps({"username": "admin", "password": "hunter2"}).encode()
        flow = _make_http_flow(
            method="POST",
            url="https://device.local/api/login",
            req_body=body,
            req_headers={"Content-Type": "application/json"},
        )
        addon.response(flow)
        events = _read_jsonl(out)
        findings = events[0]["findings"]
        assert any(f["category"] == "credentials" for f in findings)

    def test_passwd_field_in_json_body(self, tmp_path):
        out = tmp_path / "flows.jsonl"
        addon = SecurityAddon(str(out))
        body = json.dumps({"user": "root", "passwd": "toor"}).encode()
        flow = _make_http_flow(
            method="POST",
            req_body=body,
            req_headers={"Content-Type": "application/json"},
        )
        addon.response(flow)
        events = _read_jsonl(out)
        findings = events[0]["findings"]
        assert any(f["category"] == "credentials" for f in findings)


class TestAwsCloudKeys:
    def test_aws_access_key_in_header(self, tmp_path):
        out = tmp_path / "flows.jsonl"
        addon = SecurityAddon(str(out))
        flow = _make_http_flow(
            req_headers={"X-AWS-Key": "AKIAIOSFODNN7EXAMPLE"}
        )
        addon.response(flow)
        events = _read_jsonl(out)
        findings = events[0]["findings"]
        assert any(f["category"] == "cloud_keys" for f in findings)

    def test_aws_key_in_body(self, tmp_path):
        out = tmp_path / "flows.jsonl"
        addon = SecurityAddon(str(out))
        body = b'{"aws_key": "AKIAIOSFODNN7EXAMPLE", "secret": "wJalrXUtnFEMI"}'
        flow = _make_http_flow(method="POST", req_body=body)
        addon.response(flow)
        events = _read_jsonl(out)
        findings = events[0]["findings"]
        assert any(f["category"] == "cloud_keys" for f in findings)

    def test_azure_storage_account_key_in_body(self, tmp_path):
        out = tmp_path / "flows.jsonl"
        addon = SecurityAddon(str(out))
        body = b"AccountKey=abc123base64=="
        flow = _make_http_flow(method="POST", req_body=body)
        addon.response(flow)
        events = _read_jsonl(out)
        findings = events[0]["findings"]
        assert any(f["category"] == "cloud_keys" for f in findings)

    def test_azure_sas_in_url(self, tmp_path):
        out = tmp_path / "flows.jsonl"
        addon = SecurityAddon(str(out))
        flow = _make_http_flow(
            url="https://myaccount.blob.core.windows.net/container/blob?SharedAccessSignature=sig%3Dabc123"
        )
        addon.response(flow)
        events = _read_jsonl(out)
        findings = events[0]["findings"]
        assert any(f["category"] == "cloud_keys" for f in findings)

    def test_azure_iothub_hostname_in_body(self, tmp_path):
        out = tmp_path / "flows.jsonl"
        addon = SecurityAddon(str(out))
        body = b'{"conn": "HostName=myhub.azure-devices.net;DeviceId=dev01"}'
        flow = _make_http_flow(method="POST", req_body=body)
        addon.response(flow)
        events = _read_jsonl(out)
        findings = events[0]["findings"]
        assert any(f["category"] == "cloud_keys" for f in findings)


class TestInterestingEndpoints:
    @pytest.mark.parametrize("path", [
        "/ota/check",
        "/update",
        "/firmware/latest",
        "/fw",
        "/admin/reboot",
        "/config",
        "/settings",
        "/upload",
        "/flash",
    ])
    def test_interesting_path(self, tmp_path, path):
        out = tmp_path / "flows.jsonl"
        addon = SecurityAddon(str(out))
        flow = _make_http_flow(url=f"https://device.local{path}")
        addon.response(flow)
        events = _read_jsonl(out)
        findings = events[0]["findings"]
        assert any(f["category"] == "interesting_endpoint" for f in findings), \
            f"Expected interesting_endpoint finding for path {path}"


class TestTlsEstablished:
    def test_tls_established_is_critical_cert_pinning(self, tmp_path):
        out = tmp_path / "flows.jsonl"
        addon = SecurityAddon(str(out))

        data = MagicMock()
        data.context.client.peername = ("192.168.1.100", 12345)
        data.context.server.address = ("example.com", 443)
        addon.tls_established_client(data)

        events = _read_jsonl(out)
        assert len(events) == 1
        event = events[0]
        assert event["type"] == "tls"
        assert event["cert_pinned"] is False
        findings = event["findings"]
        assert len(findings) == 1
        assert findings[0]["category"] == "cert_pinning"
        assert findings[0]["severity"] == "critical"


class TestCleanRequest:
    def test_no_findings_for_clean_request(self, tmp_path):
        out = tmp_path / "flows.jsonl"
        addon = SecurityAddon(str(out))
        flow = _make_http_flow(
            url="https://example.com/api/health",
            req_headers={"Accept": "application/json"},
            res_body=b'{"status": "ok"}',
        )
        addon.response(flow)
        events = _read_jsonl(out)
        assert len(events) == 1
        assert events[0]["findings"] == []


class TestMultipleFlows:
    def test_multiple_flows_produce_valid_jsonl(self, tmp_path):
        out = tmp_path / "flows.jsonl"
        addon = SecurityAddon(str(out))

        flows = [
            _make_http_flow(req_headers={"Authorization": "Bearer tok1"}),
            _make_http_flow(url="https://example.com/api/status"),
            _make_http_flow(url="https://device.local/admin"),
        ]
        for f in flows:
            addon.response(f)

        events = _read_jsonl(out)
        assert len(events) == 3
        for event in events:
            assert isinstance(event, dict)
            assert "ts" in event
            assert "type" in event
            assert "method" in event
            assert "url" in event
            assert "findings" in event

    def test_each_line_is_independent_json_object(self, tmp_path):
        out = tmp_path / "flows.jsonl"
        addon = SecurityAddon(str(out))

        for _ in range(5):
            addon.response(_make_http_flow())

        lines = out.read_text().strip().splitlines()
        assert len(lines) == 5
        for line in lines:
            obj = json.loads(line)
            assert isinstance(obj, dict)


class TestRequiredFields:
    def test_http_event_has_required_fields(self, tmp_path):
        out = tmp_path / "flows.jsonl"
        addon = SecurityAddon(str(out))
        addon.response(_make_http_flow())
        event = _read_jsonl(out)[0]
        for field in ("ts", "type", "method", "url", "findings"):
            assert field in event, f"Missing required field: {field}"

    def test_ts_is_iso8601_string(self, tmp_path):
        out = tmp_path / "flows.jsonl"
        addon = SecurityAddon(str(out))
        addon.response(_make_http_flow())
        event = _read_jsonl(out)[0]
        ts = event["ts"]
        assert isinstance(ts, str)
        assert "T" in ts

    def test_type_is_http(self, tmp_path):
        out = tmp_path / "flows.jsonl"
        addon = SecurityAddon(str(out))
        addon.response(_make_http_flow())
        event = _read_jsonl(out)[0]
        assert event["type"] == "http"


class TestBodyTruncation:
    def test_body_summary_truncated_to_1024_chars(self, tmp_path):
        out = tmp_path / "flows.jsonl"
        addon = SecurityAddon(str(out))
        long_body = b"x" * 4096
        flow = _make_http_flow(req_body=long_body, res_body=long_body)
        addon.response(flow)
        event = _read_jsonl(out)[0]
        assert len(event["req_body_summary"]) <= 1024
        assert len(event["res_body_summary"]) <= 1024

    def test_short_body_not_truncated(self, tmp_path):
        out = tmp_path / "flows.jsonl"
        addon = SecurityAddon(str(out))
        body = b'{"key": "value"}'
        flow = _make_http_flow(req_body=body)
        addon.response(flow)
        event = _read_jsonl(out)[0]
        assert event["req_body_summary"] == body.decode("utf-8", errors="replace")


class TestOutputEnvVar:
    def test_addon_uses_env_var_when_no_path_given(self, tmp_path, monkeypatch):
        out = tmp_path / "env_flows.jsonl"
        monkeypatch.setenv("MITM_FLOWS_OUTPUT", str(out))
        addon = SecurityAddon()
        addon.response(_make_http_flow())
        events = _read_jsonl(out)
        assert len(events) == 1

    def test_addon_falls_back_to_default_path(self, tmp_path, monkeypatch):
        monkeypatch.delenv("MITM_FLOWS_OUTPUT", raising=False)
        monkeypatch.chdir(tmp_path)
        addon = SecurityAddon()
        assert addon._output_path is not None


class TestAddonsEntryPoint:
    def test_addons_function_returns_list_with_security_addon(self):
        result = addon_mod.addons()
        assert isinstance(result, list)
        assert len(result) == 1
        assert isinstance(result[0], SecurityAddon)


class TestConnectionError:
    def test_tls_error_produces_informational_finding(self, tmp_path):
        out = tmp_path / "flows.jsonl"
        addon = SecurityAddon(str(out))

        flow = MagicMock()
        flow.request = MagicMock()
        flow.request.pretty_url = "https://example.com/api"
        flow.error = MagicMock()
        flow.error.msg = "TLS handshake failed"
        flow.response = None
        addon.error(flow)

        events = _read_jsonl(out)
        assert len(events) == 1
        event = events[0]
        assert event["type"] == "error"
        findings = event["findings"]
        assert any(f["category"] == "cert_pinning" for f in findings)
        tls_finding = next(f for f in findings if f["category"] == "cert_pinning")
        assert tls_finding["severity"] == "info"

    def test_non_tls_error_no_findings(self, tmp_path):
        out = tmp_path / "flows.jsonl"
        addon = SecurityAddon(str(out))

        flow = MagicMock()
        flow.request = MagicMock()
        flow.request.pretty_url = "https://example.com/api"
        flow.error = MagicMock()
        flow.error.msg = "Connection reset by peer"
        flow.response = None
        addon.error(flow)

        events = _read_jsonl(out)
        assert len(events) == 1
        assert events[0]["findings"] == []


class TestMqttConnect:
    def test_mqtt_connect_packet_detected(self, tmp_path):
        out = tmp_path / "flows.jsonl"
        addon = SecurityAddon(str(out))

        # Minimal MQTT CONNECT packet: first byte 0x10, then length,
        # then protocol name "MQTT" (4-byte string: 0x00 0x04 M Q T T),
        # protocol level 4, connect flags 0b11000000 (username+password),
        # keepalive, client id len 0x00 0x01 "d",
        # username len 0x00 0x04 "user", password len 0x00 0x04 "pass"
        payload = (
            b"\x10"       # CONNECT packet type
            b"\x19"       # remaining length (25)
            b"\x00\x04MQTT"   # protocol name
            b"\x04"           # protocol level (3.1.1)
            b"\xc2"           # connect flags: username + password + clean session
            b"\x00\x3c"       # keepalive 60s
            b"\x00\x01d"      # client id "d"
            b"\x00\x04user"   # username "user"
            b"\x00\x04pass"   # password "pass"
        )
        flow = MagicMock()
        flow.server_conn.address = ("mqtt.example.com", 8883)
        msg = MagicMock()
        msg.from_client = True
        msg.content = payload
        flow.messages = [msg]
        addon.tcp_message(flow)

        events = _read_jsonl(out)
        assert len(events) == 1
        event = events[0]
        assert event["type"] == "mqtt_connect"
        findings = event["findings"]
        assert any(f["category"] == "credentials" for f in findings)
