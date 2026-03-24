"""Tests for MCP tool implementations."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from mitm_mcp.session import SessionManager
from mitm_mcp.tools import (
    tool_capture_status,
    tool_get_findings,
    tool_get_flows,
    tool_list_clients,
    tool_start_ap,
    tool_start_capture,
    tool_start_proxy,
    tool_stop_ap,
    tool_stop_capture,
    tool_stop_proxy,
)


def _make_manager(engagements_dir, mock_subprocess):
    """Create a SessionManager and one session with mocked subprocesses."""
    with patch("shutil.which", return_value="/usr/bin/mitmdump"), \
         patch("subprocess.Popen", return_value=mock_subprocess):
        mgr = SessionManager(engagements_dir)
        session = mgr.create("test-device")
    return mgr, session


class TestStartProxy:
    @pytest.mark.asyncio
    async def test_creates_session(self, engagements_dir, mock_subprocess):
        with patch("shutil.which", return_value="/usr/bin/mitmdump"), \
             patch("subprocess.Popen", return_value=mock_subprocess):
            mgr = SessionManager(engagements_dir)
            result = await tool_start_proxy(mgr, "test-device", port=8080)

        assert "session_id" in result
        assert result["port"] == 8080
        assert result["transparent"] is True
        assert "flows_path" in result

    @pytest.mark.asyncio
    async def test_rejects_invalid_port_zero(self, engagements_dir):
        mgr = SessionManager(engagements_dir)
        result = await tool_start_proxy(mgr, "test-device", port=0)
        assert "error" in result

    @pytest.mark.asyncio
    async def test_rejects_invalid_port_high(self, engagements_dir):
        mgr = SessionManager(engagements_dir)
        result = await tool_start_proxy(mgr, "test-device", port=70000)
        assert "error" in result

    @pytest.mark.asyncio
    async def test_rejects_negative_port(self, engagements_dir):
        mgr = SessionManager(engagements_dir)
        result = await tool_start_proxy(mgr, "test-device", port=-1)
        assert "error" in result


class TestStopProxy:
    @pytest.mark.asyncio
    async def test_closes_session(self, engagements_dir, mock_subprocess):
        mgr, session = _make_manager(engagements_dir, mock_subprocess)
        result = await tool_stop_proxy(mgr, session.session_id)
        assert result == {"closed": True}

    @pytest.mark.asyncio
    async def test_handles_nonexistent_session(self, engagements_dir):
        mgr = SessionManager(engagements_dir)
        result = await tool_stop_proxy(mgr, "does-not-exist")
        assert "error" in result


class TestGetFlows:
    @pytest.mark.asyncio
    async def test_returns_all_flows(self, sample_flows_jsonl):
        result = await tool_get_flows(str(sample_flows_jsonl))
        assert result["total"] == 4
        assert len(result["flows"]) == 4

    @pytest.mark.asyncio
    async def test_filters_by_host(self, sample_flows_jsonl):
        result = await tool_get_flows(str(sample_flows_jsonl), host_filter="mqtt.example.com")
        assert result["total"] == 1
        assert result["flows"][0]["type"] == "mqtt_connect"

    @pytest.mark.asyncio
    async def test_filters_by_path(self, sample_flows_jsonl):
        result = await tool_get_flows(str(sample_flows_jsonl), path_filter="/api/config")
        assert result["total"] == 1
        assert "/api/config" in result["flows"][0]["url"]

    @pytest.mark.asyncio
    async def test_filters_by_protocol(self, sample_flows_jsonl):
        result = await tool_get_flows(str(sample_flows_jsonl), protocol_filter="http")
        assert result["total"] == 2
        for flow in result["flows"]:
            assert flow["type"] == "http"

    @pytest.mark.asyncio
    async def test_respects_last_n(self, sample_flows_jsonl):
        result = await tool_get_flows(str(sample_flows_jsonl), last_n=2)
        assert result["total"] == 4
        assert len(result["flows"]) == 2
        # Should be the last 2 entries
        assert result["flows"][0]["type"] == "http"
        assert result["flows"][1]["type"] == "mqtt_connect"

    @pytest.mark.asyncio
    async def test_handles_empty_file(self, tmp_path):
        empty = tmp_path / "empty.jsonl"
        empty.write_text("")
        result = await tool_get_flows(str(empty))
        assert result == {"flows": [], "total": 0}

    @pytest.mark.asyncio
    async def test_handles_missing_file(self, tmp_path):
        result = await tool_get_flows(str(tmp_path / "nonexistent.jsonl"))
        assert result == {"flows": [], "total": 0}


class TestGetFindings:
    @pytest.mark.asyncio
    async def test_extracts_all_findings(self, sample_flows_jsonl):
        result = await tool_get_findings(str(sample_flows_jsonl))
        findings = result["findings"]
        assert len(findings) == 4

        categories = {f["category"] for f in findings}
        assert "auth_token" in categories
        assert "cert_pinning" in categories
        assert "interesting_endpoint" in categories
        assert "credentials" in categories

    @pytest.mark.asyncio
    async def test_findings_have_source_context(self, sample_flows_jsonl):
        result = await tool_get_findings(str(sample_flows_jsonl))
        for finding in result["findings"]:
            assert "source_ts" in finding
            assert "source_type" in finding

    @pytest.mark.asyncio
    async def test_handles_empty_file(self, tmp_path):
        empty = tmp_path / "empty.jsonl"
        empty.write_text("")
        result = await tool_get_findings(str(empty))
        assert result == {"findings": []}

    @pytest.mark.asyncio
    async def test_handles_missing_file(self, tmp_path):
        result = await tool_get_findings(str(tmp_path / "nonexistent.jsonl"))
        assert result == {"findings": []}


class TestCaptureStatus:
    @pytest.mark.asyncio
    async def test_reports_running_state(self, engagements_dir, mock_subprocess):
        mgr, session = _make_manager(engagements_dir, mock_subprocess)

        # Write some flow lines
        session.flows_path.write_text('{"type":"http"}\n{"type":"tls"}\n')

        # Create a pcap file with some bytes
        session.pcap_path.write_bytes(b"\x00" * 1024)

        result = await tool_capture_status(mgr, session.session_id)
        assert result["proxy_running"] is True
        assert result["capture_running"] is False
        assert result["flow_count"] == 2
        assert result["pcap_bytes"] == 1024

    @pytest.mark.asyncio
    async def test_handles_nonexistent_session(self, engagements_dir):
        mgr = SessionManager(engagements_dir)
        result = await tool_capture_status(mgr, "does-not-exist")
        assert "error" in result


class TestAPToggle:
    @pytest.mark.asyncio
    async def test_start_ap_works(self, tmp_path):
        script = tmp_path / "ap_toggle.sh"
        script.write_text("#!/bin/bash\necho ok")
        script.chmod(0o755)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="")
            result = await tool_start_ap(str(script))

        assert result == {"status": "started"}
        mock_run.assert_called_once()
        args = mock_run.call_args
        assert args[0][0] == [str(script), "start"]

    @pytest.mark.asyncio
    async def test_stop_ap_works(self, tmp_path):
        script = tmp_path / "ap_toggle.sh"
        script.write_text("#!/bin/bash\necho ok")
        script.chmod(0o755)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="")
            result = await tool_stop_ap(str(script))

        assert result == {"status": "stopped"}
        args = mock_run.call_args
        assert args[0][0] == [str(script), "stop"]

    @pytest.mark.asyncio
    async def test_script_not_found_returns_error(self):
        result = await tool_start_ap("/nonexistent/script.sh")
        assert "error" in result
        assert "not found" in result["error"]

    @pytest.mark.asyncio
    async def test_script_failure_returns_error(self, tmp_path):
        script = tmp_path / "ap_toggle.sh"
        script.write_text("#!/bin/bash\nexit 1")
        script.chmod(0o755)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stderr="something broke")
            result = await tool_start_ap(str(script))

        assert "error" in result
        assert "something broke" in result["error"]


class TestListClients:
    @pytest.mark.asyncio
    async def test_parses_dnsmasq_leases(self, tmp_path):
        leases = tmp_path / "dnsmasq.leases"
        leases.write_text(
            "1711300200 aa:bb:cc:dd:ee:01 192.168.4.10 esp32-device *\n"
            "1711300300 aa:bb:cc:dd:ee:02 192.168.4.11 rpi-camera *\n"
        )
        result = await tool_list_clients(str(leases))
        assert len(result["clients"]) == 2
        assert result["clients"][0]["mac"] == "aa:bb:cc:dd:ee:01"
        assert result["clients"][0]["ip"] == "192.168.4.10"
        assert result["clients"][0]["hostname"] == "esp32-device"
        assert result["clients"][1]["hostname"] == "rpi-camera"

    @pytest.mark.asyncio
    async def test_handles_missing_leases_file(self, tmp_path):
        result = await tool_list_clients(str(tmp_path / "nonexistent.leases"))
        assert result["clients"] == []
        assert "hint" in result


class TestStartCapture:
    @pytest.mark.asyncio
    async def test_start_capture(self, engagements_dir, mock_subprocess):
        mgr, session = _make_manager(engagements_dir, mock_subprocess)

        tshark_proc = MagicMock()
        tshark_proc.poll.return_value = None
        tshark_proc.pid = 54321

        with patch("shutil.which", return_value="/usr/bin/tshark"), \
             patch("subprocess.Popen", return_value=tshark_proc):
            result = await tool_start_capture(mgr, session.session_id)

        assert "pcap_path" in result

    @pytest.mark.asyncio
    async def test_handles_nonexistent_session(self, engagements_dir):
        mgr = SessionManager(engagements_dir)
        result = await tool_start_capture(mgr, "does-not-exist")
        assert "error" in result


class TestStopCapture:
    @pytest.mark.asyncio
    async def test_stop_capture(self, engagements_dir, mock_subprocess):
        mgr, session = _make_manager(engagements_dir, mock_subprocess)

        tshark_proc = MagicMock()
        tshark_proc.poll.return_value = None
        tshark_proc.pid = 54321

        with patch("shutil.which", return_value="/usr/bin/tshark"), \
             patch("subprocess.Popen", return_value=tshark_proc):
            mgr.start_capture(session.session_id)

        result = await tool_stop_capture(mgr, session.session_id)
        assert result == {"stopped": True}

    @pytest.mark.asyncio
    async def test_handles_nonexistent_session(self, engagements_dir):
        mgr = SessionManager(engagements_dir)
        result = await tool_stop_capture(mgr, "does-not-exist")
        assert "error" in result
