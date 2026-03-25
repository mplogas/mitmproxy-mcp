"""Tests for session management -- mitmdump and tshark subprocess lifecycle."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch, call

import pytest

from mitm_mcp.session import (
    Session,
    SessionManager,
    _write_pid_file,
    _remove_pid_file,
    _kill_stale_pid,
)


class TestCreateSession:
    def test_create_session(self, engagements_dir, mock_subprocess):
        """Creates session with mock Popen, verifies session_id and proxy_running."""
        with patch("mitm_mcp.session._find_bin", return_value="/usr/bin/mitmdump"), \
             patch("subprocess.Popen", return_value=mock_subprocess):
            mgr = SessionManager(engagements_dir)
            session = mgr.create("test-device")
            assert session.session_id is not None
            assert session.proxy_running is True

    def test_engagement_folder_created(self, engagements_dir, mock_subprocess):
        """Verifies logs/, artifacts/, certs/ dirs exist after create."""
        with patch("mitm_mcp.session._find_bin", return_value="/usr/bin/mitmdump"), \
             patch("subprocess.Popen", return_value=mock_subprocess):
            mgr = SessionManager(engagements_dir)
            session = mgr.create("test-device")
            eng = session.engagement_path
            assert (eng / "logs").is_dir()
            assert (eng / "artifacts").is_dir()
            assert (eng / "certs").is_dir()

    def test_config_json_written(self, engagements_dir, mock_subprocess):
        """Verifies config.json has port, transparent, created_at."""
        with patch("mitm_mcp.session._find_bin", return_value="/usr/bin/mitmdump"), \
             patch("subprocess.Popen", return_value=mock_subprocess):
            mgr = SessionManager(engagements_dir)
            session = mgr.create("test-device", port=9090, transparent=False)
            config = json.loads((session.engagement_path / "config.json").read_text())
            assert config["port"] == 9090
            assert config["transparent"] is False
            assert "created_at" in config

    def test_engagement_name_sanitized(self, engagements_dir, mock_subprocess):
        """Evil name has no dots, slashes, or bangs after sanitization."""
        with patch("mitm_mcp.session._find_bin", return_value="/usr/bin/mitmdump"), \
             patch("subprocess.Popen", return_value=mock_subprocess):
            mgr = SessionManager(engagements_dir)
            session = mgr.create("../../etc/evil!")
            folder_name = session.engagement_path.name
            assert "." not in folder_name
            assert "/" not in folder_name
            assert "!" not in folder_name

    def test_duplicate_names_get_unique_folders(self, engagements_dir, mock_subprocess):
        """Two sessions with same name get different engagement paths."""
        with patch("mitm_mcp.session._find_bin", return_value="/usr/bin/mitmdump"), \
             patch("subprocess.Popen", return_value=mock_subprocess):
            mgr = SessionManager(engagements_dir)
            s1 = mgr.create("dupe")
            s2 = mgr.create("dupe")
            assert s1.engagement_path != s2.engagement_path

    def test_raises_if_mitmdump_not_on_path(self, engagements_dir):
        """RuntimeError if mitmdump binary not found."""
        with patch("mitm_mcp.session._find_bin", return_value=None):
            mgr = SessionManager(engagements_dir)
            with pytest.raises(RuntimeError, match="mitmdump"):
                mgr.create("test-device")


class TestGetSession:
    def test_get_session(self, engagements_dir, mock_subprocess):
        """Retrieves session by ID."""
        with patch("mitm_mcp.session._find_bin", return_value="/usr/bin/mitmdump"), \
             patch("subprocess.Popen", return_value=mock_subprocess):
            mgr = SessionManager(engagements_dir)
            session = mgr.create("test-device")
            retrieved = mgr.get(session.session_id)
            assert retrieved is session

    def test_get_nonexistent_session(self, engagements_dir):
        """KeyError on nonexistent session."""
        mgr = SessionManager(engagements_dir)
        with pytest.raises(KeyError):
            mgr.get("does-not-exist")


class TestCapture:
    def test_start_capture(self, engagements_dir, mock_subprocess):
        """tshark launched, capture_running is True."""
        tshark_proc = MagicMock()
        tshark_proc.poll.return_value = None
        tshark_proc.pid = 54321

        with patch("mitm_mcp.session._find_bin", return_value="/usr/bin/mitmdump"), \
             patch("subprocess.Popen", return_value=mock_subprocess) as popen_mock:
            mgr = SessionManager(engagements_dir)
            session = mgr.create("test-device")

        with patch("mitm_mcp.session._find_bin", return_value="/usr/bin/tshark"), \
             patch("subprocess.Popen", return_value=tshark_proc):
            mgr.start_capture(session.session_id)
            assert session.capture_running is True

    def test_stop_capture(self, engagements_dir, mock_subprocess):
        """terminate() called on tshark, capture_running is False."""
        tshark_proc = MagicMock()
        tshark_proc.poll.return_value = None
        tshark_proc.pid = 54321

        with patch("mitm_mcp.session._find_bin", return_value="/usr/bin/mitmdump"), \
             patch("subprocess.Popen", return_value=mock_subprocess):
            mgr = SessionManager(engagements_dir)
            session = mgr.create("test-device")

        with patch("mitm_mcp.session._find_bin", return_value="/usr/bin/tshark"), \
             patch("subprocess.Popen", return_value=tshark_proc):
            mgr.start_capture(session.session_id)

        mgr.stop_capture(session.session_id)
        tshark_proc.terminate.assert_called_once()
        assert session.capture_running is False

    def test_capture_without_proxy_raises(self, engagements_dir):
        """KeyError on nonexistent session for start_capture."""
        mgr = SessionManager(engagements_dir)
        with pytest.raises(KeyError):
            mgr.start_capture("nonexistent")

    def test_raises_if_tshark_not_on_path(self, engagements_dir, mock_subprocess):
        """RuntimeError if tshark binary not found."""
        with patch("mitm_mcp.session._find_bin", return_value="/usr/bin/mitmdump"), \
             patch("subprocess.Popen", return_value=mock_subprocess):
            mgr = SessionManager(engagements_dir)
            session = mgr.create("test-device")

        with patch("mitm_mcp.session._find_bin", return_value=None):
            with pytest.raises(RuntimeError, match="tshark"):
                mgr.start_capture(session.session_id)


class TestCloseSession:
    def test_close_session_stops_proxy(self, engagements_dir, mock_subprocess):
        """terminate() called on proxy mock proc."""
        with patch("mitm_mcp.session._find_bin", return_value="/usr/bin/mitmdump"), \
             patch("subprocess.Popen", return_value=mock_subprocess):
            mgr = SessionManager(engagements_dir)
            session = mgr.create("test-device")

        mgr.close(session.session_id)
        mock_subprocess.terminate.assert_called_once()

    def test_close_session_stops_both_subprocesses(self, engagements_dir, mock_subprocess):
        """Both proxy and capture processes terminated on close."""
        tshark_proc = MagicMock()
        tshark_proc.poll.return_value = None
        tshark_proc.pid = 54321

        with patch("mitm_mcp.session._find_bin", return_value="/usr/bin/mitmdump"), \
             patch("subprocess.Popen", return_value=mock_subprocess):
            mgr = SessionManager(engagements_dir)
            session = mgr.create("test-device")

        with patch("mitm_mcp.session._find_bin", return_value="/usr/bin/tshark"), \
             patch("subprocess.Popen", return_value=tshark_proc):
            mgr.start_capture(session.session_id)

        mgr.close(session.session_id)
        mock_subprocess.terminate.assert_called_once()
        tshark_proc.terminate.assert_called_once()

        # Session removed from manager
        with pytest.raises(KeyError):
            mgr.get(session.session_id)


class TestPidFileHelpers:
    def test_write_and_read_pid_file(self, tmp_path):
        """PID file is written with correct content."""
        pid_path = tmp_path / ".mitmdump.pid"
        _write_pid_file(pid_path, 42)
        assert pid_path.read_text() == "42"

    def test_remove_pid_file(self, tmp_path):
        """PID file is removed."""
        pid_path = tmp_path / ".mitmdump.pid"
        pid_path.write_text("42")
        _remove_pid_file(pid_path)
        assert not pid_path.exists()

    def test_remove_nonexistent_pid_file(self, tmp_path):
        """Removing a nonexistent PID file does not raise."""
        pid_path = tmp_path / ".mitmdump.pid"
        _remove_pid_file(pid_path)  # should not raise

    def test_kill_stale_pid_no_file(self, tmp_path):
        """No-op when PID file does not exist."""
        pid_path = tmp_path / ".mitmdump.pid"
        _kill_stale_pid(pid_path, "mitmdump")  # should not raise

    def test_kill_stale_pid_garbage_file(self, tmp_path):
        """Garbage content in PID file: file removed, no crash."""
        pid_path = tmp_path / ".mitmdump.pid"
        pid_path.write_text("not-a-number")
        _kill_stale_pid(pid_path, "mitmdump")
        assert not pid_path.exists()

    def test_kill_stale_pid_dead_process(self, tmp_path):
        """PID file for a dead process: file removed."""
        pid_path = tmp_path / ".mitmdump.pid"
        # Use PID 99999999 which almost certainly does not exist
        pid_path.write_text("99999999")
        _kill_stale_pid(pid_path, "mitmdump")
        assert not pid_path.exists()


class TestPidFileIntegration:
    def test_create_writes_mitmdump_pid(self, engagements_dir, mock_subprocess):
        """create() writes a .mitmdump.pid file."""
        with patch("mitm_mcp.session._find_bin", return_value="/usr/bin/mitmdump"), \
             patch("subprocess.Popen", return_value=mock_subprocess):
            mgr = SessionManager(engagements_dir)
            mgr.create("test-device")

        pid_path = engagements_dir / ".mitmdump.pid"
        assert pid_path.exists()
        assert pid_path.read_text() == str(mock_subprocess.pid)

    def test_close_removes_pid_files(self, engagements_dir, mock_subprocess):
        """close() removes both PID files."""
        with patch("mitm_mcp.session._find_bin", return_value="/usr/bin/mitmdump"), \
             patch("subprocess.Popen", return_value=mock_subprocess):
            mgr = SessionManager(engagements_dir)
            session = mgr.create("test-device")

        mgr.close(session.session_id)
        assert not (engagements_dir / ".mitmdump.pid").exists()
        assert not (engagements_dir / ".tshark.pid").exists()

    def test_start_capture_writes_tshark_pid(self, engagements_dir, mock_subprocess):
        """start_capture() writes a .tshark.pid file."""
        tshark_proc = MagicMock()
        tshark_proc.poll.return_value = None
        tshark_proc.pid = 54321

        with patch("mitm_mcp.session._find_bin", return_value="/usr/bin/mitmdump"), \
             patch("subprocess.Popen", return_value=mock_subprocess):
            mgr = SessionManager(engagements_dir)
            session = mgr.create("test-device")

        with patch("mitm_mcp.session._find_bin", return_value="/usr/bin/tshark"), \
             patch("subprocess.Popen", return_value=tshark_proc):
            mgr.start_capture(session.session_id)

        pid_path = engagements_dir / ".tshark.pid"
        assert pid_path.exists()
        assert pid_path.read_text() == "54321"

    def test_stop_capture_removes_tshark_pid(self, engagements_dir, mock_subprocess):
        """stop_capture() removes the .tshark.pid file."""
        tshark_proc = MagicMock()
        tshark_proc.poll.return_value = None
        tshark_proc.pid = 54321

        with patch("mitm_mcp.session._find_bin", return_value="/usr/bin/mitmdump"), \
             patch("subprocess.Popen", return_value=mock_subprocess):
            mgr = SessionManager(engagements_dir)
            session = mgr.create("test-device")

        with patch("mitm_mcp.session._find_bin", return_value="/usr/bin/tshark"), \
             patch("subprocess.Popen", return_value=tshark_proc):
            mgr.start_capture(session.session_id)

        mgr.stop_capture(session.session_id)
        assert not (engagements_dir / ".tshark.pid").exists()

    def test_init_cleans_stale_processes(self, engagements_dir):
        """SessionManager init calls cleanup for stale PIDs."""
        with patch("mitm_mcp.session._kill_stale_pid") as mock_kill:
            mgr = SessionManager(engagements_dir)
            assert mock_kill.call_count == 2
            mock_kill.assert_any_call(
                engagements_dir / ".mitmdump.pid", "mitmdump"
            )
            mock_kill.assert_any_call(
                engagements_dir / ".tshark.pid", "tshark"
            )
