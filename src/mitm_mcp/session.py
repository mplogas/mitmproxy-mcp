"""Centralized session management for mitmdump and tshark subprocesses.

This is the ONLY module that manages long-lived subprocesses (Popen).
Tools call into session.py, they never manage subprocesses directly.
"""

import json
import logging
import os
import re
import signal
import shutil
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger(__name__)


def _find_bin(name: str) -> str | None:
    """Find an executable by name. Checks PATH, then the venv bin dir."""
    found = shutil.which(name)
    if found:
        return found
    # Fall back to looking next to the running Python interpreter
    # (handles venvs where bin/ is not on PATH)
    venv_bin = Path(sys.executable).parent / name
    if venv_bin.exists():
        return str(venv_bin)
    return None


def _find_addon_script() -> Path:
    """Locate addon.py relative to this module."""
    return Path(__file__).parent / "addon.py"


def _sanitize_name(name: str) -> str:
    """Strip everything except alphanumerics, hyphens, and underscores."""
    return re.sub(r"[^a-zA-Z0-9_-]", "", name) or "unnamed"


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _terminate_proc(proc: subprocess.Popen) -> None:
    """Terminate a subprocess gracefully, falling back to kill."""
    try:
        proc.terminate()
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)
    except OSError:
        pass


def _write_pid_file(path: Path, pid: int) -> None:
    """Write a PID to a file, creating parent dirs if needed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(str(pid))


def _remove_pid_file(path: Path) -> None:
    """Remove a PID file if it exists."""
    try:
        path.unlink()
    except FileNotFoundError:
        pass


def _kill_stale_pid(pid_path: Path, expected_name: str) -> None:
    """Read a PID file, kill the process if it matches expected_name, remove the file.

    Uses /proc/<pid>/comm on Linux to verify the process name before killing.
    This avoids killing an unrelated process that reused the PID.
    """
    if not pid_path.is_file():
        return

    try:
        pid = int(pid_path.read_text().strip())
    except (ValueError, OSError):
        _remove_pid_file(pid_path)
        return

    # Check if process exists and matches expected name
    try:
        comm_path = Path(f"/proc/{pid}/comm")
        if comm_path.exists():
            proc_name = comm_path.read_text().strip()
            if expected_name not in proc_name:
                log.debug(
                    "PID %d is %s, not %s -- removing stale PID file",
                    pid, proc_name, expected_name,
                )
                _remove_pid_file(pid_path)
                return
        else:
            # Process does not exist
            _remove_pid_file(pid_path)
            return

        log.info("Killing orphaned %s (PID %d)", expected_name, pid)
        os.kill(pid, signal.SIGTERM)

        # Wait briefly for it to die, then SIGKILL if needed
        for _ in range(10):
            if not comm_path.exists():
                break
            import time
            time.sleep(0.5)
        else:
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass

    except OSError:
        pass
    finally:
        _remove_pid_file(pid_path)


class Session:
    """Represents one MITM interception session with proxy and optional capture."""

    def __init__(
        self,
        session_id: str,
        engagement_path: Path,
        port: int,
        transparent: bool,
        proxy_proc: subprocess.Popen,
    ):
        self.session_id = session_id
        self.engagement_path = engagement_path
        self.port = port
        self.transparent = transparent
        self._proxy_proc = proxy_proc
        self._capture_proc: subprocess.Popen | None = None

        self.flows_path = engagement_path / "logs" / "flows.jsonl"
        self.pcap_path = engagement_path / "logs" / "capture.pcap"

        # Open event log
        self._event_log_path = engagement_path / "logs" / "events.jsonl"
        self._event_log = open(self._event_log_path, "a", encoding="utf-8")
        self._log_event("session_created", {
            "port": port,
            "transparent": transparent,
            "proxy_pid": proxy_proc.pid,
        })

    @property
    def proxy_running(self) -> bool:
        return self._proxy_proc is not None and self._proxy_proc.poll() is None

    @property
    def capture_running(self) -> bool:
        return self._capture_proc is not None and self._capture_proc.poll() is None

    def start_capture(self, tshark_proc: subprocess.Popen) -> None:
        """Attach a tshark subprocess to this session."""
        self._capture_proc = tshark_proc
        self._log_event("capture_started", {"tshark_pid": tshark_proc.pid})

    def stop_capture(self) -> None:
        """Terminate the tshark subprocess if running."""
        if self._capture_proc is not None:
            _terminate_proc(self._capture_proc)
            self._log_event("capture_stopped", {})
            self._capture_proc = None

    def close(self) -> None:
        """Terminate both subprocesses and finalize logs. Safe to call twice."""
        if self._capture_proc is not None:
            self.stop_capture()

        if self._proxy_proc is not None:
            _terminate_proc(self._proxy_proc)
            self._log_event("proxy_stopped", {})
            self._proxy_proc = None

        self._log_event("session_closed", {})
        if self._event_log and not self._event_log.closed:
            self._event_log.close()

    def _log_event(self, event_type: str, detail: dict) -> None:
        """Write a JSON line to the event log."""
        if self._event_log and not self._event_log.closed:
            entry = {"ts": _now_iso(), "event": event_type, **detail}
            self._event_log.write(json.dumps(entry) + "\n")
            self._event_log.flush()


class SessionManager:
    """Manages MITM interception sessions."""

    def __init__(self, engagements_dir: Path | str):
        self._engagements_dir = Path(engagements_dir)
        self._sessions: dict[str, Session] = {}
        self._mitmdump_pid_path = self._engagements_dir / ".mitmdump.pid"
        self._tshark_pid_path = self._engagements_dir / ".tshark.pid"
        self._cleanup_stale_processes()

    def _cleanup_stale_processes(self) -> None:
        """Kill orphaned mitmdump/tshark from a previous server run."""
        _kill_stale_pid(self._mitmdump_pid_path, "mitmdump")
        _kill_stale_pid(self._tshark_pid_path, "tshark")

    def create(
        self,
        name: str,
        port: int = 8080,
        transparent: bool = True,
        project_path: str | None = None,
    ) -> Session:
        """Create and start a new MITM session.

        Launches mitmdump, creates engagement folder structure, returns Session.
        Raises RuntimeError if mitmdump is not on PATH.
        """
        mitmdump_bin = _find_bin("mitmdump")
        if mitmdump_bin is None:
            raise RuntimeError(
                "mitmdump not found on PATH or in venv. "
                "Install with: pip install mitmproxy"
            )

        session_id = str(uuid.uuid4())

        if project_path is not None:
            resolved = Path(project_path).resolve()
            if not resolved.is_relative_to(self._engagements_dir.resolve()):
                raise ValueError("project_path must be under engagements directory")
            eng_path = resolved / "mitm"
            eng_path.mkdir(parents=True, exist_ok=True)
            (eng_path / "logs").mkdir(exist_ok=True)
            (eng_path / "artifacts").mkdir(exist_ok=True)
            (eng_path / "certs").mkdir(exist_ok=True)
        else:
            safe_name = _sanitize_name(name)
            timestamp = datetime.now().strftime("%d-%m-%Y-%H-%M")

            # Build unique folder name: DD-MM-YYYY-HH-MM_MITM_<name>
            folder_name = f"{timestamp}_MITM_{safe_name}"
            eng_path = self._engagements_dir / folder_name
            counter = 1
            while eng_path.exists():
                folder_name = f"{timestamp}_MITM_{safe_name}-{counter}"
                eng_path = self._engagements_dir / folder_name
                counter += 1

            # Create directory structure
            (eng_path / "logs").mkdir(parents=True)
            (eng_path / "artifacts").mkdir()
            (eng_path / "certs").mkdir()

        # Copy mitmproxy CA cert if available
        mitmproxy_ca = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"
        if mitmproxy_ca.exists():
            shutil.copy2(mitmproxy_ca, eng_path / "certs" / "mitmproxy-ca-cert.pem")

        # Write config
        config = {
            "session_id": session_id,
            "name": name,
            "port": port,
            "transparent": transparent,
            "created_at": _now_iso(),
        }
        (eng_path / "config.json").write_text(json.dumps(config, indent=2))

        # Build mitmdump command
        addon_path = str(_find_addon_script())
        flows_path = eng_path / "logs" / "flows.jsonl"
        cmd = [mitmdump_bin, "--listen-port", str(port), "-s", addon_path, "-q"]
        if transparent:
            cmd.extend(["--mode", "transparent"])

        env = os.environ.copy()
        env["MITM_FLOWS_OUTPUT"] = str(flows_path)

        proxy_proc = subprocess.Popen(cmd, env=env)
        _write_pid_file(self._mitmdump_pid_path, proxy_proc.pid)

        session = Session(
            session_id=session_id,
            engagement_path=eng_path,
            port=port,
            transparent=transparent,
            proxy_proc=proxy_proc,
        )
        self._sessions[session_id] = session
        return session

    def start_capture(
        self,
        session_id: str,
        interface: str = "wlan0",
    ) -> None:
        """Launch tshark for an existing session.

        Raises KeyError if session not found.
        Raises RuntimeError if tshark is not on PATH.
        """
        session = self.get(session_id)

        tshark_bin = _find_bin("tshark")
        if tshark_bin is None:
            raise RuntimeError(
                "tshark not found on PATH or in venv. "
                "Install with: apt install tshark"
            )

        cmd = [tshark_bin, "-i", interface, "-w", str(session.pcap_path), "-q"]
        tshark_proc = subprocess.Popen(cmd)
        _write_pid_file(self._tshark_pid_path, tshark_proc.pid)
        session.start_capture(tshark_proc)

    def stop_capture(self, session_id: str) -> None:
        """Stop tshark for an existing session."""
        session = self.get(session_id)
        session.stop_capture()
        _remove_pid_file(self._tshark_pid_path)

    def get(self, session_id: str) -> Session:
        """Return a session by ID. Raises KeyError if not found."""
        try:
            return self._sessions[session_id]
        except KeyError:
            raise KeyError(f"Session not found: {session_id}")

    def close(self, session_id: str) -> None:
        """Close a session, stopping all subprocesses and removing from tracking."""
        session = self.get(session_id)
        session.close()
        _remove_pid_file(self._mitmdump_pid_path)
        _remove_pid_file(self._tshark_pid_path)
        del self._sessions[session_id]
