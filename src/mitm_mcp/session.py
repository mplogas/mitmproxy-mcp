"""Centralized session management for mitmdump and tshark subprocesses.

This is the ONLY module that manages long-lived subprocesses (Popen).
Tools call into session.py, they never manage subprocesses directly.
"""

import json
import os
import re
import shutil
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path


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

    def create(
        self,
        name: str,
        port: int = 8080,
        transparent: bool = True,
    ) -> Session:
        """Create and start a new MITM session.

        Launches mitmdump, creates engagement folder structure, returns Session.
        Raises RuntimeError if mitmdump is not on PATH.
        """
        mitmdump_bin = shutil.which("mitmdump")
        if mitmdump_bin is None:
            raise RuntimeError("mitmdump not found on PATH")

        session_id = str(uuid.uuid4())
        safe_name = _sanitize_name(name)
        date_prefix = datetime.now(timezone.utc).strftime("%Y%m%d")

        # Build unique folder name
        folder_name = f"{date_prefix}-{safe_name}"
        eng_path = self._engagements_dir / folder_name
        counter = 1
        while eng_path.exists():
            folder_name = f"{date_prefix}-{safe_name}-{counter}"
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

        tshark_bin = shutil.which("tshark")
        if tshark_bin is None:
            raise RuntimeError("tshark not found on PATH")

        cmd = [tshark_bin, "-i", interface, "-w", str(session.pcap_path), "-q"]
        tshark_proc = subprocess.Popen(cmd)
        session.start_capture(tshark_proc)

    def stop_capture(self, session_id: str) -> None:
        """Stop tshark for an existing session."""
        session = self.get(session_id)
        session.stop_capture()

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
        del self._sessions[session_id]
