"""Three-tier safety model for MITM MCP tools.

Tiers:
  read-only       -- full autonomy, no side effects
  allowed-write   -- autonomous, all calls logged
  approval-write  -- blocks until human confirms (no MVP tools)
"""

from __future__ import annotations

from enum import Enum


class SafetyTier(Enum):
    READ_ONLY = "read-only"
    ALLOWED_WRITE = "allowed-write"
    APPROVAL_WRITE = "approval-write"


_TOOL_TIERS: dict[str, SafetyTier] = {
    "list_clients": SafetyTier.READ_ONLY,
    "get_flows": SafetyTier.READ_ONLY,
    "get_findings": SafetyTier.READ_ONLY,
    "capture_status": SafetyTier.READ_ONLY,
    "start_ap": SafetyTier.ALLOWED_WRITE,
    "stop_ap": SafetyTier.ALLOWED_WRITE,
    "start_proxy": SafetyTier.ALLOWED_WRITE,
    "stop_proxy": SafetyTier.ALLOWED_WRITE,
    "start_capture": SafetyTier.ALLOWED_WRITE,
    "stop_capture": SafetyTier.ALLOWED_WRITE,
}


def classify_tool(tool_name: str) -> SafetyTier:
    """Return the safety tier for a tool name."""
    tier = _TOOL_TIERS.get(tool_name)
    if tier is None:
        raise ValueError(f"Unknown tool: {tool_name}")
    return tier
