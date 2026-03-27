"""MITM MCP server -- stdio transport.

Registers all tools from tools.py with the MCP SDK and runs the
server. Claude Code spawns this process and communicates over stdin/stdout.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

from mitm_mcp.safety import classify_tool, SafetyTier
from mitm_mcp.session import SessionManager
from mitm_mcp import tools

logger = logging.getLogger("mitm-mcp")

# Engagements dir: env var overrides, fallback to package root.
# In standalone mode: defaults to <repo>/engagements/
# When submoduled: parent repo sets PIDEV_ENGAGEMENTS_DIR via .mcp.json env.
_PACKAGE_ROOT = Path(__file__).resolve().parents[2]
ENGAGEMENTS_DIR = Path(
    os.environ.get("PIDEV_ENGAGEMENTS_DIR", str(_PACKAGE_ROOT / "engagements"))
)

# Default paths
_AP_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "ap-toggle.sh"
_LEASES_PATH = "/var/lib/misc/dnsmasq.leases"

app = Server("mitm-mcp")
session_manager = SessionManager(engagements_dir=ENGAGEMENTS_DIR)


TOOL_DEFINITIONS = [
    Tool(
        name="start_ap",
        description="Start the hostapd access point via ap-toggle.sh. [allowed-write]",
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),
    Tool(
        name="stop_ap",
        description="Stop the hostapd access point via ap-toggle.sh. [allowed-write]",
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),
    Tool(
        name="list_clients",
        description="List DHCP clients from the dnsmasq leases file. [read-only]",
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),
    Tool(
        name="start_proxy",
        description=(
            "Start a mitmproxy interception session for the named engagement. "
            "Creates engagement folder and starts mitmdump. [allowed-write]"
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "engagement_name": {
                    "type": "string",
                    "description": "Target device or engagement name",
                },
                "port": {
                    "type": "integer",
                    "default": 8080,
                    "description": "Port for the MITM proxy to listen on",
                },
                "transparent": {
                    "type": "boolean",
                    "default": True,
                    "description": "Enable transparent proxy mode",
                },
                "project_path": {
                    "type": "string",
                    "description": "Path to a project folder (from project-mcp). If provided, writes to <project_path>/mitm/ instead of creating a standalone engagement.",
                },
            },
            "required": ["engagement_name"],
        },
    ),
    Tool(
        name="stop_proxy",
        description="Stop a running mitmproxy session and finalize logs. [allowed-write]",
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
            },
            "required": ["session_id"],
        },
    ),
    Tool(
        name="start_capture",
        description=(
            "Start tshark packet capture on an interface for a session. [allowed-write]"
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "interface": {
                    "type": "string",
                    "default": "wlan0",
                    "description": "Network interface to capture on",
                },
            },
            "required": ["session_id"],
        },
    ),
    Tool(
        name="stop_capture",
        description="Stop tshark packet capture for a session. [allowed-write]",
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
            },
            "required": ["session_id"],
        },
    ),
    Tool(
        name="get_flows",
        description=(
            "Read intercepted HTTP/TLS flows from a session, with optional filtering. "
            "[read-only]"
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "host_filter": {
                    "type": "string",
                    "description": "Filter flows by hostname substring",
                },
                "path_filter": {
                    "type": "string",
                    "description": "Filter flows by URL path substring",
                },
                "protocol_filter": {
                    "type": "string",
                    "description": "Filter flows by protocol type (e.g., http, tls)",
                },
                "last_n": {
                    "type": "integer",
                    "default": 20,
                    "description": "Return only the last N matching flows",
                },
            },
            "required": ["session_id"],
        },
    ),
    Tool(
        name="get_findings",
        description=(
            "Extract security findings from intercepted flows for a session. [read-only]"
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
            },
            "required": ["session_id"],
        },
    ),
    Tool(
        name="capture_status",
        description=(
            "Return current proxy and capture status, flow count, and pcap size "
            "for a session. [read-only]"
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
            },
            "required": ["session_id"],
        },
    ),
]


@app.list_tools()
async def list_tools():
    return TOOL_DEFINITIONS


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    tier = classify_tool(name)
    logger.info("tool=%s tier=%s args=%s", name, tier.value, arguments)

    # No approval-write tools in MVP, but keep the gate for future use.
    if tier == SafetyTier.APPROVAL_WRITE:
        if not arguments.get("_confirmed", False):
            desc = f"{name}({', '.join(f'{k}={v}' for k, v in arguments.items())})"
            return [TextContent(
                type="text",
                text=json.dumps({
                    "confirmation_required": True,
                    "tool": name,
                    "arguments": arguments,
                    "message": f"APPROVAL REQUIRED: {desc}. "
                    f"Re-call with _confirmed=true to execute.",
                }),
            )]
        arguments = {k: v for k, v in arguments.items() if k != "_confirmed"}

    try:
        if name == "start_ap":
            result = await tools.tool_start_ap(script_path=str(_AP_SCRIPT))

        elif name == "stop_ap":
            result = await tools.tool_stop_ap(script_path=str(_AP_SCRIPT))

        elif name == "list_clients":
            result = await tools.tool_list_clients(leases_path=_LEASES_PATH)

        elif name == "start_proxy":
            result = await tools.tool_start_proxy(
                session_manager=session_manager,
                engagement_name=arguments["engagement_name"],
                port=arguments.get("port", 8080),
                transparent=arguments.get("transparent", True),
                project_path=arguments.get("project_path"),
            )

        elif name == "stop_proxy":
            result = await tools.tool_stop_proxy(
                session_manager=session_manager,
                session_id=arguments["session_id"],
            )

        elif name == "start_capture":
            result = await tools.tool_start_capture(
                session_manager=session_manager,
                session_id=arguments["session_id"],
                interface=arguments.get("interface", "wlan0"),
            )

        elif name == "stop_capture":
            result = await tools.tool_stop_capture(
                session_manager=session_manager,
                session_id=arguments["session_id"],
            )

        elif name == "get_flows":
            # Look up the session to get the flows_path
            try:
                session = session_manager.get(arguments["session_id"])
                flows_path = str(session.flows_path)
            except KeyError:
                return [TextContent(
                    type="text",
                    text=json.dumps({"error": f"Session not found: {arguments['session_id']}"}),
                )]
            result = await tools.tool_get_flows(
                flows_path=flows_path,
                host_filter=arguments.get("host_filter"),
                path_filter=arguments.get("path_filter"),
                protocol_filter=arguments.get("protocol_filter"),
                last_n=arguments.get("last_n", 20),
            )

        elif name == "get_findings":
            # Look up the session to get the flows_path
            try:
                session = session_manager.get(arguments["session_id"])
                flows_path = str(session.flows_path)
            except KeyError:
                return [TextContent(
                    type="text",
                    text=json.dumps({"error": f"Session not found: {arguments['session_id']}"}),
                )]
            result = await tools.tool_get_findings(flows_path=flows_path)

        elif name == "capture_status":
            result = await tools.tool_capture_status(
                session_manager=session_manager,
                session_id=arguments["session_id"],
            )

        else:
            result = {"error": f"Unknown tool: {name}"}

    except Exception as exc:
        logger.error("tool=%s error=%s", name, exc)
        result = {"error": str(exc), "tool": name}

    return [TextContent(type="text", text=json.dumps(result, indent=2))]


async def main():
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
