# CLAUDE.md

This file provides guidance to Claude Code when working with code in this repository.

## Project

mitm-mcp is an MCP server that orchestrates mitmproxy (mitmdump) and tshark for
network-level TLS interception of IoT device traffic, exposing capture and
analysis operations as MCP tools over stdio transport.

## Architecture

    MCP client (Claude Code, etc.)
      |
      stdio transport
      |
    mitm-mcp (server.py)
      |
      tools.py -> session.py -> subprocess (mitmdump, tshark)
      |
    addon.py (standalone, runs inside mitmdump)
      |
    Pi network stack (hostapd AP on wlan0, eth0 uplink)

session.py is the ONLY module that manages long-lived subprocesses (Popen).
Everything else talks to session.py. This prevents race conditions from split
connection ownership.

addon.py is standalone -- no imports from mitm_mcp. It runs inside the mitmdump
process which may use a different Python environment. It communicates with the
MCP server via JSONL files only.

## Safety Model

Three tiers enforced at the MCP server boundary:

- **read-only**: full autonomy (list_clients, get_flows, get_findings, capture_status)
- **allowed-write**: autonomous but logged (start_ap, stop_ap, start_proxy, stop_proxy, start_capture, stop_capture)
- **approval-write**: reserved for future response injection (no MVP tools)

## Build and Run

    # Install
    pip install -e ".[dev]"

    # Run server (stdio transport, spawned by MCP client)
    python -m mitm_mcp

    # Tests (no network hardware needed)
    pytest

    # Integration tests (AP + network setup required)
    pytest tests/ -m network

## Prerequisites

- mitmproxy installed (provides mitmdump): pip install mitmproxy
- tshark installed: apt install tshark
- WiFi AP configured via `scripts/ap-setup.sh` (idempotent, run once or rerun to change values)
- Operator must be SSH'd over Ethernet, not WiFi

## AP Scripts

- `scripts/ap-setup.sh` -- one-time setup. Installs packages, writes hostapd/dnsmasq configs,
  creates NetworkManager connection, enables IP forwarding. Idempotent. Use `--dry-run` to preview.
  Override defaults with `--ssid`, `--passphrase`, `--channel`, `--subnet`, `--interface`.
- `scripts/ap-toggle.sh` -- per-engagement. `start` brings up hostapd + dnsmasq + iptables rules,
  `stop` tears them down. Called by the MCP server's start_ap/stop_ap tools.

## Style

- Python 3.11+
- No emojis, no em-dashes in code, comments, commits, or docs
- Commit messages: short, to the point
