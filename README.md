# mitm-mcp

MCP server for network-level TLS interception and IoT security testing. Orchestrates [mitmproxy](https://mitmproxy.org/) and [tshark](https://www.wireshark.org/) to intercept traffic from devices connecting to a WiFi access point, automatically flagging credentials, API keys, and certificate pinning failures. Exposes operations as [Model Context Protocol](https://modelcontextprotocol.io/) tools over stdio transport.

Built for use with Claude Code on a Raspberry Pi 5, but works with any MCP client.

## What it does

- **TLS interception** -- transparent proxy via mitmproxy, no device configuration needed
- **Finding extraction** -- auto-detects auth tokens, credentials, cloud keys, cert pinning failures, interesting endpoints
- **Packet capture** -- raw pcap via tshark for evidence
- **WiFi AP management** -- toggle hostapd/dnsmasq/iptables per engagement
- **Engagement logging** -- structured JSONL flow logs, per-engagement folders, evidence chain with CA cert

## Requirements

- Python 3.11+
- mitmproxy (`pip install mitmproxy`)
- tshark (`apt install tshark`)
- WiFi AP pre-configured (hostapd + dnsmasq) -- see [AP Setup](#ap-setup)
- Raspberry Pi 5 (or any Linux box with WiFi + Ethernet)
- Operator must be SSH'd over Ethernet, not WiFi

## Install

```bash
git clone https://github.com/mplogas/mitmproxy-mcp.git
cd mitmproxy-mcp
pip install -e ".[dev]"
```

## MCP Client Configuration

Add to your `.mcp.json`:

```json
{
  "mcpServers": {
    "mitm": {
      "command": "/path/to/.venv/bin/python",
      "args": ["-m", "mitm_mcp"],
      "env": {
        "PIDEV_ENGAGEMENTS_DIR": "/path/to/engagements"
      }
    }
  }
}
```

Set `PIDEV_ENGAGEMENTS_DIR` to control where engagement logs are written. Defaults to `./engagements/` relative to the package root.

## Tools

| Tool | Safety Tier | Description |
|---|---|---|
| `list_clients` | read-only | List devices connected to the WiFi AP |
| `get_flows` | read-only | Get decoded HTTP/MQTT/WS flows with filtering |
| `get_findings` | read-only | Get extracted security findings |
| `capture_status` | read-only | Status of proxy and packet capture |
| `start_ap` | allowed-write | Start the WiFi access point |
| `stop_ap` | allowed-write | Stop the WiFi access point |
| `start_proxy` | allowed-write | Start mitmproxy for a new engagement |
| `stop_proxy` | allowed-write | Stop proxy, finalize logs |
| `start_capture` | allowed-write | Start tshark raw packet capture |
| `stop_capture` | allowed-write | Stop packet capture |

## Safety Model

Three tiers enforced at the MCP server boundary:

- **read-only** -- full autonomy, no side effects
- **allowed-write** -- autonomous execution, all calls logged
- **approval-write** -- reserved for future response injection (no MVP tools)

Passive interception cannot damage hardware or corrupt device state. The device either connects and talks, or it doesn't.

## AP Setup

Run the setup script once to configure hostapd, dnsmasq, NetworkManager, and IP forwarding:

```bash
# Preview what it will do (no changes):
./scripts/ap-setup.sh --dry-run

# Run with defaults (SSID: pidev-mitm, passphrase: pidev-mitm-key):
sudo ./scripts/ap-setup.sh

# Override defaults:
sudo ./scripts/ap-setup.sh --ssid MyProbe --passphrase hunter2hunter2 --channel 11
```

The script is idempotent -- safe to rerun with different values. It installs packages, writes configs, creates a NetworkManager connection, enables IP forwarding, and disables hostapd/dnsmasq from auto-starting.

Available options:

| Flag | Default | Description |
|---|---|---|
| `--ssid` | pidev-mitm | AP network name |
| `--passphrase` | pidev-mitm-key | WPA2 passphrase (min 8 chars) |
| `--channel` | 7 | WiFi channel |
| `--subnet` | 192.168.4 | /24 subnet for AP clients |
| `--interface` | wlan0 | WiFi interface |
| `--dry-run` | | Show what would be done without changing anything |

After setup, use `scripts/ap-toggle.sh start` and `scripts/ap-toggle.sh stop` to bring the AP up and down per engagement.

## Architecture

```
mitm-mcp (server.py)
  |
  tools.py -> session.py -> subprocess (mitmdump, tshark)
  |
addon.py (standalone, runs inside mitmdump)
  |
Pi network stack (hostapd AP on wlan0, eth0 uplink)
```

- `session.py` is the only module that manages long-lived subprocesses. Tools call into session.py, never subprocess directly.
- `addon.py` is standalone -- no imports from mitm_mcp. Runs inside mitmdump, communicates via JSONL files.

## Tests

```bash
pytest            # 82 tests, no network hardware needed
pytest -m network # integration tests, AP + network setup required
```

## License

MIT
