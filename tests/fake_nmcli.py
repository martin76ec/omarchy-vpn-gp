#!/usr/bin/env python3
"""Stand-in for nmcli: serves the JSON fixture at $FAKE_NM_STATE and logs argv."""

import json
import os
import sys
import time
from pathlib import Path

state = json.loads(Path(os.environ["FAKE_NM_STATE"]).read_text())
with open(os.environ["FAKE_NM_LOG"], "a") as log:
    log.write(json.dumps(sys.argv[1:]) + "\n")

VPN_STATE = {"activating": "1 - VPN connecting (prepare)", "auth": "2 - VPN connecting (need authentication)"}
conns = {c["uuid"]: c for c in state["connections"]}
active = {a["uuid"]: a for a in state["active"]}
esc = lambda s: s.replace("\\", "\\\\").replace(":", "\\:")  # noqa: E731

def activate():
    """Scenario for `connection up`: state["up"] picks ok, fail or prompt."""
    up = state.get("up", {})
    if state.get("deny"):
        sys.exit(print("Error: Connection activation failed: Not authorized to control networking.", file=sys.stderr) or 4)
    if state.get("plugin_missing"):
        sys.exit(print(
            "Error: Connection activation failed: The VPN service "
            f"'org.freedesktop.NetworkManager.{state['plugin_missing']}' was not installed.", file=sys.stderr) or 4)
    if up.get("mode") == "prompt":
        sys.stdout.write("Password (vpn.secrets.password): ")
        sys.stdout.flush()
        if sys.stdin.readline().rstrip("\n") != up["expected"]:
            sys.exit(print("Error: Connection activation failed: Login failed", file=sys.stderr) or 4)
    time.sleep(up.get("delay", 0))
    if up.get("mode") == "fail":
        sys.exit(print(up["error"], file=sys.stderr) or 4)


match sys.argv[1:]:
    case ["-t", "-f", "UUID,NAME,TYPE", "connection", "show"]:
        for c in conns.values():
            print(f"{c['uuid']}:{esc(c['name'])}:{c['type']}")
    case ["--escape", "no", "-g", "vpn.service-type,vpn.data", "connection", "show", "uuid", u]:
        print(conns[u]["service"])
        print(conns[u]["data"])
    case ["-t", "-f", "UUID,NAME,TYPE,STATE", "connection", "show", "--active"]:
        for u, a in active.items():
            print(f"{u}:{esc(conns[u]['name'])}:{conns[u]['type']}:{a['state']}")
    case ["--escape", "no", "-g", "VPN.VPN-STATE", "connection", "show", "uuid", u]:
        print(VPN_STATE[active[u]["vpn_state"]])
    case ["--escape", "no", "-g", "GENERAL.IP-IFACE", "connection", "show", "uuid", _]:
        print(state.get("iface", "lo"))
    case ["-t", "-f", "DEVICE,TYPE", "device", "status"]:
        for name, kind in state.get("devices", []):
            print(f"{esc(name)}:{kind}")
    case ["--ask", "--wait", _, "connection", "up", "uuid", _]:
        activate()
    case ["--wait", "0", "connection", "down", "uuid", _]:
        pass
    case ["connection", "add", "type", "vpn", "vpn-type", "openconnect", "con-name", name, "ifname", "--", "vpn.data", _]:
        print(f"Connection '{name}' (44444444-4444-4444-4444-444444444444) successfully added.")
    case ["connection", "import", "type", "openvpn", "file", _]:
        print("Connection 'imported' (55555555-5555-5555-5555-555555555555) successfully added.")
    case ["connection", "modify", "uuid", _, "connection.id", _]:
        pass
    case ["connection", "modify", "uuid", _, "vpn.data", _]:
        pass
    case ["connection", "delete", "uuid", u]:
        print(f"Connection '{conns[u]['name']}' ({u}) successfully deleted.")
    case _:
        sys.exit(print("Error: unsupported fake invocation", file=sys.stderr) or 2)
