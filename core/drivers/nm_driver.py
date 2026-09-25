"""NetworkManager adapter driven through nmcli.

Runs as the logged-in user. NetworkManager performs the privileged work under
its polkit policy; an authorization denial is reported, never worked around.
Credentials are not handled here: NetworkManager asks the user-session secret
agent, so no secret ever crosses this process or an nmcli argument list.
"""

import os
import re
import socket
import subprocess
import time
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from core.errors import VpnError
from core.fsm import State
from core.security import scrub

_SERVICE_PREFIX = "org.freedesktop.NetworkManager."
_ENGINES = {"openconnect", "openvpn"}
# NMVpnConnectionState: nmcli prints "<n> - <label>" for VPN.VPN-STATE.
_VPN_NEED_AUTH = 2
_PLUGIN_MISSING = re.compile(r"NetworkManager\.(openconnect|openvpn)' was not installed")
_PLUGIN_PACKAGE = {"openconnect": "networkmanager-openconnect", "openvpn": "networkmanager-openvpn"}
_SYSFS_NET = Path("/sys/class/net")


@dataclass(frozen=True)
class Profile:
    id: str
    name: str
    engine: str
    protocol: str
    gateway: str | None


@dataclass(frozen=True)
class Status:
    state: State
    profile_id: str | None = None
    profile_name: str | None = None
    error: dict | None = None
    prompt: dict | None = None
    # True while a `verify` watcher (test-credentials, not connect) is
    # running: same AUTHENTICATING/prompt machinery, distinct label. Never
    # reaches CONNECTED — no real activation happens during a verify.
    verifying: bool = False
    # Set once, the poll after a verify watcher exits, then cleared: True on
    # success (credentials saved), False on failure (see `error` instead).
    verified: bool | None = None


@dataclass(frozen=True)
class Telemetry:
    iface: str
    rx_bytes: int
    tx_bytes: int
    latency_ms: float | None


def split_terse(line: str) -> list[str]:
    """Split nmcli -t output on unescaped ':' and unescape '\\:' and '\\\\'."""
    fields, current, chars = [], [], iter(line)
    for ch in chars:
        match ch:
            case "\\":
                current.append(next(chars, ""))
            case ":":
                fields.append("".join(current))
                current = []
            case _:
                current.append(ch)
    return [*fields, "".join(current)]


def parse_vpn_data(data: str) -> dict[str, str]:
    """Parse nmcli's "k = v, k2 = v2" rendering of vpn.data (never secrets)."""
    pairs = (item.split("=", 1) for item in data.split(",") if "=" in item)
    return {k.strip(): v.strip() for k, v in pairs}


def classify_error(stderr: str) -> VpnError:
    message = scrub(stderr) or "NetworkManager reported an error."
    # Checked before scrubbing would matter: the plugin name here is not a
    # secret, and this is the one error the panel needs to give an exact
    # fix for rather than just display.
    if found := _PLUGIN_MISSING.search(stderr):
        package = _PLUGIN_PACKAGE[found[1]]
        return VpnError("PLUGIN_MISSING", f"Install the NetworkManager {found[1]} plugin: sudo pacman -S {package}")
    text = message.lower()
    if "not authorized" in text or "permission denied" in text:
        return VpnError("AUTH_DENIED", message)
    if "not running" in text or "could not create nmclient" in text:
        return VpnError("BACKEND_UNAVAILABLE", message)
    if "unknown connection" in text or "not an active connection" in text:
        return VpnError("NOT_FOUND", message)
    return VpnError("NM_ERROR", message)


def _nmcli(*args: str, timeout: float = 15) -> str:
    # LC_ALL=C keeps stderr in English so classify_error can match it.
    try:
        done = subprocess.run(
            ["nmcli", *args], capture_output=True, text=True, timeout=timeout,
            env={**os.environ, "LC_ALL": "C"}, check=False,
        )
    except OSError:
        raise VpnError("BACKEND_UNAVAILABLE", "nmcli is not installed or not executable.") from None
    except subprocess.TimeoutExpired:
        raise VpnError("TIMEOUT", "NetworkManager did not respond in time.") from None
    if done.returncode:
        raise classify_error(done.stderr)
    return done.stdout


class NetworkManagerDriver:
    def profiles(self) -> list[Profile]:
        rows = (split_terse(line) for line in _nmcli("-t", "-f", "UUID,NAME,TYPE", "connection", "show").splitlines())
        found = (self._profile(uuid, name) for uuid, name, kind in rows if kind == "vpn")
        return [p for p in found if p]

    def _service(self, uuid: str) -> tuple[str, dict[str, str]]:
        out = _nmcli("--escape", "no", "-g", "vpn.service-type,vpn.data", "connection", "show", "uuid", uuid)
        service, _, data = out.partition("\n")
        return service.strip().removeprefix(_SERVICE_PREFIX), parse_vpn_data(data)

    def _profile(self, uuid: str, name: str) -> Profile | None:
        engine, options = self._service(uuid)
        if engine not in _ENGINES:
            return None
        # openconnect defaults to AnyConnect when no protocol is stored.
        protocol = options.get("protocol", "anyconnect") if engine == "openconnect" else "openvpn"
        gateway = options.get("gateway") or options.get("remote")
        return Profile(uuid.lower(), name, engine, protocol, gateway)

    def status(self) -> Status:
        rows = (split_terse(line) for line in _nmcli("-t", "-f", "UUID,NAME,TYPE,STATE", "connection", "show", "--active").splitlines())
        active = next(((uuid, name, nm_state) for uuid, name, kind, nm_state in rows if kind == "vpn"), None)
        if not active:
            return Status(State.DISCONNECTED)
        uuid, name, nm_state = active
        return Status(self._state(uuid, nm_state), uuid.lower(), name)

    def _state(self, uuid: str, nm_state: str) -> State:
        match nm_state:
            case "activated":
                return State.CONNECTED
            case "deactivating":
                return State.DISCONNECTING
        vpn_state = _nmcli("--escape", "no", "-g", "VPN.VPN-STATE", "connection", "show", "uuid", uuid)
        needs_auth = (m := re.match(r"\s*(\d+)", vpn_state)) and int(m[1]) == _VPN_NEED_AUTH
        return State.AUTHENTICATING if needs_auth else State.CONNECTING

    def find_profile(self, profile_id: str) -> Profile:
        # nmcli accepts any connection UUID; without this check a crafted ID
        # could take down the user's Wi-Fi or Ethernet profile.
        profile = next((p for p in self.profiles() if p.id == profile_id), None)
        if not profile:
            raise VpnError("NOT_FOUND", "No supported VPN profile with that ID.")
        return profile

    def test_server(self, profile_id: str) -> float | None:
        """Bare TCP+TLS connect-time check against the profile's own
        gateway/portal address — no protocol negotiation, no credentials,
        just "is this host reachable on its port". Returns latency in ms,
        or None if unreachable."""
        profile = self.find_profile(profile_id)
        endpoint = gateway_endpoint(profile.gateway or "")
        if endpoint is None:
            raise VpnError("INVALID_REQUEST", "This profile has no gateway address to test.")
        return tcp_latency_ms(endpoint)

    def open_activation(self, profile_id: str, wait: int) -> tuple[Profile, subprocess.Popen]:
        """Start `nmcli --ask connection up`, with nmcli acting as secret agent.

        Stdin carries any credentials nmcli asks for; stdout and stderr are
        merged because nmcli prints prompts and errors on different streams.
        """
        profile = self.find_profile(profile_id)
        proc = subprocess.Popen(
            ["nmcli", "--ask", "--wait", str(wait), "connection", "up", "uuid", profile.id],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            env={**os.environ, "LC_ALL": "C"},
        )
        return profile, proc

    def add_openconnect(self, name: str, protocol: str, gateway: str) -> str:
        out = _nmcli("connection", "add", "type", "vpn", "vpn-type", "openconnect", "con-name", name,
                     "ifname", "--", "vpn.data", f"gateway={gateway}, protocol={protocol}")
        return _created_uuid(out)

    def import_openvpn(self, path: Path, name: str | None) -> str:
        uuid = _created_uuid(_nmcli("connection", "import", "type", "openvpn", "file", str(path)))
        if name:
            _nmcli("connection", "modify", "uuid", uuid, "connection.id", name)
        return uuid

    def delete(self, profile_id: str) -> None:
        profile = self.find_profile(profile_id)
        if self.status().profile_id == profile.id:
            raise VpnError("INVALID_STATE", "Disconnect the profile before deleting it.")
        _nmcli("connection", "delete", "uuid", profile.id)

    def apply_openconnect_secrets(self, profile: Profile, auth: dict[str, str]) -> None:
        """Point the profile at the resolved gateway and pin its certificate,
        so activation connects directly with no further portal negotiation.
        Nothing here is secret: the cookie itself goes through
        activate_with_agent(), never through nmcli at all.

        The "-flags = 2" (NOT_SAVED | AGENT_OWNED) entries are load-bearing,
        not decoration: without them, NetworkManager's agent-manager still
        calls our agent and gets a response with no error ("agent returned
        secrets for request" in its own debug log), but then discards
        gateway/gwcert from it when deciding whether the VPN service now
        has enough — because the connection never declared those two as
        agent-suppliable secrets in the first place, only the well-known
        "cookie" name is recognized without one. Confirmed by toggling this
        exact flag combination against a real connection and watching the
        debug log flip from repeated "final secrets request failed to
        provide sufficient secrets" to "service indicated no additional
        secrets required" on the very next attempt."""
        host = auth.get("CONNECT_URL") or auth["HOST"]
        data = (f"gateway = {host}, protocol = {profile.protocol}, gwcert = {auth['FINGERPRINT']}, "
                "gateway-flags = 2, cookie-flags = 2, gwcert-flags = 2")
        if resolve := auth.get("RESOLVE"):
            data += f", resolve = {resolve}"
        _nmcli("connection", "modify", "uuid", profile.id, "vpn.data", data)

    def activate_with_agent(self, profile: Profile, auth: dict[str, str], wait: int) -> None:
        """Delegates to core.nm_secrets (see its module docstring for why a
        real secret agent — not nmcli --ask, not a pre-cached secret — is
        the only thing that satisfies this VPN service, and why it needs
        gateway and gwcert alongside the cookie, not just the cookie
        alone). Imported here, not at module level, so importing this
        driver doesn't require libnm's GObject-Introspection bindings
        unless this call is used.

        Under the test harness (FAKE_NM_STATE set), skips the real D-Bus
        call: there is no real NetworkManager to talk to in a test, and
        mocking libnm itself is out of proportion to this one call. Logs
        the same way the other fakes do, so tests can assert it happened —
        but never the cookie itself, only whether it matched what the test
        expected, so the "nothing sensitive in the log" property this
        project's tests rely on elsewhere stays true here too."""
        gateway = auth.get("CONNECT_URL") or auth["HOST"]
        if fake_state := os.environ.get("FAKE_NM_STATE"):
            return _fake_activate_with_agent(fake_state, profile.id, auth["COOKIE"])
        try:
            from core.nm_secrets import activate as _activate
        except ImportError:
            raise VpnError("PLUGIN_MISSING", "Install the GObject-Introspection Python bindings: "
                            "sudo pacman -S python-gobject") from None
        _activate(profile.id, gateway, auth["COOKIE"], auth["FINGERPRINT"], wait)

    def disconnect(self, profile_id: str) -> None:
        _nmcli("--wait", "0", "connection", "down", "uuid", profile_id)

    def telemetry(self, profile_id: str) -> Telemetry:
        iface = _nmcli("--escape", "no", "-g", "GENERAL.IP-IFACE", "connection", "show", "uuid", profile_id).strip()
        stats = _tun_stats(iface)
        if stats is None:
            # OpenConnect's tunnel is externally-managed and never reflected
            # in the VPN connection's own GENERAL.IP-IFACE — confirmed
            # against a real connection: it reports the underlying
            # Wi-Fi/Ethernet device instead, and the real tunnel (kernel
            # name literally "--" in one observed case) only shows up as a
            # separate, unassociated "tun"-type device. Fall back to
            # whichever single tun device NetworkManager currently tracks,
            # relying on this project's own single-VPN-at-a-time invariant.
            iface = next((split_terse(line)[0]
                          for line in _nmcli("-t", "-f", "DEVICE,TYPE", "device", "status").splitlines()
                          if split_terse(line)[1] == "tun"), "")
            stats = _tun_stats(iface)
        if stats is None:
            raise VpnError("NOT_FOUND", "The VPN tunnel interface is not available.")
        engine, options = self._service(profile_id)
        endpoint = gateway_endpoint(options.get("gateway", "")) if engine == "openconnect" else None
        return Telemetry(iface, int((stats / "rx_bytes").read_text()), int((stats / "tx_bytes").read_text()),
                         tcp_latency_ms(endpoint) if endpoint else None)


def _fake_activate_with_agent(state_path: str, profile_id: str, cookie: str) -> None:
    import json

    state = json.loads(Path(state_path).read_text())
    if log_path := os.environ.get("FAKE_NM_LOG"):
        scenario = state.get("cache_cookie", {})
        matched = cookie == scenario.get("expected", cookie)
        with open(log_path, "a") as log:
            log.write(json.dumps(["activate_with_agent", profile_id, "match" if matched else "mismatch"]) + "\n")
    if state.get("deny"):
        raise VpnError("AUTH_DENIED", "Connection activation failed: Not authorized to control networking.")
    if plugin := state.get("plugin_missing"):
        raise VpnError("PLUGIN_MISSING", f"Install the NetworkManager {plugin} plugin: sudo pacman -S networkmanager-{plugin}")
    cfg = state.get("activate", {})
    if cfg.get("mode") == "fail":
        raise VpnError(cfg.get("code", "NM_ERROR"), cfg.get("error", "Connection activation failed."))


def _created_uuid(output: str) -> str:
    found = re.search(r"\(([0-9a-fA-F-]{36})\)", output)
    if not found:
        raise VpnError("NM_ERROR", "NetworkManager did not report the new profile.")
    return found[1].lower()


def authenticate_argv(profile: Profile) -> list[str]:
    """`openconnect --authenticate` runs the full portal login as this user
    and prints shell-style variables on success; see openconnect(8)
    SCRIPTING. It never touches NetworkManager, so this step needs no
    secret-agent negotiation at all."""
    return ["openconnect", "--authenticate", "--protocol", profile.protocol, profile.gateway]


def authenticate_saved_argv(profile: Profile, username: str) -> list[str]:
    """Same as authenticate_argv, but with the username already supplied
    (man openconnect: "-u,--user=NAME ... should not be used to enter
    passwords" — it isn't one). openconnect then asks only for whatever it
    still needs — normally just the password — as a normal interactive pty
    prompt, answered by core.activation._run()'s auto_answer the instant it
    sees that prompt text, the same way a human's typed password would be,
    without ever reaching the panel. Anything beyond that (OTP, a changed
    portal flow) still falls through to a real prompt.

    Deliberately NOT --passwd-on-stdin: that flag makes openconnect read the
    password silently with no prompt text at all, which starves
    _run()'s prompt-detection loop of the very text it waits for before
    writing anything — confirmed live, it hangs forever ("stuck at
    connecting"), since nothing else ever writes to its stdin."""
    return ["openconnect", "--authenticate", "--protocol", profile.protocol,
            "--user", username, profile.gateway]


_AUTH_VAR = re.compile(r"^(COOKIE|HOST|CONNECT_URL|FINGERPRINT|RESOLVE)='(.*)'$")


def parse_authenticate_output(text: str) -> dict[str, str]:
    return dict(m.groups() for line in text.splitlines() if (m := _AUTH_VAR.match(line)))


def _tun_stats(iface: str) -> Path | None:
    """Validated the way the kernel itself validates an interface name
    (dev_valid_name(): no '/', no whitespace, 1-15 bytes, not "." or "..")
    rather than an alnum-first regex — confirmed a real one can violate
    that regex: openconnect, left to name its own externally-managed
    tunnel, named it literally "--"."""
    valid = iface and len(iface) <= 15 and iface not in (".", "..") and "/" not in iface and not any(c.isspace() for c in iface)
    stats = _SYSFS_NET / iface / "statistics" if valid else None
    return stats if stats and stats.is_dir() else None


def gateway_endpoint(raw: str) -> tuple[str, int] | None:
    with suppress(ValueError):
        parts = urlsplit(raw if "//" in raw else f"//{raw}")
        return (parts.hostname, parts.port or 443) if parts.hostname else None
    return None


def tcp_latency_ms(endpoint: tuple[str, int], timeout: float = 1.0) -> float | None:
    """Connect time to the gateway; ICMP is commonly filtered by VPN gateways."""
    start = time.perf_counter()
    with suppress(OSError), socket.create_connection(endpoint, timeout):
        return round((time.perf_counter() - start) * 1000, 1)
    return None
