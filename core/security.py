"""Input validation and output scrubbing for the IPC boundary."""

import re
from pathlib import Path

from core.errors import VpnError

# NetworkManager UUIDs only: an opaque ID that can never start with "-" is
# what keeps a hostile argument from being parsed as an nmcli option.
_UUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", re.IGNORECASE)
_SECRET = re.compile(r"(?i)\b(pass(?:word|wd|phrase)?|secret|token|cookie|authorization)\b(\s*[=:]\s*)\S+")


def validate_profile_id(value: str) -> str:
    if not _UUID.fullmatch(value):
        raise VpnError("INVALID_REQUEST", "Profile ID must be a NetworkManager UUID.")
    return value.lower()


def scrub(text: str, limit: int = 300) -> str:
    return _SECRET.sub(r"\1\2[redacted]", text).strip()[:limit]


_GATEWAY = re.compile(r"(?:https://)?(?P<host>[A-Za-z0-9.-]{1,253})(?::(?P<port>\d{1,5}))?/?")
_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
_MAX_OVPN_BYTES = 1 << 20


def validate_name(value: str) -> str:
    name = value.strip()
    # A leading "-" is never a legitimate profile name and reads as an option in logs.
    if not 1 <= len(name) <= 64 or not name.isprintable() or name.startswith("-"):
        raise VpnError("INVALID_REQUEST", "Name must be 1-64 printable characters and not start with '-'.")
    return name


def validate_gateway(value: str) -> str:
    """Return host[:port]. Strict on purpose: the value is spliced into
    NetworkManager's comma-separated vpn.data, where ',' or '=' would let a
    crafted gateway inject extra options such as another protocol."""
    match = _GATEWAY.fullmatch(value.strip())
    port = int(match["port"]) if match and match["port"] else None
    if not match or not all(_LABEL.fullmatch(label) for label in match["host"].split(".")) or port == 0 or (port or 0) > 65535:
        raise VpnError("INVALID_REQUEST", "Gateway must be a hostname or IPv4 address, optionally with :port.")
    return match["host"] + (f":{port}" if port else "")


def validate_ovpn_path(raw: str) -> Path:
    try:
        path = Path(raw).expanduser().resolve(strict=True)
    except (OSError, RuntimeError):
        raise VpnError("NOT_FOUND", "That .ovpn file does not exist.") from None
    # resolve() already followed symlinks, so a link pointing outside home fails here.
    if not path.is_relative_to(Path.home().resolve()):
        raise VpnError("INVALID_REQUEST", "The .ovpn file must be inside your home directory.")
    if path.suffix.lower() not in {".ovpn", ".conf"} or not path.is_file() or path.stat().st_size > _MAX_OVPN_BYTES:
        raise VpnError("INVALID_REQUEST", "Expected a .ovpn or .conf file under 1 MB.")
    return path
