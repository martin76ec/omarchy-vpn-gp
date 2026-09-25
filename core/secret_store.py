"""Saved VPN login credentials via the FreeDesktop Secret Service
(gnome-keyring, through `secret-tool`), scoped per profile UUID.

Only username + password are ever saved here — never a cookie, which is
short-lived and re-derived fresh on every connect (see core/activation.py).
`secret-tool store` reads the value to store from stdin when not attached
to a terminal (confirmed: a subprocess with no controlling tty), never
argv; round-tripped empirically before trusting it here — no stray
newline either storing or reading back a value containing none.
"""

import json
import subprocess

from core.errors import VpnError

_SERVICE = "dev.martin.global-connect"


def save(profile_id: str, username: str, password: str) -> None:
    payload = json.dumps({"username": username, "password": password})
    proc = subprocess.run(
        ["secret-tool", "store", "--label", f"GlobalConnect VPN ({profile_id})",
         "service", _SERVICE, "profile", profile_id],
        input=payload, capture_output=True, text=True, check=False,
    )
    if proc.returncode:
        raise VpnError("NM_ERROR", "Failed to save credentials to the system keyring.")


def load(profile_id: str) -> tuple[str, str] | None:
    proc = subprocess.run(
        ["secret-tool", "lookup", "service", _SERVICE, "profile", profile_id],
        capture_output=True, text=True, check=False,
    )
    if proc.returncode or not proc.stdout:
        return None
    try:
        data = json.loads(proc.stdout)
        return data["username"], data["password"]
    except (json.JSONDecodeError, KeyError, TypeError):
        return None


def has_saved(profile_id: str) -> bool:
    """Existence check only — unlike load(), never triggers an interactive
    keyring-unlock prompt (`secret-tool lookup`'s own man page: "if
    necessary an item will be unlocked"; `search` without --unlock instead
    skips a locked item). Used for `list`'s has_saved_credentials, polled
    far more often than an actual load ever needs to happen."""
    proc = subprocess.run(
        ["secret-tool", "search", "service", _SERVICE, "profile", profile_id],
        capture_output=True, text=True, check=False,
    )
    return proc.returncode == 0 and bool(proc.stdout.strip())


def clear(profile_id: str) -> None:
    # Best-effort: nothing to save the user from if the keyring is
    # unreachable, and there is nothing sensitive left behind either way
    # (the keyring, not this process, is what's being cleared).
    subprocess.run(["secret-tool", "clear", "service", _SERVICE, "profile", profile_id],
                    capture_output=True, text=True, check=False)
