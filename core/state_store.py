"""Per-user runtime state shared between short-lived helper invocations.

Lives under $XDG_RUNTIME_DIR (a per-login tmpfs) so failures, prompts and the
credential FIFO vanish on logout and are never written to persistent disk.
"""

import json
import os
import stat
import time
from pathlib import Path

from core.errors import VpnError


def state_dir() -> Path:
    base = Path(os.environ.get("XDG_RUNTIME_DIR") or Path.home() / ".cache")
    path = base / "omarchy-global-connect"
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    # lstat, not stat: a symlink planted at this path must not redirect our files.
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise VpnError("INSECURE_STATE", "The runtime state directory is not a directory owned by you.")
    path.chmod(0o700)
    return path


def write(name: str, data: dict) -> None:
    path = state_dir() / name
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as handle:
        json.dump(data, handle)
    os.replace(tmp, path)


def read(name: str, max_age: float | None = None) -> dict | None:
    path = state_dir() / name
    try:
        if max_age is not None and time.time() - path.stat().st_mtime > max_age:
            return None
        return json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def clear(name: str) -> None:
    (state_dir() / name).unlink(missing_ok=True)
