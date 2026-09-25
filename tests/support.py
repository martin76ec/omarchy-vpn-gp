import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import suppress
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HELPER = ROOT / "bin" / "omarchy-vpn-helper"
FAKE_NMCLI = Path(__file__).resolve().parent / "fake_nmcli.py"
FAKE_OPENCONNECT = Path(__file__).resolve().parent / "fake_openconnect.py"
FAKE_SECRET_TOOL = Path(__file__).resolve().parent / "fake_secret_tool.py"

OC_SERVICE = "org.freedesktop.NetworkManager.openconnect"
WORK_UUID = "11111111-1111-1111-1111-111111111111"
OVPN_UUID = "22222222-2222-2222-2222-222222222222"
WIFI_UUID = "33333333-3333-3333-3333-333333333333"

CONNECTIONS = [
    # The colon in the name exercises terse-output unescaping.
    {"uuid": WORK_UUID, "name": "Work: GP", "type": "vpn", "service": OC_SERVICE,
     "data": "gateway = vpn.example.com, protocol = gp, user = martin"},
    {"uuid": OVPN_UUID, "name": "Lab", "type": "vpn", "service": "org.freedesktop.NetworkManager.openvpn",
     "data": "remote = lab.example.com:1194, connection-type = tls"},
    {"uuid": WIFI_UUID, "name": "Home", "type": "802-11-wireless", "service": "", "data": ""},
]


class FakeNmTestCase(unittest.TestCase):
    """Runs the real helper as a subprocess with a fake nmcli first on PATH."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        bindir = self.tmp / "bin"
        bindir.mkdir()
        # Absolute interpreter in the shebang: PATH holds only these fakes.
        for name, target in (("nmcli", FAKE_NMCLI), ("openconnect", FAKE_OPENCONNECT), ("secret-tool", FAKE_SECRET_TOOL)):
            wrapper = bindir / name
            wrapper.write_text(f"#!{sys.executable}\nimport runpy\nrunpy.run_path({str(target)!r}, run_name='__main__')\n")
            wrapper.chmod(0o755)
        self.home = self.tmp / "home"
        self.home.mkdir()
        self.run_dir = self.tmp / "run"
        self.run_dir.mkdir(mode=0o700)
        self.state_dir = self.run_dir / "omarchy-global-connect"
        self.state_file, self.log_file = self.tmp / "state.json", self.tmp / "log"
        self.keyring_file = self.tmp / "keyring.json"
        self.addCleanup(self.kill_watcher)
        self.log_file.touch()
        self.path = str(bindir)
        self.set_state()

    def set_state(self, active=(), connections=CONNECTIONS, **extra):
        self.state_file.write_text(json.dumps({"connections": connections, "active": list(active), **extra}))

    def kill_watcher(self):
        info = self.state_dir / "watcher"
        if info.exists():
            with suppress(OSError):
                os.kill(json.loads(info.read_text())["pid"], signal.SIGKILL)

    def wait_status(self, predicate, timeout=6):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            result = self.helper("status")
            if predicate(result):
                return result
            time.sleep(0.1)
        self.fail(f"status never matched; last: {result}")

    def helper(self, *args, path=None, stdin=None):
        env = {**os.environ, "PATH": path or self.path, "FAKE_NM_STATE": str(self.state_file),
               "FAKE_NM_LOG": str(self.log_file), "XDG_RUNTIME_DIR": str(self.run_dir), "HOME": str(self.home),
               "FAKE_SECRET_STORE": str(self.keyring_file)}
        done = subprocess.run([sys.executable, str(HELPER), *args], capture_output=True, text=True, env=env,
                              input=stdin, check=False)
        lines = done.stdout.splitlines()
        self.assertEqual(len(lines), 1, f"expected exactly one stdout line, got {done.stdout!r}")
        result = json.loads(lines[0])
        self.assertEqual(done.returncode, 0 if result["ok"] else 1)
        return result

    def nmcli_calls(self):
        return [json.loads(line) for line in self.log_file.read_text().splitlines()]

    def saved_credentials(self, profile_id):
        """Peeks at the fake keyring directly — mirrors the key format
        tests/fake_secret_tool.py builds from `secret-tool`'s attribute
        pairs (see core/secret_store.py's fixed "service"/"profile" pair)."""
        if not self.keyring_file.exists():
            return None
        db = json.loads(self.keyring_file.read_text())
        raw = db.get(f"service=dev.martin.global-connect|profile={profile_id}")
        return json.loads(raw) if raw else None

    def seed_credentials(self, profile_id, username, password):
        db = json.loads(self.keyring_file.read_text()) if self.keyring_file.exists() else {}
        db[f"service=dev.martin.global-connect|profile={profile_id}"] = json.dumps({"username": username, "password": password})
        self.keyring_file.write_text(json.dumps(db))
