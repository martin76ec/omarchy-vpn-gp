"""core.secret_store against the fake secret-tool (tests/fake_secret_tool.py)."""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from core import secret_store

FAKE_SECRET_TOOL = Path(__file__).resolve().parent / "fake_secret_tool.py"


class SecretStoreTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        bindir = Path(tmp.name) / "bin"
        bindir.mkdir()
        wrapper = bindir / "secret-tool"
        wrapper.write_text(f"#!{sys.executable}\nimport runpy\nrunpy.run_path({str(FAKE_SECRET_TOOL)!r}, run_name='__main__')\n")
        wrapper.chmod(0o755)
        self.keyring_file = Path(tmp.name) / "keyring.json"
        env = {**os.environ, "PATH": str(bindir), "FAKE_SECRET_STORE": str(self.keyring_file)}
        patcher = mock.patch.dict(os.environ, env, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_round_trip(self):
        self.assertIsNone(secret_store.load("p1"))
        self.assertFalse(secret_store.has_saved("p1"))

        secret_store.save("p1", "martin", "hunter2")
        self.assertEqual(secret_store.load("p1"), ("martin", "hunter2"))
        self.assertTrue(secret_store.has_saved("p1"))

        secret_store.clear("p1")
        self.assertIsNone(secret_store.load("p1"))
        self.assertFalse(secret_store.has_saved("p1"))

    def test_profiles_are_independent(self):
        secret_store.save("p1", "martin", "pw1")
        secret_store.save("p2", "other", "pw2")
        self.assertEqual(secret_store.load("p1"), ("martin", "pw1"))
        self.assertEqual(secret_store.load("p2"), ("other", "pw2"))
        secret_store.clear("p1")
        self.assertIsNone(secret_store.load("p1"))
        self.assertEqual(secret_store.load("p2"), ("other", "pw2"))

    def test_save_overwrites(self):
        secret_store.save("p1", "martin", "old-pw")
        secret_store.save("p1", "martin", "new-pw")
        self.assertEqual(secret_store.load("p1"), ("martin", "new-pw"))

    def test_password_never_touches_argv(self):
        # subprocess.run's argv is what a `ps`-style inspection could see;
        # the secret must only ever travel via the input= (stdin) kwarg.
        with mock.patch("subprocess.run", wraps=subprocess.run) as spy:
            secret_store.save("p1", "martin", "super-secret-value")
        store_call = spy.call_args_list[0]
        self.assertNotIn("super-secret-value", store_call.args[0])
        self.assertEqual(store_call.kwargs.get("input"), '{"username": "martin", "password": "super-secret-value"}')
