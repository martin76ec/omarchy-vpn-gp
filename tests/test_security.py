"""Injection, argv-leak and scrubbing defenses."""

import inspect
import unittest

from core.drivers import nm_driver
from core.errors import VpnError
from core.security import scrub, validate_profile_id
from tests.support import OVPN_UUID, WIFI_UUID, WORK_UUID, FakeNmTestCase

HOSTILE_IDS = ["--help", "-h", "../../etc/passwd", "$(touch /tmp/pwned)", "`id`", f"{WORK_UUID}; reboot", f"{WORK_UUID}\n--x", ""]


class ValidationTests(unittest.TestCase):
    def test_rejects_anything_but_a_uuid(self):
        for value in HOSTILE_IDS:
            with self.subTest(value=value), self.assertRaises(VpnError):
                validate_profile_id(value)

    def test_scrub_redacts_credentials(self):
        text = "failed: password=hunter2 cookie: abc123 token = xyz Authorization: Bearer"
        cleaned = scrub(text)
        for leaked in ("hunter2", "abc123", "xyz"):
            self.assertNotIn(leaked, cleaned)

    def test_driver_never_uses_a_shell(self):
        source = inspect.getsource(nm_driver)
        self.assertNotIn("shell=True", source)
        self.assertNotIn("os.system", source)


class ArgvTests(FakeNmTestCase):
    def test_hostile_ids_never_reach_nmcli(self):
        for value in HOSTILE_IDS:
            with self.subTest(value=value):
                self.helper("connect", value)
        self.assertEqual(self.nmcli_calls(), [])

    def test_non_vpn_uuid_cannot_be_activated(self):
        # A valid UUID for the Wi-Fi profile must not be passed to `connection up`.
        result = self.helper("connect", WIFI_UUID)
        self.assertEqual(result["error"]["code"], "NOT_FOUND")
        self.assertFalse(any("up" in call for call in self.nmcli_calls()))

    def test_activation_argv_is_exactly_the_uuid(self):
        # OVPN_UUID: single-stage nmcli flow. The two-stage OpenConnect
        # path's argv is covered in tests/test_activation.py.
        self.helper("connect", OVPN_UUID)
        self.assertEqual(self.nmcli_calls()[-1], ["--ask", "--wait", "120", "connection", "up", "uuid", OVPN_UUID])


class PluginMissingTests(FakeNmTestCase):
    def test_missing_plugin_gives_the_install_command(self):
        self.set_state(plugin_missing="openvpn")
        result = self.helper("connect", OVPN_UUID)
        self.assertEqual(result["error"]["code"], "PLUGIN_MISSING")
        self.assertIn("sudo pacman -S networkmanager-openvpn", result["error"]["message"])
