"""Helper JSON output must match what Model.js and Panel.qml consume."""

import socket
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from core.drivers import nm_driver
from tests.support import OVPN_UUID, WORK_UUID, FakeNmTestCase

ERROR_KEYS = {"code", "message"}


class ContractTests(FakeNmTestCase):
    def assertError(self, result, code):
        self.assertFalse(result["ok"])
        self.assertEqual(set(result["error"]), ERROR_KEYS)
        self.assertEqual(result["error"]["code"], code)

    def test_list_returns_only_supported_vpn_profiles(self):
        result = self.helper("list")
        self.assertEqual(result["profiles"], [
            {"id": WORK_UUID, "name": "Work: GP", "engine": "openconnect", "protocol": "gp", "gateway": "vpn.example.com",
             "has_saved_credentials": False},
            {"id": OVPN_UUID, "name": "Lab", "engine": "openvpn", "protocol": "openvpn", "gateway": "lab.example.com:1194",
             "has_saved_credentials": False},
        ])

    def test_status_states(self):
        self.assertEqual(self.helper("status"), {"ok": True, "state": "DISCONNECTED", "profile_id": None, "profile_name": None,
                                                   "error": None, "prompt": None, "verifying": False, "verified": None})
        for nm_state, vpn_state, expected in [
            ("activated", None, "CONNECTED"),
            ("activating", "activating", "CONNECTING"),
            ("activating", "auth", "AUTHENTICATING"),
            ("deactivating", None, "DISCONNECTING"),
        ]:
            with self.subTest(expected):
                self.set_state([{"uuid": WORK_UUID, "state": nm_state, "vpn_state": vpn_state}])
                self.assertEqual(self.helper("status"),
                                 {"ok": True, "state": expected, "profile_id": WORK_UUID, "profile_name": "Work: GP",
                                  "error": None, "prompt": None, "verifying": False, "verified": None})

    def test_connect_and_disconnect_are_acknowledgements(self):
        # OVPN_UUID: single-stage nmcli flow. The two-stage OpenConnect path
        # (WORK_UUID) is covered in tests/test_activation.py.
        self.assertEqual(self.helper("connect", OVPN_UUID), {"ok": True, "state": "CONNECTING", "profile_id": OVPN_UUID})
        self.set_state([{"uuid": OVPN_UUID, "state": "activated", "vpn_state": None}])
        self.assertEqual(self.helper("disconnect"), {"ok": True, "state": "DISCONNECTING", "profile_id": OVPN_UUID})

    def test_error_codes(self):
        self.assertError(self.helper(), "INVALID_REQUEST")
        self.assertError(self.helper("frobnicate"), "INVALID_REQUEST")
        self.assertError(self.helper("disconnect"), "INVALID_STATE")
        self.assertError(self.helper("connect", "44444444-4444-4444-4444-444444444444"), "NOT_FOUND")
        self.assertError(self.helper("status", path="/nonexistent"), "BACKEND_UNAVAILABLE")

    def test_second_connect_is_rejected(self):
        self.set_state([{"uuid": WORK_UUID, "state": "activated", "vpn_state": None}])
        self.assertError(self.helper("connect", OVPN_UUID), "INVALID_STATE")

    def test_polkit_denial_is_reported_without_fallback(self):
        self.set_state(deny=True)
        self.assertError(self.helper("connect", OVPN_UUID), "AUTH_DENIED")
        # No privileged retry: exactly one "up" attempt was made.
        self.assertEqual(sum("up" in call for call in self.nmcli_calls()), 1)


class TelemetryTests(FakeNmTestCase):
    def connect_fixture(self, iface="lo", gateway="127.0.0.1:1", devices=()):
        connections = [{"uuid": WORK_UUID, "name": "Work", "type": "vpn", "service": "org.freedesktop.NetworkManager.openconnect",
                        "data": f"gateway = {gateway}, protocol = gp"}]
        self.set_state([{"uuid": WORK_UUID, "state": "activated", "vpn_state": None}],
                        connections=connections, iface=iface, devices=list(devices))

    def test_reports_counters_and_gateway_latency(self):
        with socket.create_server(("127.0.0.1", 0)) as listener:
            self.connect_fixture(gateway=f"127.0.0.1:{listener.getsockname()[1]}")
            result = self.helper("telemetry")
        self.assertEqual(set(result), {"ok", "iface", "rx_bytes", "tx_bytes", "latency_ms"})
        self.assertEqual((result["iface"], type(result["rx_bytes"])), ("lo", int))
        self.assertIsInstance(result["latency_ms"], float)

    def test_unreachable_gateway_yields_null_latency(self):
        self.connect_fixture()
        self.assertIsNone(self.helper("telemetry")["latency_ms"])

    def test_interface_name_cannot_traverse_out_of_sysfs(self):
        for iface in ("../../etc", "..", "lo/../lo", ""):
            with self.subTest(iface):
                self.connect_fixture(iface=iface)
                self.assertEqual(self.helper("telemetry")["error"]["code"], "NOT_FOUND")

    def test_requires_established_connection(self):
        self.assertEqual(self.helper("telemetry")["error"]["code"], "INVALID_STATE")

    def test_falls_back_to_tun_device_when_ip_iface_is_the_parent_device(self):
        # OpenConnect's real quirk, confirmed against a real connection:
        # GENERAL.IP-IFACE reports the underlying Wi-Fi/Ethernet device, not
        # the externally-managed tunnel. "lo" stands in for the tunnel here
        # since it's a real interface with real, readable statistics.
        self.connect_fixture(iface="not-the-real-tunnel", devices=[["lo", "tun"]])
        self.assertEqual(self.helper("telemetry")["iface"], "lo")


class TunStatsValidationTests(unittest.TestCase):
    """White-box: the kernel itself allows an interface name a naive
    alnum-first regex would reject — confirmed for real, openconnect names
    its own externally-managed tunnel literally "--" when NetworkManager
    doesn't specify one. _tun_stats must accept that, while still refusing
    anything that could traverse out of _SYSFS_NET."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        self.sysfs = root / "class" / "net"
        self.sysfs.mkdir(parents=True)
        # A real directory a bare ".." would actually reach if _tun_stats
        # didn't explicitly guard against it — makes the traversal test a
        # genuine proof the guard matters, not just incidental protection
        # from a path that happens not to exist.
        (root / "class" / "statistics").mkdir()
        patcher = mock.patch("core.drivers.nm_driver._SYSFS_NET", self.sysfs)
        patcher.start()
        self.addCleanup(patcher.stop)

    def make_iface(self, name):
        (self.sysfs / name / "statistics").mkdir(parents=True)

    def test_accepts_a_leading_hyphen_name(self):
        self.make_iface("--")
        self.assertEqual(nm_driver._tun_stats("--"), self.sysfs / "--" / "statistics")

    def test_rejects_traversal_and_empty(self):
        self.make_iface("real0")
        for name in ("..", ".", "../real0", "a/../../etc", "", "x" * 16):
            with self.subTest(name):
                self.assertIsNone(nm_driver._tun_stats(name))

    def test_missing_interface_returns_none(self):
        self.assertIsNone(nm_driver._tun_stats("nonexistent0"))
