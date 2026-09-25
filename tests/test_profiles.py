"""Profile creation and deletion: untrusted input must not reach nmcli."""

import json

from tests.support import OVPN_UUID, WIFI_UUID, WORK_UUID, FakeNmTestCase

NEW_UUID = "44444444-4444-4444-4444-444444444444"


def gp(**overrides):
    return json.dumps({"kind": "gp", "name": "Corp", "gateway": "vpn.example.com", **overrides}) + "\n"


class AddTests(FakeNmTestCase):
    def test_openconnect_profile_argv_is_exact(self):
        self.assertEqual(self.helper("add", stdin=gp(gateway="https://vpn.example.com:8443/")), {"ok": True, "profile_id": NEW_UUID})
        self.assertEqual(self.nmcli_calls(), [[
            "connection", "add", "type", "vpn", "vpn-type", "openconnect", "con-name", "Corp",
            "ifname", "--", "vpn.data", "gateway=vpn.example.com:8443, protocol=gp"]])

    def test_hostile_gateway_and_name_never_reach_nmcli(self):
        for gateway in ("a.com, protocol = pulse", "a.com,user=x", "a.com;reboot", "$(id)", "-x", "a b", "a.com:99999", "", "a..com"):
            with self.subTest(gateway=gateway):
                self.assertEqual(self.helper("add", stdin=gp(gateway=gateway))["error"]["code"], "INVALID_REQUEST")
        for name in ("", "   ", "-rf", "x" * 65, "bad\nname"):
            with self.subTest(name=name):
                self.assertEqual(self.helper("add", stdin=gp(name=name))["error"]["code"], "INVALID_REQUEST")
        for stdin in ("not json\n", "[]\n", "{}\n", json.dumps({"kind": "wireguard", "name": "x"}) + "\n", ""):
            with self.subTest(stdin=stdin):
                self.assertEqual(self.helper("add", stdin=stdin)["error"]["code"], "INVALID_REQUEST")
        self.assertEqual(self.nmcli_calls(), [])

    def test_ovpn_import_accepts_files_inside_home(self):
        config = self.home / "Downloads" / "lab.ovpn"
        config.parent.mkdir()
        config.write_text("client\n")
        result = self.helper("add", stdin=json.dumps({"kind": "openvpn", "path": str(config), "name": "Lab VPN"}) + "\n")
        self.assertEqual(result["profile_id"], "55555555-5555-5555-5555-555555555555")
        self.assertEqual(self.nmcli_calls()[0][-1], str(config.resolve()))
        self.assertEqual(self.nmcli_calls()[1][-2:], ["connection.id", "Lab VPN"])

    def test_ovpn_import_cannot_escape_home(self):
        outside = self.tmp / "outside.ovpn"
        outside.write_text("client\n")
        (self.home / "link.ovpn").symlink_to(outside)
        (self.home / "notes.txt").write_text("x")
        for path in (str(outside), str(self.home / "link.ovpn"), str(self.home / ".." / "outside.ovpn"),
                     "/etc/passwd", str(self.home / "notes.txt"), str(self.home / "missing.ovpn")):
            with self.subTest(path=path):
                self.assertFalse(self.helper("add", stdin=json.dumps({"kind": "openvpn", "path": path}) + "\n")["ok"])
        self.assertEqual(self.nmcli_calls(), [])


class DeleteTests(FakeNmTestCase):
    def test_deletes_a_vpn_profile(self):
        self.assertEqual(self.helper("delete", OVPN_UUID), {"ok": True})
        self.assertEqual(self.nmcli_calls()[-1], ["connection", "delete", "uuid", OVPN_UUID])

    def test_cannot_delete_non_vpn_connections(self):
        self.assertEqual(self.helper("delete", WIFI_UUID)["error"]["code"], "NOT_FOUND")
        self.assertFalse(any("delete" in call for call in self.nmcli_calls()))

    def test_cannot_delete_the_active_profile(self):
        self.set_state([{"uuid": WORK_UUID, "state": "activated", "vpn_state": None}])
        self.assertEqual(self.helper("delete", WORK_UUID)["error"]["code"], "INVALID_STATE")
        self.assertEqual(self.helper("delete", "--help")["error"]["code"], "INVALID_REQUEST")
