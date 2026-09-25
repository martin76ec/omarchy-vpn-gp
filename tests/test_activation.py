"""Failure reporting, credential relay and cancellation across helper runs.

These use OVPN_UUID (openvpn engine): a single `nmcli --ask connection up`
call, unaffected by the two-stage OpenConnect flow covered separately in
OpenConnectTests below.
"""

import stat
import time

from tests.support import OVPN_UUID, WORK_UUID, FakeNmTestCase

SECRET = "hunter2-S3cr3t"
PROMPT_UP = {"mode": "prompt", "expected": SECRET}


class ErrorStateTests(FakeNmTestCase):
    def test_late_failure_becomes_error_state_and_is_retryable(self):
        message = "Error: Connection activation failed: Secrets were required, but not provided."
        self.set_state(up={"mode": "fail", "delay": 2, "error": message})
        self.assertTrue(self.helper("connect", OVPN_UUID)["ok"])
        self.assertEqual(self.helper("status")["state"], "CONNECTING")

        result = self.wait_status(lambda r: r["state"] == "ERROR")
        self.assertEqual(result["profile_id"], OVPN_UUID)
        self.assertEqual(result["error"]["code"], "NM_ERROR")
        self.assertIn("Secrets were required", result["error"]["message"])

        self.set_state(up={"mode": "ok", "delay": 2})
        self.assertTrue(self.helper("connect", OVPN_UUID)["ok"])
        self.assertEqual(self.helper("status")["state"], "CONNECTING")

    def test_immediate_failure_is_not_left_as_error_state(self):
        self.set_state(deny=True)
        self.assertEqual(self.helper("connect", OVPN_UUID)["error"]["code"], "AUTH_DENIED")
        self.assertEqual(self.helper("status")["state"], "DISCONNECTED")


class CredentialTests(FakeNmTestCase):
    def start_prompt(self):
        self.set_state(up=PROMPT_UP)
        self.helper("connect", OVPN_UUID)
        result = self.wait_status(lambda r: r["state"] == "AUTHENTICATING")
        self.assertEqual({k: v for k, v in result["prompt"].items() if k != "id"},
                         {"label": "Password", "field": "vpn.secrets.password", "secret": True})
        return result["prompt"]["id"]

    def test_secret_reaches_nmcli_without_touching_argv_or_disk(self):
        prompt_id = self.start_prompt()
        self.assertEqual(self.helper("credentials", prompt_id, stdin=SECRET + "\n"), {"ok": True})
        result = self.wait_status(lambda r: r["state"] == "DISCONNECTED")
        self.assertIsNone(result["error"])  # fake nmcli exited 0: the secret matched

        self.assertNotIn(SECRET, self.log_file.read_text())
        for path in self.state_dir.rglob("*"):
            if path.is_file():
                self.assertNotIn(SECRET.encode(), path.read_bytes(), path)

    def test_wrong_secret_reports_error(self):
        prompt_id = self.start_prompt()
        self.helper("credentials", prompt_id, stdin="nope\n")
        result = self.wait_status(lambda r: r["state"] == "ERROR")
        self.assertIn("Login failed", result["error"]["message"])

    def test_stale_or_malformed_prompt_ids_are_rejected(self):
        self.assertEqual(self.helper("credentials", "deadbeef", stdin="x\n")["error"]["code"], "NO_PROMPT")
        self.start_prompt()
        for bad in ("deadbeef", "../x", "--help"):
            with self.subTest(bad):
                self.assertEqual(self.helper("credentials", bad, stdin="x\n")["error"]["code"], "NO_PROMPT")

    def test_state_files_are_private(self):
        self.start_prompt()
        self.assertEqual(stat.S_IMODE(self.state_dir.stat().st_mode), 0o700)
        for path in self.state_dir.iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode) & 0o077, 0, path)

    def test_disconnect_cancels_pending_prompt_without_error(self):
        self.start_prompt()
        self.assertEqual(self.helper("disconnect")["state"], "DISCONNECTING")
        time.sleep(0.6)
        result = self.helper("status")
        self.assertEqual((result["state"], result["prompt"]), ("DISCONNECTED", None))


class OpenConnectTests(FakeNmTestCase):
    """WORK_UUID (openconnect/gp engine): `openconnect --authenticate` runs
    first, relaying its own prompts, then a real, throwaway NM secret agent
    answers NetworkManager's request for the cookie, with no further human
    interaction. See core/activation.py's and core/nm_secrets.py's module
    docstrings for why nothing less than a real agent satisfies this VPN
    service — confirmed against the real portal, not assumed."""

    AUTH = {"mode": "prompt", "user": "martin", "password": SECRET,
            "COOKIE": "abc@def@123", "HOST": "10.0.0.1", "CONNECT_URL": "https://gw.example.com",
            "FINGERPRINT": "sha1:469bb424ec8835944d30bc77c77e8fc1d8e23a42", "RESOLVE": "gw.example.com:10.0.0.1"}

    def start_prompt(self, **auth_overrides):
        auth = {**self.AUTH, **auth_overrides}
        # cache_cookie.expected: the fake driver method records only
        # match/mismatch (never the raw cookie — see nm_driver.py), so this
        # still proves the cookie stage one produced is what actually
        # reaches the agent's response, without the fake trivially passing.
        self.set_state(auth=auth, cache_cookie={"expected": auth["COOKIE"]})
        self.helper("connect", WORK_UUID)
        return self.wait_status(lambda r: r["state"] == "AUTHENTICATING")

    def test_openconnect_prompts_are_relayed_then_agent_answers_unattended(self):
        result = self.start_prompt()
        self.assertEqual({k: v for k, v in result["prompt"].items() if k != "id"},
                         {"label": "Username", "field": "username", "secret": False})
        self.helper("credentials", result["prompt"]["id"], stdin="martin\n")

        result = self.wait_status(lambda r: r["state"] == "AUTHENTICATING" and r["prompt"]["field"] == "password")
        self.assertTrue(result["prompt"]["secret"])
        self.helper("credentials", result["prompt"]["id"], stdin=SECRET + "\n")

        # No cookie prompt ever reaches the panel: the agent answers it
        # directly, never through the panel's credential FIFO at all.
        result = self.wait_status(lambda r: r["state"] != "AUTHENTICATING")
        self.assertIsNone(result["error"])
        self.assertIsNone(result["prompt"])
        self.assertIn(["activate_with_agent", WORK_UUID, "match"], self.nmcli_calls())

    def test_wrong_password_fails_before_touching_nmcli(self):
        result = self.start_prompt()
        self.helper("credentials", result["prompt"]["id"], stdin="martin\n")
        result = self.wait_status(lambda r: r["prompt"] and r["prompt"]["field"] == "password")
        self.helper("credentials", result["prompt"]["id"], stdin="wrong\n")

        result = self.wait_status(lambda r: r["state"] == "ERROR")
        self.assertIn("Login failed", result["error"]["message"])
        # A failed portal login must never reach the real activation step.
        self.assertFalse(any(call[0] == "activate_with_agent" for call in self.nmcli_calls()))

    def test_cookie_never_appears_in_argv_or_on_disk(self):
        self.start_prompt()
        self.assertTrue(self.helper("credentials", self.helper("status")["prompt"]["id"], stdin="martin\n")["ok"])
        self.helper("credentials", self.wait_status(lambda r: r["prompt"])["prompt"]["id"], stdin=SECRET + "\n")
        self.wait_status(lambda r: r["state"] != "AUTHENTICATING")

        cookie = self.AUTH["COOKIE"]
        self.assertNotIn(cookie, self.log_file.read_text())
        for path in self.state_dir.rglob("*"):
            if path.is_file():
                self.assertNotIn(cookie.encode(), path.read_bytes(), path)

    def test_gateway_and_cert_are_resolved_before_activation(self):
        self.start_prompt()
        self.helper("credentials", self.helper("status")["prompt"]["id"], stdin="martin\n")
        self.helper("credentials", self.wait_status(lambda r: r["prompt"])["prompt"]["id"], stdin=SECRET + "\n")
        self.wait_status(lambda r: r["state"] != "AUTHENTICATING")

        modify = next(c for c in self.nmcli_calls() if c[:2] == ["connection", "modify"])
        self.assertIn("gateway = https://gw.example.com", modify[-1])
        self.assertIn(self.AUTH["FINGERPRINT"], modify[-1])
        self.assertIn(["activate_with_agent", WORK_UUID, "match"], self.nmcli_calls())

    def test_activation_failure_after_a_good_login_surfaces_as_error(self):
        self.start_prompt()
        self.set_state(auth=self.AUTH, cache_cookie={"expected": self.AUTH["COOKIE"]},
                        activate={"mode": "fail", "error": "Error: Connection activation failed: No valid secrets"})
        self.helper("credentials", self.helper("status")["prompt"]["id"], stdin="martin\n")
        self.helper("credentials", self.wait_status(lambda r: r["prompt"])["prompt"]["id"], stdin=SECRET + "\n")

        result = self.wait_status(lambda r: r["state"] == "ERROR")
        self.assertIn("No valid secrets", result["error"]["message"])

    def test_authentication_failure_surfaces_as_error(self):
        # A delay past EARLY_FAILURE_WINDOW: connect acknowledges, and the
        # portal's own failure (unreachable, TLS error, ...) surfaces later
        # as ERROR — mirroring ErrorStateTests' late-failure case.
        self.set_state(auth={"mode": "fail", "delay": 2, "error": "Failed to obtain WebVPN cookie."})
        self.assertTrue(self.helper("connect", WORK_UUID)["ok"])
        result = self.wait_status(lambda r: r["state"] == "ERROR")
        self.assertIn("Failed to obtain WebVPN cookie", result["error"]["message"])


class VerifyAndSavedCredentialsTests(FakeNmTestCase):
    """`verify` runs the same interactive login as `connect` but never
    touches NetworkManager; on success it saves username+password (never
    the cookie — that's re-derived fresh every time) so a later `connect`
    can skip the prompt entirely."""

    AUTH = {"mode": "prompt", "user": "martin", "password": SECRET,
            "COOKIE": "abc@def@123", "HOST": "10.0.0.1", "CONNECT_URL": "https://gw.example.com",
            "FINGERPRINT": "sha1:469bb424ec8835944d30bc77c77e8fc1d8e23a42", "RESOLVE": "gw.example.com:10.0.0.1"}

    def start_verify(self, **auth_overrides):
        self.set_state(auth={**self.AUTH, **auth_overrides})
        self.helper("verify", WORK_UUID)
        return self.wait_status(lambda r: r["state"] == "AUTHENTICATING")

    def test_verify_success_saves_credentials_and_never_connects(self):
        result = self.start_verify()
        self.assertTrue(result["verifying"])
        self.helper("credentials", result["prompt"]["id"], stdin="martin\n")
        result = self.wait_status(lambda r: r["prompt"] and r["prompt"]["field"] == "password")
        self.helper("credentials", result["prompt"]["id"], stdin=SECRET + "\n")

        result = self.wait_status(lambda r: r["verified"] is not None)
        self.assertTrue(result["verified"])
        self.assertEqual(result["state"], "DISCONNECTED")  # never activates a real connection
        self.assertEqual(self.saved_credentials(WORK_UUID), {"username": "martin", "password": SECRET})
        self.assertFalse(any(c[0] == "activate_with_agent" for c in self.nmcli_calls()))

    def test_verify_failure_does_not_save_credentials(self):
        result = self.start_verify()
        self.helper("credentials", result["prompt"]["id"], stdin="martin\n")
        result = self.wait_status(lambda r: r["prompt"] and r["prompt"]["field"] == "password")
        self.helper("credentials", result["prompt"]["id"], stdin="wrong\n")

        result = self.wait_status(lambda r: r["verified"] is False)
        self.assertEqual(result["state"], "ERROR")
        self.assertIn("Login failed", result["error"]["message"])
        self.assertIsNone(self.saved_credentials(WORK_UUID))

    def test_verify_rejects_openvpn_profiles(self):
        result = self.helper("verify", OVPN_UUID)
        self.assertEqual(result["error"]["code"], "INVALID_REQUEST")

    def test_verify_blocked_while_connect_in_progress(self):
        self.set_state(auth=self.AUTH, cache_cookie={"expected": self.AUTH["COOKIE"]})
        self.helper("connect", WORK_UUID)
        self.wait_status(lambda r: r["state"] == "AUTHENTICATING")
        result = self.helper("verify", WORK_UUID)
        self.assertEqual(result["error"]["code"], "INVALID_STATE")

    def test_connect_with_saved_credentials_skips_the_prompt_entirely(self):
        self.seed_credentials(WORK_UUID, "martin", SECRET)
        self.set_state(auth={**self.AUTH, "COOKIE": "fresh-cookie-xyz"}, cache_cookie={"expected": "fresh-cookie-xyz"})
        self.helper("connect", WORK_UUID)

        # Polled repeatedly, not once: a single lucky poll passing would
        # hide a real regression where the prompt flashes briefly.
        result = None
        for _ in range(8):
            result = self.helper("status")
            self.assertIsNone(result["prompt"], result)
            if result["state"] not in ("CONNECTING", "AUTHENTICATING"):
                break
            time.sleep(0.3)
        self.assertNotEqual(result["state"], "AUTHENTICATING")
        self.assertIn(["activate_with_agent", WORK_UUID, "match"], self.nmcli_calls())

    def test_saved_credentials_go_argv_username_pty_password(self):
        self.seed_credentials(WORK_UUID, "martin", SECRET)
        self.set_state(auth={**self.AUTH, "COOKIE": "fresh-cookie-xyz"}, cache_cookie={"expected": "fresh-cookie-xyz"})
        self.helper("connect", WORK_UUID)
        self.wait_status(lambda r: r["state"] not in ("CONNECTING", "AUTHENTICATING"))

        argv = next(c for c in self.nmcli_calls() if c[0] == "openconnect")
        self.assertEqual(argv[argv.index("--user") + 1], "martin")
        # NOT --passwd-on-stdin: that flag makes real openconnect read the
        # password with no prompt text printed at all, which starves the
        # prompt-detection auto-answer in core/activation.py's _run() of
        # the text it waits for before writing anything — confirmed live,
        # it hangs forever ("stuck at connecting"). The password instead
        # goes over the same pty-prompt relay a human's typed answer would.
        self.assertNotIn("--passwd-on-stdin", argv)
        # The password itself must never appear in the logged argv either way.
        self.assertNotIn(SECRET, argv)

    def test_wrong_saved_password_surfaces_as_error_without_prompting(self):
        self.seed_credentials(WORK_UUID, "martin", "stale-wrong-password")
        self.set_state(auth=self.AUTH)  # the portal's real password is SECRET
        # Fails almost instantly (no network round trip for a fake wrong
        # password), so it's an "early failure" returned directly from
        # connect — same documented behavior as a polkit denial — not a
        # deferred ERROR status.
        result = self.helper("connect", WORK_UUID)
        self.assertFalse(result["ok"])
        self.assertIn("Login failed", result["error"]["message"])
        self.assertIsNone(self.helper("status")["prompt"])
