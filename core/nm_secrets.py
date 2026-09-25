"""Answers NetworkManager's OpenConnect secrets request via a real,
in-process secret agent, since nothing short of that works.

Two earlier designs were tried and empirically disproven against a real
GlobalProtect portal, in order:

1. Hand the cookie to `nmcli --ask`. Fails outright: NetworkManager logs
   "No agents were available for this request" for every secrets request
   this VPN service makes, not just the dynamic username/password round —
   nmcli's built-in agent never advertises VPN_HINTS, which every request
   from this service requires.
2. Pre-cache the cookie on the connection via
   `NM.RemoteConnection.update2(..., IN_MEMORY)`, then activate with no
   agent involved. Also fails, confirmed by manually caching a secret,
   verifying via `nmcli -s` that it was genuinely stored, and then
   activating anyway: identical "No valid secrets" error. NetworkManager
   does not consult a connection's stored secrets for this VPN service at
   activation time; the request explicitly asks for a *new* secret
   (SecretAgentGetSecretsFlags includes REQUEST_NEW) and skips anything
   already on the connection.

So this registers a genuine `NM.SecretAgentOld` for the one activation,
answers its `get_secrets` call with values already in hand from
`core/activation.py`'s own `openconnect --authenticate` step, and
unregisters once activation finishes. `NM.SecretAgentOld` is abstract and
provides no defaults, so a subclass missing any one of
get_secrets/cancel_get_secrets/save_secrets/delete_secrets fails
GInitable init with an assertion, silently, with no usable error message
surfaced to Python — this took reading NetworkManager's own C source
(fetched from its GitHub mirror) to diagnose, since this distro's libnm
build strips assertion text to a literal "<dropped>", unreadable even
under gdb.

The response needs three secrets, not just the cookie: NetworkManager-
openconnect's own `real_need_secrets()` (src/nm-openconnect-service.c,
fetched the same way, after a real answer containing only "cookie" was
consistently rejected with "final secrets request failed to provide
sufficient secrets") checks `nm_setting_vpn_get_secret()` — the *secrets*
namespace, not vpn.data, even though gateway and the cert fingerprint
already live in vpn.data as plain config — for all three of
NM_OPENCONNECT_KEY_GATEWAY ("gateway"), _COOKIE ("cookie") and _GWCERT
("gwcert").

Even all three present isn't enough by itself: NetworkManager's own
debug-level log (`nmcli general logging level DEBUG domains VPN,AGENTS`)
showed the agent being asked and answering without error every time
("agent returned secrets for request"), yet the VPN service kept
reporting "additional secrets required" until NetworkManager gave up —
because the connection never *declared* gateway/cookie/gwcert as
agent-suppliable secrets in the first place, so NetworkManager silently
dropped the two it didn't already expect when deciding whether the
service now had enough. `apply_openconnect_secrets()` in nm_driver.py
fixes this by writing "gateway-flags = 2", "cookie-flags = 2" and
"gwcert-flags = 2" (NOT_SAVED | AGENT_OWNED) into vpn.data alongside the
values themselves — confirmed by toggling exactly this and watching the
debug log flip from repeated failures to "service indicated no additional
secrets required" on the next attempt, against a real connection.

One more trap, purely from testing methodology, not a design flaw: once
NetworkManager accepts a (possibly fake, from mechanical testing) secret
set as sufficient, it caches it on the connection — visible via plain
`nmcli -s -f vpn.secrets` — and *reuses that cache on later activations
without re-asking the agent at all*. A connection used for mechanical
verification with placeholder values is contaminated for real use from
then on; `clear_secrets()` does not clear it. The only reliable reset
found was deleting and recreating the connection profile (a fresh UUID
has no cache history). Test against a disposable connection, never the
one a person will actually use.
"""

import gi

gi.require_version("NM", "1.0")
from gi.repository import GLib, NM  # noqa: E402

from core.errors import VpnError

_SERVICE_TYPE = "org.freedesktop.NetworkManager.openconnect"
_IDENTIFIER = "dev.martin.global-connect"


class _CookieAgent(NM.SecretAgentOld):
    """Scoped to one connection UUID and one set of secrets; never asked
    about anything else, and unregistered the moment activation concludes."""

    def __init__(self, uuid: str, secrets: dict[str, str]):
        super().__init__(identifier=_IDENTIFIER, capabilities=NM.SecretAgentCapabilities.VPN_HINTS)
        self._uuid = uuid
        self._secrets = secrets

    def do_get_secrets(self, connection, connection_path, setting_name, hints, flags, callback, user_data=None):
        if connection.get_uuid() != self._uuid or setting_name != "vpn":
            callback(self, connection, None, GLib.Error("Not this project's connection."))
            return
        secrets = GLib.Variant("a{sa{sv}}", {"vpn": {"secrets": GLib.Variant("a{ss}", self._secrets)}})
        callback(self, connection, secrets, None)

    def do_cancel_get_secrets(self, connection_path, setting_name):
        pass

    def do_save_secrets(self, connection, connection_path, callback, user_data=None):
        callback(self, connection, None)

    def do_delete_secrets(self, connection, connection_path, callback, user_data=None):
        callback(self, connection, None)


def activate(profile_id: str, gateway: str, cookie: str, gwcert: str, wait: int) -> None:
    """Register the agent, activate the connection, wait for the result,
    and unregister — all within one throwaway GLib main loop, since the
    agent can only answer callbacks while one is running."""
    agent = _CookieAgent(profile_id, {"gateway": gateway, "cookie": cookie, "gwcert": gwcert})
    if not agent.init(None):
        raise VpnError("NM_ERROR", "Failed to initialize the VPN secret agent.")

    outcome: dict = {}
    loop = GLib.MainLoop()

    def registered(source, result):
        try:
            if not source.register_finish(result):
                outcome["error"] = VpnError("NM_ERROR", "Failed to register the VPN secret agent.")
                loop.quit()
                return
        except GLib.Error as err:
            outcome["error"] = VpnError("NM_ERROR", f"Failed to register the VPN secret agent: {err.message}")
            loop.quit()
            return
        _start_activation(profile_id, wait, outcome, loop)

    agent.register_async(None, registered)
    # Absolute ceiling beyond `wait`: guards against a stuck callback chain
    # leaving the watcher hung forever instead of failing visibly.
    GLib.timeout_add_seconds(wait + 10, loop.quit)
    loop.run()
    agent.unregister(None)

    if "error" in outcome:
        raise outcome["error"]


def _start_activation(profile_id: str, wait: int, outcome: dict, loop: GLib.MainLoop) -> None:
    import subprocess

    proc = subprocess.Popen(
        ["nmcli", "--wait", str(wait), "connection", "up", "uuid", profile_id],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )

    def poll():
        if proc.poll() is None:
            return True
        if proc.returncode:
            from core.drivers.nm_driver import classify_error
            outcome["error"] = classify_error(proc.stdout.read())
        loop.quit()
        return False

    GLib.timeout_add(200, poll)
