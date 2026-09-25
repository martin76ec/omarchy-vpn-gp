# GlobalConnect

Omarchy bar widget that lists, connects and disconnects NetworkManager VPN profiles (OpenConnect: GlobalProtect/AnyConnect/Pulse, and OpenVPN). It does not create profiles; it drives what NetworkManager already knows. Credentials are only ever stored if you explicitly ask it to (see **Saved credentials** below) — by default it asks each time, the same as NetworkManager itself would.

## Setup

1. Install NetworkManager and the plugin for your protocol: `networkmanager-openconnect` and/or `networkmanager-openvpn`. GlobalProtect/AnyConnect/Pulse profiles also need `python-gobject` (provides the `gi`/libnm Python bindings the cookie handoff uses — see step 3) and the `openconnect` CLI, both usually already present alongside `networkmanager-openconnect`. The plugin never runs any of this for you (it never calls `sudo`, and neither does any first-party Omarchy plugin); if you skip a step, connecting shows the exact command to run.
2. Create a profile with `nm-connection-editor` or `nmcli connection add type vpn ...`. Only profiles whose service type is OpenConnect or OpenVPN are listed.
3. Credentials are requested in the panel itself. GlobalProtect/AnyConnect/Pulse profiles authenticate through `openconnect --authenticate` (the officially documented way to script OpenConnect — see openconnect(8)), then the resulting cookie is handed to NetworkManager by a real, throwaway secret agent this plugin registers for that one activation (`core/nm_secrets.py`). That's not a stylistic choice: confirmed against a real GlobalProtect portal that NetworkManager rejects nmcli's `--ask` agent for *every* secret this VPN service asks for — not just the interactive username/password round — and that pre-caching the secret on the connection doesn't help either, since this service always asks fresh. Only a real secret agent answering the live request works. OpenVPN profiles use `nmcli --ask` directly — that one nmcli can actually serve, no extra agent needed.

## Usage

Click the bar button. While connected the panel shows throughput and gateway latency (TCP connect time; OpenConnect profiles only). `j`/`k` move, `Enter` connects the selected profile (or disconnects it when active), `t` toggles, `s` tests the selected profile's server, `v` verifies its credentials (see below), `a` adds a profile, `x` deletes the selected one (press twice to confirm), `r` refreshes, `Esc` closes. Each profile row also has clickable Test/Verify buttons, and the credential prompt has Submit/Cancel buttons, for mouse use. Only one VPN can be active at a time.

### Server check (`s` / the Test button)

A plain TCP+TLS connect-time probe against the profile's gateway address — no credentials, no protocol negotiation, just "is this host reachable." Useful for telling a down/unreachable server apart from a login problem before you type a password.

### Saved credentials (`v` / the Verify button, GlobalProtect/AnyConnect/Pulse only)

Runs the same interactive login as connecting, but never touches NetworkManager. On success it stores the username and password in the system's FreeDesktop Secret Service keyring (`secret-tool`/gnome-keyring), scoped to that one profile, and the row gets a "saved" tag. From then on, connecting that profile supplies the saved username via `--user` and answers the password prompt automatically over the same pty relay a human's typed answer would go through — never via `openconnect`'s own `--passwd-on-stdin`, which turned out to suppress the very prompt text the auto-answer relies on and hangs the connection forever (see `core/drivers/nm_driver.py`'s `authenticate_saved_argv` docstring). If the login fails, nothing is saved and the panel shows why. OpenVPN doesn't get a Verify button: `nmcli --ask` already handles its credentials directly, so there's nothing separate to pre-verify.

## Privilege boundary

The panel and `bin/omarchy-vpn-helper` run as your user and never call `sudo`. NetworkManager performs the network changes under its polkit policy; if polkit denies the request the panel shows the error and stops. Credentials you type go panel stdin, then the helper's stdin, then a 0600 FIFO in `$XDG_RUNTIME_DIR/omarchy-global-connect` (0700, tmpfs), then the running subprocess's stdin. They are never placed in an argument list, written to a file, or logged. Saved credentials (see above) live only in the system keyring, addressed via `secret-tool` with the secret piped over stdin, never an argument. The GlobalProtect/AnyConnect/Pulse cookie that comes out the other end is a different kind of secret — not something you typed, but still sensitive — and is handed to NetworkManager entirely in-process: this plugin registers a real NetworkManager secret agent for the duration of one activation, which answers the daemon's live request over its own D-Bus callback, never a subprocess argument, a file, or a log. Failures and prompts are kept in the runtime directory and disappear on logout. The helper only activates connections that are OpenConnect/OpenVPN profiles, so a crafted profile ID cannot bring down Wi-Fi or Ethernet.

## Known limitations

- Portals that redirect to a browser for SAML/SSO login are not handled — only plain username/password (confirmed against a real GlobalProtect portal that uses this flow; a SAML one was not available to test against).
- The OpenVPN path (`nmcli --ask` relay) is verified against a fake `nmcli` only, not a real OpenVPN profile — the GlobalProtect path is the one confirmed end-to-end against a live server.
- Saved-credentials auto-answer only covers the first prompt after the username (normally just the password). Anything beyond that — an OTP, a changed portal flow — still falls through to a real prompt, same as a first-time connect.

## Development

- `make check` runs plugin validation, the tests and a bytecode compile. `make test` runs only the tests (`tests/fake_nmcli.py`/`fake_openconnect.py`/`fake_secret_tool.py` stand in for the real CLIs, so no VPN or keyring is touched).
- QML lint: `qmllint -I <dir containing a "qs" symlink to /usr/share/omarchy/shell> BarWidget.qml Panel.qml`.
- The OpenConnect two-stage flow (authenticate, then register a real secret agent for one activation, answering with `gateway`, `cookie` and `gwcert` together, each declared agent-owned via a `-flags = 2` entry in `vpn.data`) is verified end-to-end against a real GlobalProtect portal and a real connection profile, including a full tunnel with a real login (confirmed via a real tunnel interface and a real assigned IP, not assumed) and the saved-credentials replay path (confirmed connecting with zero prompts from a previously-verified profile). **`core/nm_secrets.py`'s module docstring has the full debugging history** — three real, separate bugs, two disproven designs, and a testing-methodology trap (a connection used for mechanical testing gets its secret cache poisoned by NetworkManager and must be deleted and recreated before real use) — worth reading before touching this code again.
