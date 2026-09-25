# Omarchy GlobalConnect

A decoupled, multi-protocol VPN client built as a native status bar plugin and popover menu for the **Omarchy Desktop Shell** (Arch Linux / Hyprland / Quickshell).

This document describes the design. The NetworkManager phase is implemented: the helper lists, connects and disconnects OpenConnect/OpenVPN profiles through `nmcli`, and the panel drives it. Profile storage and direct drivers are not implemented; items marked "planned" below are still to do.

---

## 1. Objectives & Scope

- **Multi-Protocol Support**:
  - **OpenConnect Engine**: Palo Alto Networks GlobalProtect (`gp`), Cisco AnyConnect (`anyconnect`), Juniper Pulse (`pulse`).
  - **OpenVPN Engine**: Standard `.ovpn` configuration bundles, TLS certificates, user/password auth.
- **Native Omarchy Integration**:
  - A `bar-widget` plugin with a root `BarWidget.qml` entry point displaying connection status, latency, and throughput.
  - A `Panel.qml` loaded by the bar widget, with `KeyboardPanel` navigation (`j`/`k`, `Enter`, `t`, `Esc`), connection hero card, gateway selector, and credential prompt where supported.
- **Enterprise-Grade Security**:
  - Passwords and tokens never exposed in system process tables (`/proc/*/cmdline`).
  - Keyring-backed secret storage (`gnome-keyring` / `secret-tool`).
  - Path traversal and shell injection immunity.
- **Desktop Execution**:
  - The first implementation uses NetworkManager and its VPN plugins. The panel and helper run in the logged-in user's session; NetworkManager performs privileged network changes subject to polkit and connection permissions.
  - Direct OpenConnect and OpenVPN tunnel drivers are a later phase requiring a separately designed, narrowly scoped privilege mechanism.

---

## 2. Architecture: Hexagonal (Ports & Adapters)

The project enforces strict separation between visual presentation, application domain, and low-level protocol drivers.

```
┌──────────────────────────────────────────────────────────────────┐
│                     UI LAYER (root QML files)                    │
│  • BarWidget.qml (manifest entry point and panel lifecycle)     │
│  • Panel.qml (popover content)                                   │
│  • components/ (GatewayRow, AuthModal, SpeedStats)               │
│  • Model.js (Presentation formatting & filtering)                │
└─────────────────────────────────┬────────────────────────────────┘
                                  │ JSON Contract (CLI IPC)
                                  ▼
┌──────────────────────────────────────────────────────────────────┐
│                    ENTRY POINT (`bin/`)                          │
│  • omarchy-vpn-helper (Thin CLI router & JSON serializer)        │
└─────────────────────────────────┬────────────────────────────────┘
                                  │
┌─────────────────────────────────▼────────────────────────────────┐
│                   CORE DOMAIN (`core/` - Python)                 │
│  • fsm.py (Finite State Machine: DISCONNECTED -> CONNECTED)      │
│  • security.py (Input sanitizer, path canonicalizer, 0600 lock)  │
│  • secret_store.py (gnome-keyring / secret-tool interface)       │
│  • profile_store.py (Profile CRUD & .ovpn parser)                │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ Port: VpnDriver (Abstract Base Class)                      │  │
│  │  - connect(profile, secrets) -> ConnectionResult           │  │
│  │  - disconnect() -> None                                    │  │
│  │  - get_telemetry() -> Telemetry                            │  │
│  └────────────────────────────┬───────────────────────────────┘  │
└───────────────────────────────┼──────────────────────────────────┘
                                │
                                ▼
                 ┌───────────────────────────────┐
                 │ NetworkManager Driver         │
                 │ • networkmanager-openconnect  │
                 │ • networkmanager-openvpn      │
                 └───────────────────────────────┘
```

---

## 3. Directory Layout

```
omarchy-global-connect/
├── manifest.json              # Omarchy shell plugin registration
├── BarWidget.qml              # bar-widget entry point and panel lifecycle
├── Panel.qml                  # Panel loaded by BarWidget.qml
├── Model.js                   # Presentation helpers
├── README.md                  # Setup and current implementation status
├── project.md                 # System architecture and specifications
├── AGENTS.md                  # AI agent engineering & security directives
├── Makefile                   # Validation, linting, and testing tasks
│
├── components/                # Planned modular QML subviews
│   ├── GatewayRow.qml         # Gateway item with [GP]/[Cisco]/[OVPN] badges
│   ├── AuthModal.qml          # Credential prompt (implemented; SAML triggers planned)
│   └── SpeedStats.qml         # Real-time transfer sparklines & counters
├── assets/                    # Planned SVG glyphs and brand icons
│
├── bin/                       # Executable CLI Interface
│   └── omarchy-vpn-helper     # IPC bridge executed by Quickshell Process
│
├── core/                      # Core Domain & Protocol Drivers (Python 3)
│   ├── __init__.py
│   ├── errors.py              # VpnError(code, message)
│   ├── activation.py          # Detached watcher: two-stage OpenConnect auth, credential relay, failure record
│   ├── nm_secrets.py          # Real NM.SecretAgentOld: answers the VPN service's live secrets request
│   ├── state_store.py         # 0700/0600 runtime state under $XDG_RUNTIME_DIR
│   ├── fsm.py                 # Connection lifecycle states and legal transitions
│   ├── security.py            # Profile-ID validation and output scrubbing
│   └── drivers/               # Protocol adapters
│       ├── __init__.py
│       └── nm_driver.py       # NetworkManager adapter (nmcli)
│   # Planned: secret_store.py, profile_store.py, drivers/base.py (only once a second driver exists)
│
└── tests/
    ├── fake_nmcli.py          # nmcli stand-in serving a JSON fixture
    ├── test_activation.py     # ERROR state, credential relay, cancellation
    ├── test_security.py       # Injection, argv, non-VPN-UUID and scrubbing defenses
    ├── test_contracts.py      # Helper JSON output shape, states and error codes
    └── test_fsm.py            # Connection state transition integrity
```

---

## 4. Key Subsystems

### A. The UI Module (root QML files)
- Pure presentation. Contains no knowledge of process PIDs, sockets, or protocol command flags.
- Declare `kinds: ["bar-widget"]` and `entryPoints.barWidget: "BarWidget.qml"` in a schema version 1 manifest. Use a permanent namespaced ID outside `omarchy.*`, and the same ID as `moduleName` in both QML files. The nested panel is not a separate manifest kind.
- `BarWidget.qml` loads `Panel.qml`, passes its bar and anchor context, and forwards `opened`, `open()`, `close()`, and panel switch lifecycle. The plugin runs within the existing shell process; it never starts another Quickshell instance.
- Interacts with the backend via `Quickshell.Io.Process` calling `bin/omarchy-vpn-helper`.
- Adheres to Omarchy's design language:
  - Uses `qs.Commons` (`Style`, `Color`) for theme consistency.
  - Uses `qs.Ui` (`BarWidget`, `WidgetButton`, `KeyboardPanel`, `PanelKeyCatcher`).
  - Supports keyboard-first navigation (`j`/`k`, `Enter`, `t`, `r`, `Esc`).

### B. The Application Core (`core/`)
- **Connection FSM**: Tracks valid states (`DISCONNECTED`, `CONNECTING`, `AUTHENTICATING`, `CONNECTED`, `DISCONNECTING`, `ERROR`).
- **Profile Store**: Stores non-sensitive metadata in `~/.config/omarchy-global-connect/profiles.json`.
- **Secret Store**: Stores passwords, private key passphrases, and SAML cookies in `gnome-keyring` via `secret-tool`.

### C. The Driver Layer (`core/drivers/`)
- **`NetworkManagerDriver`**: Initial adapter. Uses NetworkManager to control `networkmanager-openconnect` and `networkmanager-openvpn`. Authorization is governed by polkit and connection permissions, not `wheel` membership. Report authorization denial to the UI without attempting a privileged fallback.
- **Later direct drivers**: Add only for a demonstrated unsupported workflow. Document the exact privileged operation and authorization policy before implementation. OpenConnect authentication may run as the user, but tunnel creation requires privilege; pass the resulting cookie through stdin, never argv. Direct OpenVPN requires its own privilege and credential transport design.

### D. CLI and privilege contract
- `bin/omarchy-vpn-helper` accepts `list`, `status`, `connect <profile-id>`, and `disconnect`. Arguments contain only command names and opaque profile IDs; credential input, when required, uses stdin. Each invocation emits exactly one JSON object on stdout. Errors use `{"ok": false, "error": {"code": "...", "message": "..."}}`; diagnostics on stderr must be scrubbed of secrets.
- `connect` acknowledges that activation was requested. The panel polls `status` for the resulting connection state.
- **Commands**: also `telemetry` (CONNECTED only), `credentials <prompt-id>` (secret on stdin), and the internal `--watch <profile-id>` used by `connect`.
- **Connect flow**: `connect` starts a detached watcher. For OpenVPN profiles it runs `nmcli --ask --wait 120 connection up` directly — nmcli's own built-in secret agent is enough for a flat username/password prompt. **OpenConnect profiles (GlobalProtect/AnyConnect/Pulse) cannot use nmcli's agent at all**, not even for the simplest secret. The watcher runs `openconnect --authenticate` itself first (openconnect(8), SCRIPTING), relaying its username/password/OTP prompts through the same FIFO; writes the resolved gateway and pinned certificate to `vpn.data` (plus per-secret `-flags = 2` entries — load-bearing, not decoration); then registers a real, throwaway `NM.SecretAgentOld` (`core/nm_secrets.py`) declaring `VPN_HINTS`, which answers NetworkManager's live `GetSecrets` call with `gateway`, `cookie` and `gwcert` together, for the duration of that one activation only. **`core/nm_secrets.py`'s own module docstring has the full debugging history** — two earlier designs (nmcli's `--ask`, then pre-caching via libnm) disproven, the exact NetworkManager/plugin source that explained each failure, and the `-flags` requirement found only by reading NetworkManager's own debug-level log — read it there rather than here, so this stays in one place. A failure within one second (polkit denial, unknown profile, bad portal address) is returned by `connect` itself; a later failure (wrong password, unreachable gateway, activation rejected even once the agent answers) is recorded and reported by `status` as `ERROR` for 5 minutes, or until the next `connect`. `disconnect` cancels a pending watcher at either stage.
- **Responses** (success): `list` → `{"ok":true,"profiles":[{"id","name","engine","protocol","gateway"}]}` where `id` is the NetworkManager UUID, `engine` is `openconnect|openvpn`, `protocol` is `gp|anyconnect|pulse|openvpn`, `gateway` may be null. `status` → `{"ok":true,"state","profile_id","profile_name","error","prompt"}` (profile fields null when disconnected; `error` is `{"code","message"}` in `ERROR`; `prompt` is `{"id","label","field","secret"}` while `AUTHENTICATING` on a credential request). `telemetry` → `{"ok":true,"iface","rx_bytes","tx_bytes","latency_ms"}` with `latency_ms` null when unmeasurable; counters are cumulative and the panel derives rates. `connect`/`disconnect` → `{"ok":true,"state":"CONNECTING"|"DISCONNECTING","profile_id"}`.
- **Telemetry interface lookup**: the VPN connection's own `GENERAL.IP-IFACE` reports OpenConnect's *underlying* device (Wi-Fi/Ethernet), not its tunnel — confirmed against a real connection, where the tunnel is externally-managed and only shows up as a separate, unassociated `tun`-type device in `nmcli device status`. `telemetry()` falls back to that when the direct lookup doesn't yield a readable stats directory, relying on this project's own single-VPN-at-a-time invariant. Interface-name validation is a proper kernel-`dev_valid_name()`-style check (reject `/`, whitespace, `.`/`..`, length), not an alnum-first regex — a real tunnel can be named things an alnum-first pattern would wrongly reject (observed: OpenConnect naming its own tunnel literally `--` when NetworkManager doesn't specify one).
- **States**: `DISCONNECTED`, `CONNECTING`, `AUTHENTICATING` (a credential prompt is pending), `CONNECTED`, `DISCONNECTING`, `ERROR` (NetworkManager removes a failed activation, so the watcher records the failure and `status` overlays it while disconnected).
- **Error codes**: `INVALID_REQUEST`, `INVALID_STATE`, `NOT_FOUND`, `NO_PROMPT`, `INSECURE_STATE`, `PLUGIN_MISSING` (either the OpenConnect/OpenVPN NetworkManager plugin, or — for the libnm cookie handoff specifically — the `python-gobject` bindings, isn't installed; message includes the exact `pacman -S` command either way), `AUTH_DENIED` (polkit), `BACKEND_UNAVAILABLE` (nmcli missing or NetworkManager not running), `TIMEOUT`, `NM_ERROR`, `INTERNAL_ERROR`.
- The helper remains an unprivileged user process. NetworkManager performs privileged network changes under its polkit policy. An authorization denial is surfaced as an error; the helper does not invoke `sudo` or fall back to a direct tunnel driver.
- Use NetworkManager secret-agent handling and appropriate agent-owned or not-saved flags for credentials. Do not put secrets in `nmcli` arguments or generated connection files, and never in a subprocess argument list (`openconnect --authenticate` needs none: it prompts interactively; the cookie handoff needs none either: it's delivered via a libnm callback, in-process, no subprocess involved at all). OpenVPN: `nmcli --ask` is the secret agent directly. OpenConnect: the watcher's own `openconnect --authenticate` step is the "agent" for the human-facing prompts (plain `Label: ` text, no dotted field name — the label doubles as one); the resulting values are handed over by a real `NM.SecretAgentOld` subclass (`core/nm_secrets.py`), registered for the duration of one activation and unregistered once it concludes — see that file for the full debugging history (three separate real bugs, each found by reading NetworkManager's own source or debug log, not guessed). Human-facing answers (stage one's prompts) travel panel stdin → `credentials` stdin → 0600 FIFO → the running subprocess's stdin, matched to a prompt ID, and masked unless the label looks like a username/gateway/selection field. **Testing note**: mechanical verification (fake secret values) must run against a disposable connection profile, never the one a person will actually use — NetworkManager caches whatever secret set an agent successfully provides and reuses it on later activations without re-asking, so testing against a real profile silently poisons it for every subsequent real attempt; this cost significant back-and-forth before being identified, and the only reliable reset found is deleting and recreating the profile. SAML/browser-redirect portals are out of scope — confirmed via this project's own probe that USFQ's portal is plain username/password, not SAML.

**Fixed bug (2026-09-24)**: submitting the combined username/password form cleared `Panel.qml`'s `prompt` property synchronously inside the same key-event handling that submitted it. That flipped `PanelKeyCatcher`'s `blocked` guard back to `false` while the *same* Enter keypress was still propagating (`Keys.priority: Keys.BeforeItem` gives the catcher a pass before the focused field, then the normal bubble-up gives it another after) — so one keystroke fired twice, unblocked the second time, and triggered `activateRequested()` → disconnected the attempt that had just started. Confirmed with temporary `console.log` instrumentation read from the shell's own journal, not guessed. Fixed by deferring the state changes that clear `blocked` (`root.prompt = null`, `root.adding = false` on cancel) via `Qt.callLater`, so they land after the triggering event has finished propagating.

---

## 5. Security & Testing Strategy

- **No bloated TDD**: No hundreds of unit tests for trivial accessors or visual layouts.
- **Focused High-Impact Testing**:
  1. **Argv Leakage**: Ensure passwords/tokens never appear in `sys.argv` or subprocess argument lists.
  2. **Injection Defense**: Ensure command arguments are passed as structured lists with `shell=False`.
  3. **Path Traversal**: Ensure `.ovpn` profiles and cert references cannot escape to unauthorized directories.
  4. **Permission Lockdown**: Ensure all config files and private keys enforce `0600` permissions.
  5. **Contract Validation**: Ensure `bin/omarchy-vpn-helper` JSON output strictly matches the UI schema.

## 6. Omarchy plugin validation

- Keep manifest entry points as safe relative paths and avoid symlinks anywhere in the plugin folder.
- Document runtime dependencies, setup, services, and privilege boundaries in `README.md` before distribution.
- Run `omarchy plugin validate <plugin-directory>` and `qmllint` on both root QML files with the installed Omarchy shell imports. Then test bar click, Escape, shell summon/hide, disable/re-enable, shell restart, and removal in a user-owned plugin directory.
