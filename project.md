# Omarchy GlobalConnect

A decoupled, multi-protocol VPN client built as a native status bar plugin and popover menu for the **Omarchy Desktop Shell** (Arch Linux / Hyprland / Quickshell).

This document describes the intended design. The repository currently has a valid bar-widget scaffold and a helper that reports placeholder state. VPN operations and most domain modules below are planned.

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
│   ├── AuthModal.qml          # Credentials, OTP, and SAML triggers
│   └── SpeedStats.qml         # Real-time transfer sparklines & counters
├── assets/                    # Planned SVG glyphs and brand icons
│
├── bin/                       # Executable CLI Interface
│   └── omarchy-vpn-helper     # IPC bridge executed by Quickshell Process
│
├── core/                      # Core Domain & Protocol Drivers (Python 3)
│   ├── __init__.py
│   ├── fsm.py                 # Planned connection lifecycle state machine
│   ├── security.py            # Planned security validations
│   ├── secret_store.py        # Planned Secret Service adapter
│   ├── profile_store.py       # Planned profile storage
│   └── drivers/               # Protocol adapters
│       ├── __init__.py
│       ├── base.py            # Planned VpnDriver definition
│       └── nm_driver.py       # Planned NetworkManager adapter
│
└── tests/                     # Planned security and contract tests
    ├── test_security.py       # Argv leak, path traversal, injection defenses
    ├── test_contracts.py      # JSON schema validation between core and UI
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
- `connect` acknowledges that activation was requested. The panel polls `status` for the resulting connection state. Define the complete response fields, state names, and stable error codes before implementing either side of the IPC contract.
- The helper remains an unprivileged user process. NetworkManager performs privileged network changes under its polkit policy. An authorization denial is surfaced as an error; the helper does not invoke `sudo` or fall back to a direct tunnel driver.
- Use NetworkManager secret-agent handling and appropriate agent-owned or not-saved flags for credentials. Do not put secrets in `nmcli` arguments or generated connection files. Document the exact transport per supported VPN plugin before implementing credential entry.

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
