# AI Engineering & Security Directives

This document sets the mandatory coding, architecture, and security directives for all AI agents contributing to `omarchy-global-connect`.

---

## 1. High-Signal AI Comments Only

- **Never state the obvious**: Do not write comments that describe what the syntax already shows (e.g., `# Loop through profiles`, `# Return true`).
- **Document rationale and non-obvious invariants**: Write comments explaining *why* a particular decision was made, protocol quirks, security guardrails, or platform-specific gotchas.
  ```python
  # Good:
  # OpenConnect requires password over stdin to avoid process table (/proc) leakage.
  # Bad:
  # Write password to stdin.
  ```

---

## 2. Concise, High-Density Code

- Write the most concise, idiomatic code possible without sacrificing readability.
- Prefer Python stdlib features (`dataclasses`, `pathlib`, `itertools`, `subprocess.run`) and modern syntax (Python 3.12+ type hints, pattern matching).
- Avoid premature abstractions, unnecessary wrapper classes, and repetitive boilerplate.

---

## 3. Centralized Error Handling

- **Do NOT sprinkle `try/except` across every function**: Catching exceptions everywhere produces noisy, unmaintainable code and masks bugs.
- **Fail fast in domain logic & drivers**: Allow standard exceptions (`ValueError`, `FileNotFoundError`, `SecurityException`) to bubble up.
- **Centralize user-facing errors at system boundaries**: Catch domain errors at the CLI / IPC boundary (`bin/omarchy-vpn-helper` and `Panel.qml`) and serialize them into structured JSON responses. Catch exceptions near resource ownership when cleanup or recovery requires it:
  ```python
  # Top-level boundary catcher:
  def main():
      try:
          dispatch_command(sys.argv[1:])
      except VpnError as err:
          emit_json({"status": "error", "code": err.code, "message": str(err)})
          sys.exit(1)
  ```

---

## 4. Flat Control Flow (Avoid Nested Structures)

- Prefer **guard clauses** and **early returns**; use deeper nesting when it makes the logic clearer.
- Avoid deep `if/else` pyramids, nested loops, and callback hell.
  ```python
  # Preferred (Flat):
  def activate_profile(profile: Profile) -> None:
      if not profile.is_valid:
          raise ValidationError("Invalid profile")
      if fsm.state != State.DISCONNECTED:
          raise StateError("VPN already active")
      driver.connect(profile)

  # Prohibited (Deep nesting):
  def activate_profile(profile: Profile) -> None:
      if profile.is_valid:
          if fsm.state == State.DISCONNECTED:
              driver.connect(profile)
          else:
              raise StateError("VPN already active")
      else:
          raise ValidationError("Invalid profile")
  ```

---

## 5. Idiomatic OOP & FP Patterns

- **Object-Oriented Programming (OOP)**: Use for stateful entities, lifecycle management, and polymorphic adapters:
  - An abstract `VpnDriver` port when multiple adapters justify it; the initial implementation uses `NetworkManagerDriver`. Direct process drivers require a separately reviewed privilege design.
  - Finite State Machine (`ConnectionFSM`) to manage state transitions.
- **Functional Programming (FP)**: Use for data transformation, parsing, and formatting:
  - Pure functions for parsing `.ovpn` files, calculating throughput rates, and formatting durations.
  - Immutability for configuration objects (`@dataclass(frozen=True)`).
  - List comprehensions, `map`, and dictionary filters over stateful mutation loops.

---

## 6. Strict Security Directives

Any code that violates these directives will be rejected immediately:

1. **Zero Credential Exposure on `sys.argv` (`CWE-214`)**:
   - Never pass passwords, private key passphrases, or auth tokens via command-line arguments.
   - Always supply credentials via **stdin pipes**, temporary file descriptors, or FreeDesktop Secret Service.
2. **Absolute Prohibition of `shell=True` (`CWE-78`)**:
   - Subprocesses must always be invoked with argument lists (`["openconnect", ...]` or `["nmcli", ...]`) and `shell=False`.
3. **Strict Path Canonicalization & Traversal Defense (`CWE-22`)**:
   - All file paths (profiles, certificates, keys) must be resolved via `Path.resolve()` and verified to reside inside permitted directories.
   - Prohibit following untrusted symlinks pointing outside the configuration root.
4. **Enforced File Permissions (`CWE-732`)**:
   - Configuration directories must enforce `0700` (`rwx------`).
   - Profile definitions, temporary configs, and token caches must enforce `0600` (`rw-------`).
5. **No Secret Logging**:
   - Telemetry, stderr collectors, and debug logs must be scrubbed of session cookies, passwords, and authorization headers.

---

## 7. Pragmatic Testing Directives

- **No TDD Dogmatism**: Do not write tests for boilerplate getters, UI element bindings, or simple passthroughs.
- **Focus Exclusively on High-Risk Invariants**:
  1. *Security Tests*: Verify secrets do not leak to `cmdline`, paths cannot traverse out of bounds, and shell injection strings are treated as literals.
  2. *Contract Tests*: Verify `bin/omarchy-vpn-helper` CLI outputs match the exact JSON schema expected by `Model.js` and `Panel.qml`.
  3. *FSM Transitions*: Verify illegal state transitions raise proper exceptions.
