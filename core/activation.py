"""Activation watcher.

OpenVPN profiles connect in one step: `nmcli --ask connection up` acts as
its own secret agent, and credentials flow panel stdin -> `credentials`
helper stdin -> 0600 FIFO -> nmcli stdin.

OpenConnect profiles (GlobalProtect/AnyConnect/Pulse) cannot use that one
step. Their portal login is a multi-round, plugin-driven negotiation, and
NetworkManager only routes ANY secrets request from this VPN service —
not just the dynamic username/password round, confirmed the same for the
final single-field cookie handoff too — to an agent that advertises
VPN_HINTS support. nm-applet's GUI auth-dialog does; nmcli's built-in
--ask agent never does, so it gets "No agents were available for this
request" every time, no matter how simple the request is. A pre-cached
secret doesn't help either — confirmed empirically that NetworkManager
still asks an agent for this service even when a secret is already stored
on the connection. So for these engines we authenticate ourselves first
with `openconnect --authenticate` (openconnect(8), SCRIPTING) — relaying
its prompts through the same FIFO — then register a real, throwaway
secret agent (core/nm_secrets.py) that answers with the cookie already in
hand, for the duration of that one activation only.

No secret is ever placed in an argument list, a file, or a log.
"""

import errno
import os
import pty
import re
import secrets
import select
import signal
import subprocess
import sys

from core import secret_store, state_store
from core.drivers.nm_driver import (
    Status,
    authenticate_argv,
    authenticate_saved_argv,
    classify_error,
    parse_authenticate_output,
)
from core.errors import VpnError
from core.fsm import State
from core.security import scrub

DEADLINE = 120
FAILURE_TTL = 300
# nmcli does not end prompts with a newline, so a prompt is a trailing
# "Label (field.name): " fragment after the output has gone quiet.
_NMCLI_PROMPT = re.compile(r"(?P<label>[^\n()]+?) \((?P<field>[\w.\-]+)\): $")
# openconnect's own prompts are plainer ("Username: ", "Password: ", a
# numbered gateway list ending in "...list above ('.' to abort): "), with no
# machine-readable field name — the label doubles as one.
_OPENCONNECT_PROMPT = re.compile(r"(?P<label>[A-Za-z][^\n:]{0,60}):[ \t]*$")
_SECRET_WORDS = re.compile(r"pass|secret|token|pin\b|otp|passcode|response|code|cookie", re.IGNORECASE)
_MAX_SECRET = 1024
_PROMPT_ID = re.compile(r"[0-9a-f]{8}")


def _fifo_path():
    return state_store.state_dir() / "credentials.fifo"


def _watcher_pid() -> int | None:
    info = state_store.read("watcher")
    if not info:
        return None
    try:
        cmdline = open(f"/proc/{info['pid']}/cmdline", "rb").read()
    except OSError:
        return None
    # Guards against a recycled PID: only trust it if it is still a watcher
    # (either --watch or --verify-watch — both end in "-watch").
    return info["pid"] if b"-watch" in cmdline else None


def observe(status: Status) -> Status:
    """Overlay watcher knowledge on NetworkManager's view of the connection."""
    info = state_store.read("watcher") if _watcher_pid() else None
    if info and info.get("kind") == "verify":
        # A verify watcher never touches NetworkManager (see verify()), so
        # status.state stays DISCONNECTED throughout — synthesize the
        # prompt phase the same way a connect watcher does.
        prompt = state_store.read("prompt")
        state = State.AUTHENTICATING if prompt else State.CONNECTING
        return Status(state, info["profile_id"], info["profile_name"], prompt=prompt, verifying=True)
    if info and status.state in (State.DISCONNECTED, State.CONNECTING, State.AUTHENTICATING):
        prompt = state_store.read("prompt")
        # The watcher exists before NetworkManager registers the activation.
        state = State.AUTHENTICATING if prompt else (status.state if status.state is not State.DISCONNECTED else State.CONNECTING)
        return Status(state, info["profile_id"], info["profile_name"], prompt=prompt)
    if status.state is State.DISCONNECTED:
        if verified := state_store.read("verified", FAILURE_TTL):
            if verified["ok"]:
                return Status(State.DISCONNECTED, verified.get("profile_id"), verified.get("profile_name"), verified=True)
            error = {"code": verified["code"], "message": verified["message"]}
            return Status(State.ERROR, verified.get("profile_id"), verified.get("profile_name"), error=error, verified=False)
        if failure := state_store.read("failure", FAILURE_TTL):
            error = {"code": failure["code"], "message": failure["message"]}
            return Status(State.ERROR, failure["profile_id"], failure["profile_name"], error=error)
    return status


def cancel() -> None:
    """Stop a pending activation; SIGTERM lets the watcher clean up after itself."""
    if pid := _watcher_pid():
        os.kill(pid, signal.SIGTERM)


def submit(prompt_id: str, secret: str) -> None:
    prompt = state_store.read("prompt")
    if not _PROMPT_ID.fullmatch(prompt_id) or not prompt or prompt["id"] != prompt_id:
        raise VpnError("NO_PROMPT", "No matching credential prompt is pending.")
    try:
        fd = os.open(_fifo_path(), os.O_WRONLY | os.O_NONBLOCK)
    except OSError as err:
        if err.errno in (errno.ENXIO, errno.ENOENT):
            raise VpnError("NO_PROMPT", "No matching credential prompt is pending.") from None
        raise
    with os.fdopen(fd, "wb") as fifo:
        fifo.write(secret[:_MAX_SECRET].encode() + b"\n")


def watch(driver, profile_id: str) -> None:
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(1))
    profile = proc = None
    try:
        profile = driver.find_profile(profile_id)
        state_store.clear("failure")
        state_store.clear("verified")
        state_store.clear("prompt")
        state_store.write("watcher", {"pid": os.getpid(), "profile_id": profile.id, "profile_name": profile.name})
        if profile.engine == "openconnect":
            # A saved username/password (see verify() below) skips the
            # interactive prompt entirely: only what wasn't already known —
            # normally nothing — still reaches the panel.
            saved = secret_store.load(profile.id)
            auth = _authenticate(profile, saved=saved)
            driver.apply_openconnect_secrets(profile, auth)
            # A real, in-process secret agent for the duration of this one
            # activation — see core/nm_secrets.py's module docstring for
            # why nothing short of that satisfies this VPN service.
            driver.activate_with_agent(profile, auth, DEADLINE)
        else:
            _, proc = driver.open_activation(profile_id, DEADLINE)
            output = _run(proc.stdout.fileno(), proc.stdin.fileno(), _NMCLI_PROMPT)
            if proc.wait():
                raise classify_error(_failure_text(output))
    except VpnError as err:
        state_store.write("failure", {
            "profile_id": profile.id if profile else profile_id,
            "profile_name": profile.name if profile else None,
            "code": err.code, "message": str(err),
        })
        raise
    finally:
        if proc and proc.poll() is None:
            proc.kill()
        state_store.clear("prompt")
        state_store.clear("watcher")
        _fifo_path().unlink(missing_ok=True)


def verify(driver, profile_id: str) -> None:
    """Runs the same interactive `openconnect --authenticate` step as
    watch(), but never touches NetworkManager at all — it only exists to
    confirm the typed username/password work, then save them (see
    core/secret_store.py) for watch() to use silently next time. Success
    or failure is recorded the same way a connect failure is (state_store
    "verified", read by observe()), since this process exits before any
    caller could read a return value."""
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(1))
    profile = None
    try:
        profile = driver.find_profile(profile_id)
        if profile.engine != "openconnect":
            raise VpnError("INVALID_REQUEST", "Only GlobalProtect/AnyConnect/Pulse profiles support saved credentials.")
        state_store.clear("failure")
        state_store.clear("verified")
        state_store.clear("prompt")
        state_store.write("watcher", {"pid": os.getpid(), "profile_id": profile.id, "profile_name": profile.name, "kind": "verify"})
        captured: dict[str, str] = {}
        _authenticate(profile, capture=captured)
        if "username" not in captured or "password" not in captured:
            raise VpnError("NM_ERROR", "The portal did not ask for a username and password the way this feature expects.")
        secret_store.save(profile.id, captured["username"], captured["password"])
        state_store.write("verified", {"ok": True, "profile_id": profile.id, "profile_name": profile.name})
    except VpnError as err:
        state_store.write("verified", {
            "ok": False, "code": err.code, "message": str(err),
            "profile_id": profile.id if profile else profile_id,
            "profile_name": profile.name if profile else None,
        })
        raise
    finally:
        state_store.clear("prompt")
        state_store.clear("watcher")
        _fifo_path().unlink(missing_ok=True)


def _authenticate(profile, saved: tuple[str, str] | None = None, capture: dict[str, str] | None = None) -> dict[str, str]:
    """Run `openconnect --authenticate` under a pty (it disables terminal
    echo for the password prompt, which fails outright on a plain pipe —
    confirmed against a real portal: "Inappropriate ioctl for device").

    `saved`, when given, supplies the username via argv (not a secret —
    man openconnect: "-u,--user ... should not be used to enter
    passwords") and the password automatically the moment openconnect asks
    for it, without that prompt ever reaching the panel. `capture`, when
    given, records what was typed (or auto-answered) for each field name,
    for verify() to save afterward — never done for a `saved`-driven run,
    which already came from the keyring."""
    argv = authenticate_saved_argv(profile, saved[0]) if saved else authenticate_argv(profile)
    master_fd, slave_fd = pty.openpty()
    proc = subprocess.Popen(
        argv, stdin=slave_fd, stdout=slave_fd, stderr=slave_fd,
        start_new_session=True, env={**os.environ, "LC_ALL": "C"},
    )
    os.close(slave_fd)
    try:
        output = _run(master_fd, master_fd, _OPENCONNECT_PROMPT, auto_answer=saved[1] if saved else None, capture=capture)
    finally:
        os.close(master_fd)
    code = proc.wait()
    auth = parse_authenticate_output(output.decode(errors="replace"))
    if code or "COOKIE" not in auth:
        raise classify_error(_failure_text(output))
    return auth


def _failure_text(output: bytes) -> str:
    # nmcli trails its "Error: ..." line with an unhelpful "Hint: use
    # journalctl ..." line; prefer whichever lines actually say what broke.
    lines = [line for line in output.decode(errors="replace").splitlines() if line.strip()]
    meaningful = [line for line in lines if re.search(r"error|fail", line, re.IGNORECASE)]
    return scrub("\n".join(meaningful) if meaningful else " ".join(lines[-2:])) or "The VPN helper exited without a clear error."


def _run(read_fd: int, write_fd: int, prompt_re: re.Pattern,
         auto_answer: str | None = None, capture: dict[str, str] | None = None) -> bytes:
    """Pump `read_fd`, publish detected prompts to the panel via the
    credentials FIFO, and write typed answers back to `write_fd`. Returns
    everything read since the last answered prompt.

    `auto_answer`, when given, answers the *first* prompt on sight without
    ever reaching the panel — used for a saved password once the username
    is already supplied via argv. Anything after that first prompt still
    goes to the human: a defensive fallback in case the portal unexpectedly
    needs more (OTP, a changed flow).

    `capture`, when given, records field name -> answer (typed or
    auto-answered) for every prompt handled here, for verify() to save
    afterward.
    """
    fifo_path = _fifo_path()
    fifo_path.unlink(missing_ok=True)
    os.mkfifo(fifo_path, 0o600)
    # O_RDWR keeps the FIFO from reporting EOF between writers.
    fifo = os.open(fifo_path, os.O_RDWR | os.O_NONBLOCK)
    pending, output = None, b""
    try:
        while True:
            ready, _, _ = select.select([read_fd, fifo], [], [], 0.3)
            if read_fd in ready:
                try:
                    chunk = os.read(read_fd, 4096)
                except OSError:  # pty closes with EIO, not an empty read, on exit
                    break
                if not chunk:
                    break
                output += chunk
            elif fifo in ready:
                answer = os.read(fifo, _MAX_SECRET + 2)
                if pending:
                    text = answer.split(b"\n")[0]
                    os.write(write_fd, text + b"\n")
                    if capture is not None:
                        capture[pending["field"]] = text.decode(errors="replace")
                    state_store.clear("prompt")
                    pending, output = None, b""
            elif not ready and not pending and (found := prompt_re.search(output.decode(errors="replace"))):
                label = found["label"].strip()
                field = found.groupdict().get("field") or label.lower().replace(" ", "_")
                if auto_answer is not None:
                    os.write(write_fd, auto_answer.encode()[:_MAX_SECRET] + b"\n")
                    if capture is not None:
                        capture[field] = auto_answer
                    output, auto_answer = b"", None
                    continue
                pending = {"id": secrets.token_hex(4), "label": label, "field": field,
                           "secret": bool(_SECRET_WORDS.search(label))}
                state_store.write("prompt", pending)
    finally:
        os.close(fifo)
    return output
