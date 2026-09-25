#!/usr/bin/env python3
"""Stand-in for `openconnect --authenticate`, driven by the same JSON
fixture as fake_nmcli.py, under key "auth". Talks over a real pty (like the
production code), so plain input()/print() without manual echo control is
enough for the test's purposes."""

import json
import os
import signal
import sys
import time
from pathlib import Path

state = json.loads(Path(os.environ["FAKE_NM_STATE"]).read_text())
with open(os.environ["FAKE_NM_LOG"], "a") as log:
    log.write(json.dumps(["openconnect", *sys.argv[1:]]) + "\n")


def prompt(label: str) -> str:
    sys.stdout.write(f"{label}: ")
    sys.stdout.flush()
    return sys.stdin.readline().rstrip("\n")


auth = state.get("auth", {"mode": "ok"})
match auth.get("mode"):
    case "fail":
        time.sleep(auth.get("delay", 0))
        print(auth.get("error", "Failed to obtain WebVPN cookie."), file=sys.stderr)
        sys.exit(1)
    case "prompt":
        print("Enter login credentials")
        # Matches real openconnect: -u/--user supplies the username up
        # front, so only "Password: " is asked — this is exactly what the
        # saved-credentials path (core/nm_secrets.py's authenticate_saved_argv)
        # relies on to answer automatically without a human ever seeing it.
        if "--user" in sys.argv[1:]:
            username = sys.argv[sys.argv.index("--user") + 1]
        else:
            username = prompt("Username")
        # Real openconnect: --passwd-on-stdin reads the password silently,
        # printing no prompt text at all — confirmed live, this is exactly
        # what broke core/activation.py's prompt-detection auto-answer (it
        # only ever writes after seeing prompt text, so nothing is ever
        # sent and openconnect hangs forever). The alarm turns that hang
        # into a fast, clear test failure instead of a wedged test run, in
        # case this flag ever comes back to the saved-credentials argv.
        if "--passwd-on-stdin" in sys.argv[1:]:
            signal.alarm(3)
            password = sys.stdin.readline().rstrip("\n")
            signal.alarm(0)
        else:
            password = prompt("Password")
        if [username, password] != [auth["user"], auth["password"]]:
            print("Login failed.", file=sys.stderr)
            sys.exit(1)

for key in ("COOKIE", "HOST", "CONNECT_URL", "FINGERPRINT", "RESOLVE"):
    if key in auth:
        print(f"{key}='{auth[key]}'")
