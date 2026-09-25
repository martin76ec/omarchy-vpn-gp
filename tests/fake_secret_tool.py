#!/usr/bin/env python3
"""Stand-in for secret-tool: a tiny mutable JSON "keyring" at
$FAKE_SECRET_STORE, so store/lookup/search/clear behave consistently
across the separate subprocess invocations one test makes."""

import json
import os
import sys
from pathlib import Path

db_path = Path(os.environ["FAKE_SECRET_STORE"])
db = json.loads(db_path.read_text()) if db_path.exists() else {}


def key(pairs: list[str]) -> str:
    return "|".join(f"{k}={v}" for k, v in zip(pairs[::2], pairs[1::2]))


match sys.argv[1:]:
    case ["store", "--label", _, *pairs]:
        db[key(pairs)] = sys.stdin.read()
        db_path.write_text(json.dumps(db))
    case ["lookup", *pairs]:
        value = db.get(key(pairs))
        sys.exit(1) if value is None else sys.stdout.write(value)
    case ["search", *pairs]:
        value = db.get(key(pairs))
        sys.exit(1) if value is None else print("secret = " + value)
    case ["clear", *pairs]:
        db.pop(key(pairs), None)
        db_path.write_text(json.dumps(db))
    case _:
        sys.exit(2)
