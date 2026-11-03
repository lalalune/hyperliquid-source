#!/usr/bin/env python3
"""Verify only the expected packet files against the manifest."""
import hashlib
from pathlib import Path

p = Path(__file__).resolve().parent
names = {"README.md", "records.json", "verify.py"}
lines = (p / "MANIFEST.sha256").read_text().splitlines()
seen = set()
for line in lines:
    h, sep, name = line.partition("  ")
    if sep != "  " or name not in names or name in seen or len(h) != 64:
        raise SystemExit("invalid manifest whitelist")
    if hashlib.sha256((p / name).read_bytes()).hexdigest() != h:
        raise SystemExit("packet hash mismatch: " + name)
    seen.add(name)
if seen != names or {x.name for x in p.iterdir()} != names | {"MANIFEST.sha256"}:
    raise SystemExit("packet file set changed")
print("Packet manifest and whitelist OK")
