#!/usr/bin/env python3
"""Verify the packet's exact file whitelist and SHA-256 manifest."""
import hashlib
from pathlib import Path

p = Path(__file__).resolve().parent
names = ("README.md", "records.json", "verify.py")
lines = (p / "MANIFEST.sha256").read_text().splitlines()
expected = [hashlib.sha256((p / n).read_bytes()).hexdigest() + "  " + n for n in names]
if lines != expected or {x.name for x in p.iterdir()} != set(names) | {"MANIFEST.sha256"}:
    raise SystemExit("Packet whitelist or manifest mismatch")
print("Packet whitelist and SHA-256 manifest OK")
