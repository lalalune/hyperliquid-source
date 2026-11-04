#!/usr/bin/env python3
"""Verify the packet whitelist, hashes and independent regeneration."""
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
NAMES = ("README.md", "records.json", "verify.py")
if {p.name for p in HERE.iterdir()} != set(NAMES) | {"MANIFEST.sha256"}:
    raise SystemExit("Unexpected packet contents")
manifest = "".join(hashlib.sha256((HERE / n).read_bytes()).hexdigest() + "  " + n + "\n" for n in NAMES)
if (HERE / "MANIFEST.sha256").read_text() != manifest:
    raise SystemExit("Manifest mismatch")
with tempfile.TemporaryDirectory() as tmp:
    subprocess.run([sys.executable, str(ROOT / "tools/node115_limb_subtract.py"), "--out", tmp], check=True)
    for name in (*NAMES, "MANIFEST.sha256"):
        if (HERE / name).read_bytes() != (Path(tmp) / name).read_bytes():
            raise SystemExit("Regenerated packet mismatch: " + name)
print("Packet whitelist, hashes and regeneration verified")
