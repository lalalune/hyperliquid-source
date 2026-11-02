#!/usr/bin/env python3
"""Verify the fixed packet whitelist, manifest and byte-identical regeneration."""
from pathlib import Path
import sys

sys.dont_write_bytecode = True
PACKET = Path(__file__).resolve().parent
sys.path.insert(0, str(PACKET.parents[2] / "tools"))
import tuple_saturating_gate

if __name__ == "__main__":
    raise SystemExit(tuple_saturating_gate.main(["--check", str(PACKET), *sys.argv[1:]]))
