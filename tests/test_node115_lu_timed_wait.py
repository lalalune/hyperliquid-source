#!/usr/bin/env python3
"""Unit tests for the RE-001-node115-lu-timed-wait packet.

Regeneration comparison is byte-exact against the pinned body hex;
corruption controls flip one pinned fact each and require the verifier
to reject it. Mirrors the conventions of the earlier node-115 lu
packets (regeneration + corruption controls, no node execution).
"""
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research" / "work-items" / "RE-001-node115-lu-timed-wait"
NODE = ROOT / "artifacts" / "node" / "115" / "hl-node"
TOOL = ROOT / "tools" / "node115_lu_timed_wait.py"

BODY_LO, BODY_HI = 0x5BB2440, 0x5BB35ED


def run_verifier(cwd, tool=TOOL):
    return subprocess.run([sys.executable, str(tool)], cwd=cwd,
                          capture_output=True, text=True)


def corrupt_and_run(name, mutate):
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        (td / "research").mkdir()
        (td / "tools").mkdir()
        (td / "artifacts" / "node" / "115").mkdir(parents=True)
        import shutil
        shutil.copytree(PACKET, td / "research" / PACKET.name)
        shutil.copy(TOOL, td / "tools" / TOOL.name)
        shutil.copy(NODE, td / "artifacts" / "node" / "115" / "hl-node")
        mutate(td / "research" / PACKET.name)
        return run_verifier(td, td / "tools" / TOOL.name)


class TestTimedWait(unittest.TestCase):
    def test_verifier_passes(self):
        r = run_verifier(ROOT)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_body_hex_matches_binary(self):
        data = NODE.read_bytes()
        body = data[BODY_LO - 0x1000:BODY_HI - 0x1000]
        pinned = bytes.fromhex((PACKET / "fde2440.hex").read_text().strip())
        self.assertEqual(pinned, body)
        self.assertEqual(len(body), BODY_HI - BODY_LO)

    def test_single_ret_inside_fde(self):
        pinned = bytes.fromhex((PACKET / "fde2440.hex").read_text().strip())
        self.assertEqual(pinned[0x1046], 0xC3)
        # pop rbp immediately before ret (0x5bb3485 -> 0x5bb3486).
        self.assertEqual(pinned[0x1045], 0x5D)

    def test_corrupt_body_hex_rejected(self):
        def mutate(p):
            hx = (p / "fde2440.hex").read_text().strip()
            bad = ("00" if hx[:2] != "00" else "ff") + hx[2:]
            (p / "fde2440.hex").write_text(bad + "\n")
        r = corrupt_and_run("body", mutate)
        self.assertNotEqual(r.returncode, 0)

    def test_corrupt_futex_nr_rejected(self):
        def mutate(p):
            hx = (p / "fde2440.hex").read_text().strip()
            off = (0x5BB25BC - BODY_LO) * 2
            self.assertEqual(hx[off:off + 10], "bfca000000")
            (p / "fde2440.hex").write_text(hx[:off] + "bfcb000000" + hx[off + 10:] + "\n")
        r = corrupt_and_run("futex", mutate)
        self.assertNotEqual(r.returncode, 0)

    def test_corrupt_xorshift_shift_rejected(self):
        def mutate(p):
            hx = (p / "fde2440.hex").read_text().strip()
            off = (0x5BB317B - BODY_LO) * 2
            self.assertEqual(hx[off:off + 6], "c1e60d")
            (p / "fde2440.hex").write_text(hx[:off] + "c1e60e" + hx[off + 6:] + "\n")
        r = corrupt_and_run("shift", mutate)
        self.assertNotEqual(r.returncode, 0)

    def test_corrupt_records_byte_count_rejected(self):
        def mutate(p):
            rec = json.loads((p / "records.json").read_text())
            rec["bodies"]["timed_wait"]["bytes"] += 1
            (p / "records.json").write_text(json.dumps(rec))
        r = corrupt_and_run("records", mutate)
        self.assertNotEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main()
