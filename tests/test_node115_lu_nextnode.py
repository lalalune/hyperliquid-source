"""Unit tests for the RE-001-node115-lu-nextnode packet (#214).

Regeneration checks + a tamper control, as stdlib unittest TestCases (the
repo runner is `tools/run_tests.py`, i.e. `python -m unittest discover`).
Static only: reads the node binary, never executes it.
"""

import hashlib
import json
import struct
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
BIN = REPO / "artifacts" / "node" / "115" / "hl-node"
PACKET = REPO / "research" / "work-items" / "RE-001-node115-lu-nextnode"
TOOL = REPO / "tools" / "node115_lu_nextnode.py"

EXCERPTS = [
    ("thunk", 0x63AE260, 0x63AE278, 7),
    ("head", 0x63ADF71, 0x63ADF9D, 9),
    ("valid", 0x63ADFED, 0x63AE014, 11),
    ("kind", 0x63AE014, 0x63AE040, 11),
    ("tail", 0x63AE088, 0x63AE0CF, 18),
]

CENSUS_CALLS = [
    (0x63B1BAD, 0x63AE260),
    (0x63B1C0A, 0x63AE260),
    (0x63B1C75, 0x63AE260),
    (0x63B479D, 0x63AE280),
    (0x63AE26E, 0x63ADF40),
    (0x63AE290, 0x63ADF40),
]


class TestLuNextnode(unittest.TestCase):
    def test_verifier_passes(self):
        r = subprocess.run([sys.executable, str(TOOL)], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("all checks passed", r.stdout)

    def test_exhibit_bytes_match_binary(self):
        data = BIN.read_bytes()
        for name, start, end, _strict in EXCERPTS:
            claimed = bytes.fromhex("".join((PACKET / f"{name}.hex").read_text().split()))
            self.assertEqual(claimed, data[start - 0x1000:end - 0x1000], name)

    def test_strict_counts_match(self):
        data = BIN.read_bytes()
        for name, start, end, want in EXCERPTS:
            lines = (PACKET / f"{name}.objdump.txt").read_text().splitlines()
            strict = sum(1 for ln in lines if ln.count("\t") >= 2)
            self.assertEqual(strict, want, name)
            # every strict line's bytes must reappear at its address
            for ln in lines:
                if ln.count("\t") < 2:
                    continue
                addr_s, byts, _mnem = ln.split("\t", 2)
                addr = int(addr_s.rstrip(":"), 16)
                raw = bytes(int(b, 16) for b in byts.split())
                self.assertEqual(data[addr - 0x1000:addr - 0x1000 + len(raw)], raw, (name, ln))

    def test_census_call_targets(self):
        data = BIN.read_bytes()
        for site, want in CENSUS_CALLS:
            b = data[site - 0x1000:site - 0x1000 + 5]
            self.assertEqual(b[0], 0xE8, hex(site))
            tgt = site + 5 + struct.unpack("<i", b[1:5])[0]
            self.assertEqual(tgt, want, (hex(site), hex(tgt), hex(want)))

    def test_key_bytes_match(self):
        data = BIN.read_bytes()
        checks = [
            (0x63AE288, "41b901000000"),
            (0x63AE28E, "6a01"),
            (0x63ADF9D, "4885db"),
            (0x63AE070, "a802"),
            (0x63AE0D3, "4584d2"),
            (0x63AE097, "4c8d358a1b1500"),
        ]
        for va, hx in checks:
            raw = bytes.fromhex(hx)
            self.assertEqual(data[va - 0x1000:va - 0x1000 + len(raw)].hex(), hx, hex(va))

    def test_tamper_control(self):
        data = BIN.read_bytes()
        claimed = bytes.fromhex("".join((PACKET / "thunk.hex").read_text().split()))
        tampered = bytearray(claimed)
        tampered[0] ^= 0xFF
        self.assertNotEqual(bytes(tampered), data[0x63AE260 - 0x1000:0x63AE278 - 0x1000])
        self.assertEqual(claimed, data[0x63AE260 - 0x1000:0x63AE278 - 0x1000])

    def test_manifest_covers_packet(self):
        entries = [ln.split() for ln in (PACKET / "MANIFEST.sha256").read_text().splitlines() if ln.strip()]
        listed = sorted(rel for _sha, rel in entries)
        actual = sorted(
            [str(p.relative_to(PACKET)) for p in PACKET.iterdir()
             if p.is_file() and p.name != "MANIFEST.sha256"]
            + ["../../../tools/node115_lu_nextnode.py",
               "../../../tests/test_node115_lu_nextnode.py"]
        )
        self.assertEqual(listed, actual)
        for sha, rel in entries:
            got = hashlib.sha256((PACKET / rel).read_bytes()).hexdigest()
            self.assertEqual(got, sha, rel)

    def test_records_agree(self):
        rec = json.loads((PACKET / "records.json").read_text())
        self.assertEqual(rec["packet"], 214)
        self.assertEqual(rec["thunk_fde"], ["0x63ae260", "0x63ae278", 24])
        self.assertEqual(rec["worker_fde"], ["0x63adf40", "0x63ae252", 786])
        self.assertEqual(rec["exhibit_bytes"], sum(end - start for _n, start, end, _s in EXCERPTS))
        self.assertEqual(rec["exhibit_strict"], sum(s for _n, _a, _b, s in EXCERPTS))
        self.assertEqual(rec["census_e8"], {"thunk": 3, "thunk_b": 1, "worker": 2})
        self.assertEqual(rec["census_e9"], 0)
        self.assertEqual(rec["census_got"], 0)


if __name__ == "__main__":
    unittest.main()
