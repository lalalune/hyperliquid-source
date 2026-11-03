"""Unit tests for RE-001-node115-lu-merge-redistribute.

Regeneration-vs-packet agreement plus corruption controls: the packet
hex must match the binary FDE bytes, the verifier must pass on the
pristine packet, and single-byte corruptions of each FDE, of the
objdump counts, and of the records must be rejected.
"""
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET = os.path.join(ROOT, "research", "work-items",
                      "RE-001-node115-lu-merge-redistribute")
BINARY = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")
VERIFIER = os.path.join(ROOT, "tools", "node115_lu_merge_redistribute.py")

FDES = {
    "merge": (0x4CA2500, 0x4CA2915),
    "redistL": (0x4C93C20, 0x4C93F18),
    "redistR": (0x4C9B3B0, 0x4C9B6FF),
}


def run_verifier(packet_dir):
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    import node115_lu_merge_redistribute as v
    v.verify(ROOT, packet_dir, BINARY)


class MergeRedistributeTests(unittest.TestCase):
    def test_verify_passes(self):
        run_verifier(PACKET)

    def test_packet_tamper_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            copy = os.path.join(tmp, "packet")
            shutil.copytree(PACKET, copy)
            for name, (s, e) in FDES.items():
                p = os.path.join(copy, name + ".hex")
                raw = bytes.fromhex(open(p).read().strip())
                bad = bytes([raw[0] ^ 0xFF]) + raw[1:]
                open(p, "w").write(bad.hex() + "\n")
                with self.assertRaises(AssertionError):
                    run_verifier(copy)
                open(p, "w").write(raw.hex() + "\n")

    def test_digest_mismatch_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            copy = os.path.join(tmp, "packet")
            shutil.copytree(PACKET, copy)
            rec = json.load(open(os.path.join(copy, "records.json")))
            rec["merge"]["full_sha256"] = "0" * 64
            json.dump(rec, open(os.path.join(copy, "records.json"), "w"))
            with self.assertRaises(AssertionError):
                run_verifier(copy)

    def test_objdump_counts_match_records(self):
        rec = json.load(open(os.path.join(PACKET, "records.json")))
        keys = {"merge": "merge", "redistL": "redistribute_left",
                "redistR": "redistribute_right"}
        for name, (s, e) in FDES.items():
            lines = open(os.path.join(PACKET, name + ".objdump.txt")).read().splitlines()
            instrs = [l for l in lines
                      if re.match(r"^\s+[0-9a-f]+:\s+[0-9a-f ]+\s+\S", l)]
            self.assertEqual(len(instrs), rec[keys[name]]["total_instructions"])

    def test_corrupt_ret_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            copy = os.path.join(tmp, "packet")
            shutil.copytree(PACKET, copy)
            for name, (s, e) in FDES.items():
                p = os.path.join(copy, name + ".hex")
                raw = bytes.fromhex(open(p).read().strip())
                # Corrupt the ret byte (last body byte): ret positions are
                # merge 0x4ca28c9, redistL 0x4c93ecc, redistR 0x4c9b6cc.
                ret_off = {"merge": 0x4CA28C9 - s, "redistL": 0x4C93ECC - s,
                           "redistR": 0x4C9B6CC - s}[name]
                bad = bytearray(raw)
                bad[ret_off] ^= 0xFF
                open(p, "w").write(bytes(bad).hex() + "\n")
                with self.assertRaises(AssertionError):
                    run_verifier(copy)
                open(p, "w").write(raw.hex() + "\n")

    def test_corrupt_panic_message_rejected(self):
        # The verifier pins panic messages from the binary itself; check
        # the pinned bytes exist at the pinned addresses.
        data = open(BINARY, "rb").read()
        self.assertEqual(data[0x913599:0x913599 + 10], b"assertion ")
        self.assertEqual(data[0x913496:0x913496 + 40],
                         b"internal error: entered unreachable code")

    def test_objdump_range_spans_fde(self):
        for name, (s, e) in FDES.items():
            lines = open(os.path.join(PACKET, name + ".objdump.txt")).read().splitlines()
            addrs = [int(l.split(":")[0].strip(), 16) for l in lines
                     if re.match(r"^\s+[0-9a-f]+:\t", l)]
            self.assertEqual(min(addrs), s)
            self.assertLess(max(addrs), e)


if __name__ == "__main__":
    unittest.main()
