"""Unit tests for RE-001-node115-lu-resolver.

Regeneration-vs-packet agreement plus corruption controls: the packet
hex must match the binary FDE bytes, the verifier must pass on the
pristine packet, and single-byte corruptions of the FDE, of the ret
bytes, of the objdump counts, and of the records must be rejected.
Instruction counts are strict mnemonic-line counts (address + byte
field + tab + mnemonic); objdump byte-continuation lines excluded.
"""
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET = os.path.join(ROOT, "research", "work-items",
                      "RE-001-node115-lu-resolver")
BINARY = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")
VERIFIER = os.path.join(ROOT, "tools", "node115_lu_resolver.py")

START = 0x4D35B60
END = 0x4D35DE4
FIRST_RET_OFF = 0x4D35D68 - START
SECOND_RET_OFF = 0x4D35DE3 - START

INSTR_RE = re.compile(r"\s+[0-9a-f]+:\t[0-9a-f ]+\t\S")


def run_verifier(packet_dir):
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    import node115_lu_resolver as v
    v.verify(ROOT, packet_dir, BINARY)


class ResolverTests(unittest.TestCase):
    def test_verify_passes(self):
        run_verifier(PACKET)

    def test_packet_tamper_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            copy = os.path.join(tmp, "packet")
            shutil.copytree(PACKET, copy)
            p = os.path.join(copy, "resolver.hex")
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
            rec["resolver"]["full_sha256"] = "0" * 64
            json.dump(rec, open(os.path.join(copy, "records.json"), "w"))
            with self.assertRaises(AssertionError):
                run_verifier(copy)

    def test_objdump_counts_match_records(self):
        rec = json.load(open(os.path.join(PACKET, "records.json")))
        lines = open(os.path.join(PACKET, "resolver.objdump.txt")).read().splitlines()
        instrs = [l for l in lines if INSTR_RE.match(l)]
        self.assertEqual(len(instrs), rec["resolver"]["total_instructions"])
        body = [l for l in instrs
                if int(l.split(":")[0].strip(), 16) <= 0x4D35D68]
        tail = [l for l in instrs
                if int(l.split(":")[0].strip(), 16) > 0x4D35D68]
        self.assertEqual(len(body), rec["resolver"]["body_instructions"])
        self.assertEqual(len(tail), rec["resolver"]["tail_instructions"])
        nops = [l for l in instrs if re.search(r"\bnop\b", l.split("\t")[-1])]
        self.assertEqual(len(nops), rec["resolver"]["nops"])

    def test_corrupt_ret_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            copy = os.path.join(tmp, "packet")
            shutil.copytree(PACKET, copy)
            p = os.path.join(copy, "resolver.hex")
            raw = bytes.fromhex(open(p).read().strip())
            for off in (FIRST_RET_OFF, SECOND_RET_OFF):
                bad = bytearray(raw)
                bad[off] ^= 0xFF
                open(p, "w").write(bytes(bad).hex() + "\n")
                with self.assertRaises(AssertionError):
                    run_verifier(copy)
                open(p, "w").write(raw.hex() + "\n")

    def test_objdump_range_spans_fde(self):
        lines = open(os.path.join(PACKET, "resolver.objdump.txt")).read().splitlines()
        addrs = [int(l.split(":")[0].strip(), 16) for l in lines
                 if re.match(r"^\s+[0-9a-f]+:\t", l)]
        self.assertEqual(min(addrs), START)
        self.assertEqual(max(addrs), 0x4D35DE3)
        self.assertLess(max(addrs), END)

    def test_manifest_agreement(self):
        manifest = open(os.path.join(PACKET, "MANIFEST.sha256")).read().splitlines()
        self.assertEqual(len(manifest), 7)
        for line in manifest:
            digest, path = line.split(None, 1)
            full = os.path.normpath(os.path.join(PACKET, path))
            self.assertEqual(hashlib.sha256(open(full, "rb").read()).hexdigest(),
                             digest, f"MANIFEST mismatch for {path}")


if __name__ == "__main__":
    unittest.main()
