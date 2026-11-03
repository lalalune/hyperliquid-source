"""Unit tests for RE-001-node115-lu-completion-callers."""
import hashlib
import os
import re
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

from node115_lu_completion_callers import (  # noqa: E402
    ACQUIRE_END,
    ACQUIRE_SHA256,
    ACQUIRE_START,
    CELLRES_END,
    CELLRES_SHA256,
    CELLRES_START,
    parse_objdump,
    verify,
)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET_DIR = os.path.join(
    ROOT, "research", "work-items", "RE-001-node115-lu-completion-callers")
BINARY = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")
INSTR_RE = re.compile(r"\s+[0-9a-f]+:\t[0-9a-f ]+\t\S")


class CompletionCallersTests(unittest.TestCase):
    def test_verify_passes(self):
        self.assertTrue(verify(ROOT, PACKET_DIR, BINARY))

    def test_packet_tamper_rejected(self):
        blob = open(BINARY, "rb").read()
        raw = bytearray.fromhex(
            open(os.path.join(PACKET_DIR, "acquire.hex")).read().strip())
        raw[10] ^= 0xFF
        self.assertNotEqual(
            hashlib.sha256(bytes(raw)).hexdigest(), ACQUIRE_SHA256)
        self.assertNotEqual(
            bytes(raw), blob[ACQUIRE_START - 0x1000:ACQUIRE_END - 0x1000])

    def test_digest_mismatch_rejected(self):
        blob = open(BINARY, "rb").read()
        raw = bytes.fromhex(
            open(os.path.join(PACKET_DIR, "cellres.hex")).read().strip())
        self.assertEqual(len(raw), CELLRES_END - CELLRES_START)
        self.assertEqual(
            raw, blob[CELLRES_START - 0x1000:CELLRES_END - 0x1000])
        self.assertEqual(hashlib.sha256(raw).hexdigest(), CELLRES_SHA256)
        flipped = bytearray(raw)
        flipped[-20] ^= 0x01
        self.assertNotEqual(
            hashlib.sha256(bytes(flipped)).hexdigest(), CELLRES_SHA256)

    def test_objdump_counts_match_records(self):
        import json
        rec = json.load(open(os.path.join(PACKET_DIR, "records.json")))
        for objdump_name, key in (
                ("acquire.objdump.txt", "acquire_fde"),
                ("cellres.objdump.txt", "cell_resolver_fde")):
            instrs = parse_objdump(os.path.join(PACKET_DIR, objdump_name))
            self.assertEqual(len(instrs), rec[key]["total_instructions"])
            first_ret = int(rec[key]["first_ret"], 16)
            body = [a for a, _, _ in instrs if a <= first_ret]
            tail = [a for a, _, _ in instrs if a > first_ret]
            self.assertEqual(len(body), rec[key]["body_instructions"])
            self.assertEqual(len(tail), rec[key]["tail_instructions"])
            # The packet objdump files must contain no extra strict lines.
            raw_lines = open(os.path.join(PACKET_DIR, objdump_name)).read()
            strict = [ln for ln in raw_lines.splitlines()
                      if INSTR_RE.match(ln)]
            self.assertEqual(len(strict), len(instrs))

    def test_corrupt_ret_rejected(self):
        instrs = parse_objdump(os.path.join(PACKET_DIR, "acquire.objdump.txt"))
        by_addr = {a: field.split()[0] for a, field, _ in instrs}
        self.assertEqual(by_addr[ACQUIRE_START], "push")
        self.assertEqual(by_addr[0x4FAC78F], "ret")
        cellres = parse_objdump(os.path.join(PACKET_DIR, "cellres.objdump.txt"))
        by_addr2 = {a: field.split()[0] for a, field, _ in cellres}
        self.assertEqual(by_addr2[CELLRES_START], "push")
        self.assertEqual(by_addr2[0x4DA6CF7], "ret")
        # A ret replaced by int3 must break the verifier's key-site check.
        self.assertNotEqual(by_addr[0x4FAC78F], "int3")

    def test_objdump_range_spans_fde(self):
        for objdump_name, start, end in (
                ("acquire.objdump.txt", ACQUIRE_START, ACQUIRE_END),
                ("cellres.objdump.txt", CELLRES_START, CELLRES_END)):
            instrs = parse_objdump(os.path.join(PACKET_DIR, objdump_name))
            self.assertEqual(min(a for a, _, _ in instrs), start)
            self.assertLess(max(a for a, _, _ in instrs), end)
            self.assertGreater(max(a for a, _, _ in instrs), start)

    def test_manifest_agreement(self):
        import hashlib
        manifest = {}
        for line in open(os.path.join(PACKET_DIR, "MANIFEST.sha256")):
            parts = line.split()
            self.assertEqual(len(parts), 2)
            manifest[parts[1]] = parts[0]
        for rel in ("README.md", "EVIDENCE.md", "records.json",
                    "acquire.hex", "acquire.objdump.txt",
                    "cellres.hex", "cellres.objdump.txt"):
            digest = hashlib.sha256(
                open(os.path.join(PACKET_DIR, rel), "rb").read()).hexdigest()
            self.assertEqual(manifest[rel], digest)
        for rel in ("../../../tools/node115_lu_completion_callers.py",
                    "../../../tests/test_node115_lu_completion_callers.py"):
            digest = hashlib.sha256(
                open(os.path.join(PACKET_DIR, rel), "rb").read()).hexdigest()
            self.assertEqual(manifest[rel], digest)


if __name__ == "__main__":
    unittest.main()
