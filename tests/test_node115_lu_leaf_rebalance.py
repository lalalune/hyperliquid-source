"""Unit tests for the RE-001-node115-lu-leaf-rebalance verifier."""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "tools"))
import node115_lu_leaf_rebalance as verifier  # noqa: E402

PACKET = os.path.join(ROOT, "research", "work-items",
                      "RE-001-node115-lu-leaf-rebalance")
BINARY = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")


def copy_binary_with_flip(va, xor=0xFF):
    tmp = tempfile.NamedTemporaryFile(delete=False)
    with open(BINARY, "rb") as src:
        data = bytearray(src.read())
    data[va - 0x1000] ^= xor
    tmp.write(data)
    tmp.close()
    return tmp.name


class LeafRebalanceTests(unittest.TestCase):
    def test_verify_passes(self):
        self.assertEqual(verifier.verify(ROOT, PACKET, BINARY), 0)

    def test_digest_mismatch_rejected(self):
        tmp = tempfile.NamedTemporaryFile(delete=False)
        with open(BINARY, "rb") as src:
            data = bytearray(src.read())
        data[0x1000] ^= 0xFF
        tmp.write(data)
        tmp.close()
        try:
            with self.assertRaises(AssertionError):
                verifier.verify(ROOT, PACKET, tmp.name)
        finally:
            os.unlink(tmp.name)

    def test_packet_tamper_rejected(self):
        tmpdir = tempfile.mkdtemp()
        try:
            pkt = os.path.join(tmpdir, "pkt")
            shutil.copytree(PACKET, pkt)
            hex_path = os.path.join(pkt, "fde4790.hex")
            text = open(hex_path).read().strip()
            flipped = ("0" if text[0] != "0" else "1") + text[1:]
            open(hex_path, "w").write(flipped + "\n")
            with self.assertRaises(AssertionError):
                verifier.verify(ROOT, pkt, BINARY)
        finally:
            shutil.rmtree(tmpdir)

    def test_corrupt_flag_store_rejected(self):
        tmp = copy_binary_with_flip(0x4D24EFA)
        try:
            with self.assertRaises(AssertionError):
                verifier.verify(ROOT, PACKET, tmp)
        finally:
            os.unlink(tmp)

    def test_corrupt_root_count_test_rejected(self):
        tmp = copy_binary_with_flip(0x4D24EEC)
        try:
            with self.assertRaises(AssertionError):
                verifier.verify(ROOT, PACKET, tmp)
        finally:
            os.unlink(tmp)

    def test_corrupt_underflow_gate_rejected(self):
        tmp = copy_binary_with_flip(0x4D2483E)
        try:
            with self.assertRaises(AssertionError):
                verifier.verify(ROOT, PACKET, tmp)
        finally:
            os.unlink(tmp)

    def test_objdump_counts_match_records(self):
        text = open(os.path.join(PACKET, "fde4790.objdump.txt")).read()
        instrs = [l for l in text.splitlines()
                  if re.match(r"\s+[0-9a-f]+:\t", l)]
        rec = json.load(open(os.path.join(PACKET, "records.json")))["leaf_op"]
        self.assertEqual(len(instrs), rec["total_instructions"])
        body = [l for l in instrs
                if int(l.split(":")[0].strip(), 16) < 0x4D24A47]
        self.assertEqual(len(body), rec["body_instructions"])
        self.assertEqual(len(instrs) - len(body), rec["tail_instructions"])
        nops = sum(1 for l in instrs if "\tnop" in l or " nop " in l)
        self.assertEqual(nops, rec["nops"])


if __name__ == "__main__":
    unittest.main()
