#!/usr/bin/env python3
"""Unit tests for the RE-001-node115-lu-flag-completion packet.

Mirrors the packet's own verifier: a passing run, tamper controls on
packet copies (no binary copies: the real binary is read, only small
packet files are copied to a temp dir), and an objdump-count check.
"""

import json
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PACKET = ROOT / "research" / "work-items" / "RE-001-node115-lu-flag-completion"
BINARY = ROOT / "artifacts" / "node" / "115" / "hl-node"
VERIFIER = ROOT / "tools" / "node115_lu_flag_completion.py"

sys.path.insert(0, str(ROOT / "tools"))
import node115_lu_flag_completion as verifier


def temp_packet_copy():
    tmp = Path(tempfile.mkdtemp(prefix="flag_completion_"))
    dst = tmp / "packet"
    shutil.copytree(PACKET, dst)
    return tmp, dst


class FlagCompletionTests(unittest.TestCase):
    def test_verify_passes(self):
        result = subprocess.run([sys.executable, str(VERIFIER)],
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        summary = json.loads(result.stdout)
        self.assertTrue(summary["ok"])
        self.assertEqual(summary["checks"]["spot_checks"], 12)
        self.assertEqual(summary["checks"]["flag_e8_callers"], 2)
        self.assertEqual(summary["checks"]["completion_e8_callers"], 1)

    def test_digest_mismatch_rejected(self):
        tmp, dst = temp_packet_copy()
        try:
            records = json.loads((dst / "records.json").read_text())
            records["binary"]["sha256"] = "0" * 64
            (dst / "records.json").write_text(json.dumps(records))
            result = verifier.verify(BINARY, dst)
            self.assertFalse(result["ok"])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_packet_tamper_rejected(self):
        tmp, dst = temp_packet_copy()
        try:
            hexpath = dst / "fdeccf20.hex"
            text = hexpath.read_text().strip()
            flipped = ("0" if text[0] != "0" else "1") + text[1:]
            hexpath.write_text(flipped + "\n")
            result = verifier.verify(BINARY, dst)
            self.assertFalse(result["ok"])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_corrupt_free_size_rejected(self):
        tmp, dst = temp_packet_copy()
        try:
            hexpath = dst / "fde86a0.hex"
            raw = bytes.fromhex(hexpath.read_text().strip())
            # mov esi,0x148 at 0x4da8726: FDE offset 0x86.
            self.assertEqual(raw[0x86:0x8B], bytes.fromhex("be48010000"))
            raw = bytearray(raw)
            raw[0x87] = 0x49  # 0x148 -> 0x149
            hexpath.write_text(bytes(raw).hex() + "\n")
            result = verifier.verify(BINARY, dst)
            self.assertFalse(result["ok"])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_corrupt_threshold_rejected(self):
        tmp, dst = temp_packet_copy()
        try:
            hexpath = dst / "fdeccf20.hex"
            raw = bytes.fromhex(hexpath.read_text().strip())
            # cmp [r14+0x18],0x3f at 0x4dcd07a: FDE offset 0x15a.
            self.assertEqual(raw[0x15A:0x15F], bytes.fromhex("49837e183f"))
            raw = bytearray(raw)
            raw[0x15E] = 0x40  # 0x3f -> 0x40
            hexpath.write_text(bytes(raw).hex() + "\n")
            result = verifier.verify(BINARY, dst)
            self.assertFalse(result["ok"])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_corrupt_flag_store_rejected(self):
        tmp, dst = temp_packet_copy()
        try:
            hexpath = dst / "fdeccf20.hex"
            raw = bytes.fromhex(hexpath.read_text().strip())
            # mov [rbx],rdi at 0x4dcd2a9: FDE offset 0x389.
            self.assertEqual(raw[0x389:0x38C], bytes.fromhex("48893b"))
            raw = bytearray(raw)
            raw[0x38B] = 0x33  # rdi -> rsi
            hexpath.write_text(bytes(raw).hex() + "\n")
            result = verifier.verify(BINARY, dst)
            self.assertFalse(result["ok"])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_objdump_counts_match_records(self):
        records = json.loads((PACKET / "records.json").read_text())
        for hexfile, objfile, rec in (
            ("fdeccf20.hex", "fdeccf20.objdump.txt",
             records["flag_helper"]),
            ("fde86a0.hex", "fde86a0.objdump.txt",
             records["completion_helper"]),
        ):
            lines = (PACKET / objfile).read_text().splitlines()
            count = sum(1 for ln in lines
                        if re.match(r"^\s+[0-9a-f]+:", ln))
            self.assertEqual(count, rec["total_instructions"],
                             f"{objfile} count {count}")
            # Instruction lines must all fall inside the FDE range.
            addrs = [int(m.group(1), 16) for ln in lines
                     if (m := re.match(r"^\s+([0-9a-f]+):", ln))]
            self.assertTrue(addrs)
            self.assertEqual(min(addrs), int(rec["start"], 16))
            self.assertLess(max(addrs), int(rec["end"], 16))


if __name__ == "__main__":
    unittest.main()
