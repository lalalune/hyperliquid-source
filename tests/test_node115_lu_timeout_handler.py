#!/usr/bin/env python3
"""Unit tests for the node #115 lu timeout-handler packet (RE-001)."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools" / "node115_lu_timeout_handler.py"
PACKET = ROOT / "research" / "work-items" / "RE-001-node115-lu-timeout-handler"


def run_tool(hex_path, records_path):
    return subprocess.run(
        [sys.executable, str(TOOL), "--hex", str(hex_path), "--records", str(records_path)],
        capture_output=True, text=True)


class TestTimeoutHandler(unittest.TestCase):
    def test_verifier_passes(self):
        proc = run_tool(PACKET / "handler.hex", PACKET / "records.json")
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_handler_hex_matches_binary(self):
        binary = (ROOT / "artifacts" / "node" / "115" / "hl-node").read_bytes()
        body = binary[0x5BB3CA0 - 0x1000:0x5BB3E41 - 0x1000]
        self.assertEqual(bytes.fromhex((PACKET / "handler.hex").read_text().strip()), body)

    def test_single_ret_inside_fde(self):
        out = subprocess.run(
            ["objdump", "-d", "-M", "intel", "--start-address=0x5bb3ca0",
             "--stop-address=0x5bb3e41",
             str(ROOT / "artifacts" / "node" / "115" / "hl-node")],
            capture_output=True, text=True, check=True).stdout
        rets = [ln for ln in out.splitlines() if ln.strip().endswith("\tret")]
        self.assertEqual(len(rets), 1)
        self.assertIn("5bb3e23", rets[0])

    def _corrupt_hex(self, tmp, offset, xor=0xFF):
        hex_bytes = bytearray(bytes.fromhex((PACKET / "handler.hex").read_text().strip()))
        hex_bytes[offset] ^= xor
        hex_path = Path(tmp) / "handler.hex"
        hex_path.write_text(hex_bytes.hex() + "\n")
        records_path = Path(tmp) / "records.json"
        records_path.write_text((PACKET / "records.json").read_text())
        return hex_path, records_path

    def test_corrupt_handler_hex_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            hex_path, records_path = self._corrupt_hex(tmp, 0)
            self.assertNotEqual(run_tool(hex_path, records_path).returncode, 0)

    def test_corrupt_claim_site_rejected(self):
        # File offset of the claim cmpxchg (VA 0x5bb3d5c) within the body.
        with tempfile.TemporaryDirectory() as tmp:
            hex_path, records_path = self._corrupt_hex(tmp, 0x5BB3D5C - 0x5BB3CA0)
            self.assertNotEqual(run_tool(hex_path, records_path).returncode, 0)

    def test_corrupt_golden_ratio_rejected(self):
        # File offset of the golden-ratio immediate (VA 0x5bb3cbe) within the body.
        with tempfile.TemporaryDirectory() as tmp:
            hex_path, records_path = self._corrupt_hex(tmp, 0x5BB3CBE - 0x5BB3CA0)
            self.assertNotEqual(run_tool(hex_path, records_path).returncode, 0)

    def test_corrupt_records_byte_count_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            records = json.loads((PACKET / "records.json").read_text())
            records["bodies"]["handler"]["bytes"] = 418
            records_path = Path(tmp) / "records.json"
            records_path.write_text(json.dumps(records))
            hex_path = Path(tmp) / "handler.hex"
            hex_path.write_text((PACKET / "handler.hex").read_text())
            self.assertNotEqual(run_tool(hex_path, records_path).returncode, 0)


if __name__ == "__main__":
    unittest.main()
