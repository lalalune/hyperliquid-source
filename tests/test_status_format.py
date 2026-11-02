"""Tests for the node #94 status formatter model (RE-001, 0x542f8a0).

End-to-end behavior tests (inputs through the model to observable output
strings) plus packet verification: records.json agreement with the model,
excerpt regeneration, byte-for-byte sampled instructions, MANIFEST hashes,
and corruption controls. Run with:
    python3 -m unittest tests.test_status_format -v
(pytest also works; pytest is not installed on this VM.)
"""
import hashlib
import json
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tools"))

from status_format import CODE_PREFIX, SUBCODE_NAME, format_status  # noqa: E402

PACKET = REPO / "research/work-items/RE-001-status-format-94"
BINARY = REPO / "work/hl-node-94.bin"
SHA256 = ("3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575"
          "eff1c0459f")


def file_offset(vaddr):
    return vaddr - 0x1000 if vaddr >= 0x1343C80 else vaddr


class TestFormatBehavior(unittest.TestCase):
    def test_ok_ignores_subcode_and_message(self):
        self.assertEqual(format_status(0, 0, None), "OK")
        self.assertEqual(format_status(0, 9, "ignored"), "OK")
        self.assertEqual(format_status(0, 15, ""), "OK")

    def test_every_code_prefix_with_message(self):
        for code, prefix in CODE_PREFIX.items():
            if code == 0:
                continue
            self.assertEqual(format_status(code, 0, "m"), prefix + "m")

    def test_every_code_prefix_null_message(self):
        for code, prefix in CODE_PREFIX.items():
            if code == 0:
                continue
            self.assertEqual(format_status(code, 0, None), prefix)

    def test_unknown_codes(self):
        self.assertEqual(format_status(16, 0, "m"), "Unknown code(16): m")
        self.assertEqual(format_status(255, 0, None), "Unknown code(255): ")
        self.assertEqual(format_status(200, 3, "m"),
                         "Unknown code(200): "
                         "Failed to acquire lock due to max_num_locks limit: m")

    def test_subcode_names_all(self):
        for sub in range(16):
            got = format_status(2, sub, "m")
            if sub == 0:
                self.assertEqual(got, "Corruption: m")
            else:
                self.assertEqual(got, "Corruption: " + SUBCODE_NAME[sub] + ": m")

    def test_subcode_null_message_has_no_separator(self):
        self.assertEqual(format_status(2, 5, None), "Corruption: Deadlock")
        self.assertEqual(format_status(1, 12, None), "NotFound:  (overwritten)")

    def test_replay_loop_case(self):
        # The pinned consumer: WAL replay loop, too-small record.
        self.assertEqual(format_status(2, 0, "log record too small"),
                         "Corruption: log record too small")

    def test_boundaries_rejected(self):
        with self.assertRaises(ValueError):
            format_status(256, 0, None)
        with self.assertRaises(ValueError):
            format_status(2, 16, None)
        with self.assertRaises(ValueError):
            format_status(2, -1, None)


class TestPacket(unittest.TestCase):
    def test_binary_digest(self):
        self.assertEqual(hashlib.sha256(BINARY.read_bytes()).hexdigest(), SHA256)

    def test_records_agree_with_model(self):
        records = json.loads((PACKET / "records.json").read_text())
        table = {e["code"]: e for e in records["code_table"]}
        self.assertEqual(len(table), 16)
        for code, prefix in CODE_PREFIX.items():
            self.assertEqual(table[code]["prefix"], prefix)
            self.assertEqual(table[code]["length"], len(prefix))
        subs = records["subcode_table"]["entries"]
        self.assertEqual(len(subs), 16)
        for entry in subs:
            self.assertEqual(entry["name"], SUBCODE_NAME[entry["subcode"]])

    def test_manifest(self):
        for line in (PACKET / "MANIFEST.sha256").read_text().splitlines():
            digest, name = line.split("  ", 1)
            self.assertEqual(
                hashlib.sha256((PACKET / name).read_bytes()).hexdigest(), digest)

    def test_excerpt_regeneration(self):
        fresh = subprocess.run(
            ["objdump", "-d", "--start-address=0x542f8a0",
             "--stop-address=0x542fe90", "work/hl-node-94.bin"],
            cwd=REPO, capture_output=True, text=True).stdout
        self.assertEqual(fresh, (PACKET / "window.txt").read_text())

    def test_sampled_instructions_byte_for_byte(self):
        data = BINARY.read_bytes()
        samples = {
            0x542F8A0: bytes.fromhex("f30f1efa"),
            0x542F8CC: bytes.fromhex("4180f90f"),
            0x542FA08: bytes.fromhex("488d15f16c3300"),
        }
        for addr, raw in samples.items():
            off = file_offset(addr)
            self.assertEqual(data[off:off + len(raw)], raw)

    def test_jump_table_arms(self):
        data = BINARY.read_bytes()
        records = json.loads((PACKET / "records.json").read_text())
        for i, arm in enumerate(records["jump_table"]["arms"]):
            off = struct.unpack_from("<i", data, file_offset(0x7FC298) + i * 4)[0]
            self.assertEqual(hex(0x7FC298 + off), arm)

    def test_corruption_controls(self):
        # (1) A corrupted window excerpt no longer matches a fresh dump.
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "window.txt"
            text = (PACKET / "window.txt").read_text()
            bad.write_text(text.replace("endbr64", "endbr63", 1))
            fresh = subprocess.run(
                ["objdump", "-d", "--start-address=0x542f8a0",
                 "--stop-address=0x542fe90", "work/hl-node-94.bin"],
                cwd=REPO, capture_output=True, text=True).stdout
            self.assertNotEqual(fresh, bad.read_text())
        # (2) A flipped prefix in records no longer matches the model table.
        records = json.loads((PACKET / "records.json").read_text())
        records["code_table"][2]["prefix"] = "Corruption! "
        table = {e["code"]: e for e in records["code_table"]}
        self.assertNotEqual(table[2]["prefix"], CODE_PREFIX[2])


if __name__ == "__main__":
    unittest.main()
