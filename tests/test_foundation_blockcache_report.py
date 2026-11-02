"""Tests for the node #94 BlockCache report formatter (0x514f770)."""

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import foundation_blockcache_report as subject

REPO = Path(__file__).resolve().parents[1]
PACKET = REPO / "research" / "work-items" / "RE-001-blockcache-report-94"
BINARY = REPO / "work" / "hl-node-94.bin"

SENTINEL = "sentinel-cell"


def node(slot, value):
    return {"slot": slot, "call": lambda: value}


def fixture():
    return {
        "identity": "cache-A",
        "capacity": 2048,
        "usage": 1536,
        "table_size": 42,
        "occupancy": 7,
        "counts": [5, 0, 2] + [0] * 11,
        "values": [2048, 999, 1024] + [0] * 11,
        "collections": 3,
        "last_copies": 9,
        "clock_value": 1000,
        "commit": 5000,
    }


NAMES = ["alpha", "beta", "gamma"] + ["e%d" % i for i in range(3, 14)]


class AccessorTests(unittest.TestCase):
    def test_positive_difference(self):
        self.assertEqual(subject.saturating_window(5000, 1000), 4000)

    def test_negative_difference_saturates(self):
        self.assertEqual(subject.saturating_window(1000, 5000), 0)

    def test_equal_values(self):
        self.assertEqual(subject.saturating_window(700, 700), 0)


class HelperTests(unittest.TestCase):
    def test_zero(self):
        self.assertEqual(subject.format_scaled(0), "0.00 KB")

    def test_below_one_kb_still_kb(self):
        self.assertEqual(subject.format_scaled(1023), "1.00 KB")

    def test_kb_boundary(self):
        self.assertEqual(subject.format_scaled(1048575), "1024.00 KB")
        self.assertEqual(subject.format_scaled(1048576), "1.00 MB")

    def test_tb_terminal(self):
        self.assertEqual(subject.format_scaled(2 ** 40), "1.00 TB")

    def test_max_uint64(self):
        self.assertEqual(subject.format_scaled(2 ** 64 - 1),
                         "16777216.00 TB")


class ChainTests(unittest.TestCase):
    def test_dispatch_at_first_node(self):
        self.assertEqual(
            subject.walk_clock_chain([node("live", 9000)], SENTINEL), 9000)

    def test_dispatch_at_second_node(self):
        chain = [node(SENTINEL, 1), node("live", 8000)]
        self.assertEqual(subject.walk_clock_chain(chain, SENTINEL), 8000)

    def test_unconditional_third_node(self):
        chain = [node(SENTINEL, 1), node(SENTINEL, 2),
                 node(SENTINEL, 7000)]
        # The second node's slot equals the first slot value, so the
        # walk reaches the unconditional third node.
        self.assertEqual(subject.walk_clock_chain(chain, SENTINEL), 7000)

    def test_exhaustion(self):
        for chain in ([], [node(SENTINEL, 1)],
                      [node(SENTINEL, 1), node(SENTINEL, 2)]):
            with self.assertRaises(subject.ChainExhausted):
                subject.walk_clock_chain(chain, SENTINEL)


class SecsSinceTests(unittest.TestCase):
    def test_basic(self):
        self.assertEqual(subject.secs_since(15005000, 5000), 15)

    def test_wraparound(self):
        self.assertEqual(subject.secs_since(100, 2 ** 64 - 1), 0)
        self.assertEqual(subject.secs_since(2 ** 64 - 1, 0),
                         (2 ** 64 - 1) // 1000000)


class ReportTests(unittest.TestCase):
    def test_full_report_end_to_end(self):
        result = subject.format_report(
            fixture(), NAMES, [node("live", 15005000)], SENTINEL)
        self.assertEqual(
            result,
            "Block cache cache-A capacity: 2.00 KB usage: 1.50 KB "
            "table_size: 42 occupancy: 7 collections: 3 last_copies: 9 "
            "last_secs: 0.004 secs_since: 15\n"
            "Block cache entry stats(count,size,portion):"
            " alpha(5,2.00 KB,100%) gamma(2,1.00 KB,50%)\n")

    def test_zero_capacity_ratio_is_inf(self):
        snap = fixture()
        snap["capacity"] = 0
        result = subject.format_report(
            snap, NAMES, [node("live", 15000)], SENTINEL)
        self.assertIn("alpha(5,2.00 KB,inf%)", result)

    def test_zero_capacity_zero_value_ratio_is_nan(self):
        snap = fixture()
        snap["capacity"] = 0
        snap["values"] = [0] + [0] * 13
        result = subject.format_report(
            snap, NAMES, [node("live", 15000)], SENTINEL)
        self.assertIn("alpha(5,0.00 KB,nan%)", result)

    def test_bad_entry_counts_rejected(self):
        snap = fixture()
        snap["counts"] = [1, 2]
        with self.assertRaises(ValueError):
            subject.format_report(snap, NAMES,
                                  [node("live", 15000)], SENTINEL)


class PacketTests(unittest.TestCase):
    def test_packet_verification(self):
        result = subprocess.run(
            [sys.executable, str(PACKET / "verify.py"),
             "--binary", "work/hl-node-94.bin"],
            capture_output=True, text=True, cwd=str(REPO))
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_excerpt_regeneration(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run(
                [sys.executable, str(PACKET / "export_excerpts.py"),
                 "--binary", "work/hl-node-94.bin", "--out", tmp],
                capture_output=True, text=True, cwd=str(REPO))
            self.assertEqual(result.returncode, 0, result.stderr)
            for name in ("window.objdump.txt", "cleanup.objdump.txt",
                         "accessor.objdump.txt", "helper.objdump.txt",
                         "caller1.objdump.txt", "caller2.objdump.txt"):
                self.assertEqual(
                    (Path(tmp) / name).read_text(),
                    (PACKET / name).read_text(), name)

    def test_corruption_controls(self):
        # A flipped excerpt byte no longer matches a fresh objdump run.
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "window.objdump.txt"
            shutil.copy(PACKET / "window.objdump.txt", out)
            data = bytearray(out.read_bytes())
            data[200] ^= 0xFF
            out.write_bytes(data)
            fresh = subprocess.run(
                ["objdump", "-d", "--start-address=0x514f770",
                 "--stop-address=0x514fd30", "work/hl-node-94.bin"],
                capture_output=True, text=True, cwd=str(REPO))
            self.assertNotEqual(out.read_bytes(),
                                fresh.stdout.encode())
        # A flipped records byte breaks the manifest digest.
        import hashlib
        import json
        records = json.loads((PACKET / "records.json").read_text())
        manifest = {}
        for line in (PACKET / "MANIFEST.sha256").read_text().splitlines():
            digest, name = line.split(None, 1)
            manifest[name.strip()] = digest
        digest = hashlib.sha256(
            (PACKET / "records.json").read_bytes()).hexdigest()
        self.assertEqual(manifest["records.json"].strip(), digest)
        tampered = (PACKET / "records.json").read_bytes() + b" "
        self.assertNotEqual(
            hashlib.sha256(tampered).hexdigest(), digest)
        self.assertEqual(records["task_id"], "RE-001")
