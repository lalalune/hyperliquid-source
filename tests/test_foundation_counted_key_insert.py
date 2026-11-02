"""Tests for tools/foundation_counted_key_insert.py, the model of
node #94 0x5160940 (mutex-guarded counted-key insert-or-increment).

Run with unittest (no pytest on this VM):

    python3 -m unittest tests.test_foundation_counted_key_insert -v
"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tools"))

from foundation_counted_key_insert import (  # noqa: E402
    CountedKeyTable, LockFailed, NeedsGrowth)

PACKET = REPO / "research" / "work-items" / "RE-001-counted-key-insert-94"
# Relative on purpose: objdump prints the binary path in its header,
# so the stored excerpts only regenerate byte-for-byte when the
# binary is named by the same relative path from the repo root.
BINARY = "work/hl-node-94.bin"


def growing_table(capacity, pairs):
    """A table whose grow callback extends capacity and inserts."""
    table = CountedKeyTable(capacity, pairs)

    def grow(tbl, key):
        tbl.capacity += 1
        # Same descending-order scan the window performs.
        position = 0
        for index in range(len(tbl.pairs) - 1, -1, -1):
            other = tbl.pairs[index][0]
            if key == other:
                raise AssertionError("grow called for a present key")
            if key < other:
                position = index + 1
                break
        tbl.pairs.insert(position, [key, 1])
        return position

    return table, grow


class CountedKeyInsertTests(unittest.TestCase):
    def test_empty_vector_appends(self):
        table = CountedKeyTable(4)
        self.assertEqual(table.insert_or_increment(10), ("inserted", 0))
        self.assertEqual(table.pairs, [[10, 1]])
        self.assertFalse(table.locked)

    def test_append_when_key_less_than_last(self):
        table = CountedKeyTable(4, [[10, 2], [7, 1], [5, 3]])
        self.assertEqual(table.insert_or_increment(3), ("inserted", 3))
        self.assertEqual(table.keys(), [10, 7, 5, 3])

    def test_middle_insert_keeps_descending_order(self):
        table = CountedKeyTable(8, [[10, 1], [7, 1], [5, 1]])
        self.assertEqual(table.insert_or_increment(8), ("inserted", 1))
        self.assertEqual(table.keys(), [10, 8, 7, 5])

    def test_begin_insert_when_key_greater_than_all(self):
        table = CountedKeyTable(8, [[10, 1], [7, 1], [5, 1]])
        self.assertEqual(table.insert_or_increment(12), ("inserted", 0))
        self.assertEqual(table.keys(), [12, 10, 7, 5])

    def test_increment_on_match(self):
        table = CountedKeyTable(8, [[10, 1], [7, 4], [5, 1]])
        self.assertEqual(table.insert_or_increment(7), ("incremented", 1))
        self.assertEqual(table.pairs, [[10, 1], [7, 5], [5, 1]])
        self.assertFalse(table.locked)

    def test_increment_wraps_modulo_2_to_64(self):
        table = CountedKeyTable(4, [[10, (1 << 64) - 1]])
        table.insert_or_increment(10)
        self.assertEqual(table.pairs, [[10, 0]])

    def test_unsigned_comparison(self):
        # A key with the high bit set sorts above every small key.
        table = CountedKeyTable(8, [[10, 1], [7, 1]])
        self.assertEqual(table.insert_or_increment(1 << 63), ("inserted", 0))
        self.assertEqual(table.keys(), [1 << 63, 10, 7])

    def test_end_to_end_sequence(self):
        table = CountedKeyTable(16)
        for key in (10, 5, 7, 5, 12, 3, 7):
            table.insert_or_increment(key)
        self.assertEqual(table.pairs,
                         [[12, 1], [10, 1], [7, 2], [5, 2], [3, 1]])

    def test_full_vector_without_grow_raises_and_unlocks(self):
        table = CountedKeyTable(2, [[10, 1], [5, 1]])
        with self.assertRaises(NeedsGrowth):
            table.insert_or_increment(7)
        self.assertEqual(table.pairs, [[10, 1], [5, 1]])
        self.assertFalse(table.locked)

    def test_full_vector_growth_contract(self):
        table, grow = growing_table(2, [[10, 1], [5, 1]])
        self.assertEqual(table.insert_or_increment(7, grow=grow),
                         ("grown", 1))
        self.assertEqual(table.keys(), [10, 7, 5])
        self.assertEqual(table.capacity, 3)
        self.assertFalse(table.locked)

    def test_lock_failure_throws_and_leaves_unlocked(self):
        table = CountedKeyTable(4, [[10, 1]])
        table.lock_fail = True
        with self.assertRaises(LockFailed):
            table.insert_or_increment(7)
        self.assertFalse(table.locked)
        self.assertEqual(table.pairs, [[10, 1]])

    def test_packet_verification(self):
        result = subprocess.run(
            [sys.executable, str(PACKET / "verify.py"),
             "--binary", str(BINARY)],
            capture_output=True, text=True, cwd=str(REPO))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("ALL CHECKS PASSED", result.stdout)

    def test_excerpt_regeneration(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run(
                [sys.executable, str(PACKET / "export_excerpts.py"),
                 "--binary", str(BINARY), "--out", tmp],
                capture_output=True, text=True, cwd=str(REPO))
            self.assertEqual(result.returncode, 0, result.stderr)
            for name in ("window.objdump.txt", "cleanup.objdump.txt",
                         "caller-site.objdump.txt"):
                self.assertEqual((Path(tmp) / name).read_text(),
                                 (PACKET / name).read_text())

    def test_corruption_control_records(self):
        records = json.loads((PACKET / "records.json").read_text())
        records["window"]["start"] = "0x5160941"
        with tempfile.TemporaryDirectory() as tmp:
            packet = Path(tmp) / "packet"
            packet.mkdir()
            for path in PACKET.iterdir():
                if not path.is_file():
                    continue
                (packet / path.name).write_bytes(path.read_bytes())
            (packet / "records.json").write_text(json.dumps(records))
            result = subprocess.run(
                [sys.executable, str(packet / "verify.py"),
                 "--binary", str(BINARY)],
                capture_output=True, text=True, cwd=str(REPO))
            self.assertNotEqual(result.returncode, 0)

    def test_corruption_control_excerpt(self):
        with tempfile.TemporaryDirectory() as tmp:
            packet = Path(tmp) / "packet"
            packet.mkdir()
            for path in PACKET.iterdir():
                if not path.is_file():
                    continue
                (packet / path.name).write_bytes(path.read_bytes())
            window = packet / "window.objdump.txt"
            window.write_text(window.read_text().replace(
                "5160940", "5160941", 1))
            result = subprocess.run(
                [sys.executable, str(packet / "verify.py"),
                 "--binary", str(BINARY)],
                capture_output=True, text=True, cwd=str(REPO))
            self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
