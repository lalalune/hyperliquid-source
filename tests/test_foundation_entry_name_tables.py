"""Tests for the node #94 entry-name table initializer model.

Run from the repository root with unittest (no pytest on this VM):

    python3 -m unittest tests.test_foundation_entry_name_tables -v
"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from foundation_entry_name_tables import (
    CxxString,
    EntryNameTable,
    ENTRY_COUNT,
    ENTRY_STRIDE,
    FIRST_TABLE_BASE,
    KEBAB_NAMES,
    NullStringError,
    PASCAL_NAMES,
    SECOND_TABLE_BASE,
    SSO_LIMIT,
    initialize,
)

REPO = Path(__file__).resolve().parents[1]
PACKET = REPO / "research" / "work-items" / "RE-001-entry-name-tables-94"


class TestTables(unittest.TestCase):
    def test_initialize_returns_both_tables_in_order(self):
        first, second, registrations = initialize()
        self.assertEqual(first.names(), PASCAL_NAMES)
        self.assertEqual(second.names(), KEBAB_NAMES)
        self.assertEqual(first.base, FIRST_TABLE_BASE)
        self.assertEqual(second.base, SECOND_TABLE_BASE)
        self.assertEqual(
            registrations,
            [(0x515F870, FIRST_TABLE_BASE, 0x577A660),
             (0x515F870, SECOND_TABLE_BASE, 0x577A660)])

    def test_entry_addresses_use_stride(self):
        table = EntryNameTable(FIRST_TABLE_BASE, PASCAL_NAMES)
        for i in range(ENTRY_COUNT):
            self.assertEqual(table.entry_address(i),
                             FIRST_TABLE_BASE + i * ENTRY_STRIDE)
        self.assertEqual(table.entry_address(13), FIRST_TABLE_BASE + 0x1A0)

    def test_pascal_and_kebab_align_entry_by_entry(self):
        # Same 14 entries, same order, different spelling only.
        self.assertEqual(len(PASCAL_NAMES), len(KEBAB_NAMES))
        for pascal, kebab in zip(PASCAL_NAMES, KEBAB_NAMES):
            self.assertEqual(kebab, kebab.lower())
            self.assertNotEqual(pascal, kebab)

    def test_heap_and_inline_split_matches_lengths(self):
        first, second, _ = initialize()
        for table in (first, second):
            for entry in table.entries:
                want = "inline" if len(entry.value) <= SSO_LIMIT else "heap"
                self.assertEqual(entry.storage, want)
                self.assertEqual(entry.terminated,
                                 entry.value + b"\x00")
                self.assertEqual(entry.length, len(entry.value))
        # Boundary names pinned by the tables themselves: 15 stays
        # inline, 21 goes to the heap.
        self.assertEqual(first.entries[2].storage, "inline")  # FilterMetaBlock
        self.assertEqual(first.entries[3].storage, "heap")  # Deprecated...
        self.assertEqual(second.entries[2].storage, "heap")  # filter-meta-block


class TestStringArms(unittest.TestCase):
    def test_null_source_raises(self):
        with self.assertRaises(NullStringError):
            CxxString(None)

    def test_empty_and_single_byte(self):
        empty = CxxString(b"")
        self.assertEqual(empty.length, 0)
        self.assertEqual(empty.storage, "inline")
        self.assertEqual(empty.terminated, b"\x00")
        one = CxxString(b"x")
        self.assertEqual(one.length, 1)
        self.assertEqual(one.storage, "inline")
        self.assertEqual(one.terminated, b"x\x00")

    def test_sso_boundary(self):
        self.assertEqual(CxxString(b"a" * 15).storage, "inline")
        self.assertEqual(CxxString(b"a" * 16).storage, "heap")
        self.assertEqual(CxxString(b"a" * 33).length, 33)


class TestDestructor(unittest.TestCase):
    def test_frees_heap_only_in_reverse_order(self):
        _, second, _ = initialize()
        freed = second.destroy()
        # Heap entries in the kebab table, backwards: indices with
        # length > 15, in descending order.
        want = [i for i in range(ENTRY_COUNT - 1, -1, -1)
                if len(KEBAB_NAMES[i]) > SSO_LIMIT]
        self.assertEqual(freed, want)
        self.assertTrue(all(second.entries[i].disposed for i in want))
        self.assertFalse(any(second.entries[i].disposed
                             for i in range(ENTRY_COUNT) if i not in want))

    def test_destroy_is_idempotent(self):
        first, _, _ = initialize()
        first.destroy()
        self.assertEqual(first.destroy(), [])


class TestPacket(unittest.TestCase):
    def test_verify_passes(self):
        result = subprocess.run(
            [sys.executable, str(PACKET / "verify.py"),
             "--binary", "work/hl-node-94.bin"],
            cwd=str(REPO), capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("ALL CHECKS PASSED", result.stdout)

    def test_excerpts_regenerate(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run(
                [sys.executable, str(PACKET / "export_excerpts.py"),
                 "--binary", "work/hl-node-94.bin", "--out", tmp],
                cwd=str(REPO), capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            for name in ("window.objdump.txt", "assign.objdump.txt",
                         "destructor.objdump.txt"):
                self.assertEqual((Path(tmp) / name).read_text(),
                                 (PACKET / name).read_text())

    def test_records_match_model(self):
        records = json.loads((PACKET / "records.json").read_text())
        self.assertEqual(records["tables"][0]["names"], PASCAL_NAMES)
        self.assertEqual(records["tables"][1]["names"], KEBAB_NAMES)
        self.assertEqual(records["tables"][0]["base"], "0x578c2e0")
        self.assertEqual(records["tables"][1]["base"], "0x578c120")

    def test_corruption_control_banned_key(self):
        # Corruption control 1: a per-instruction list in the
        # records must fail verification.
        with tempfile.TemporaryDirectory() as tmp:
            tmp_packet = Path(tmp) / "packet"
            tmp_packet.mkdir()
            for path in PACKET.iterdir():
                if path.name != "MANIFEST.sha256":
                    (tmp_packet / path.name).write_bytes(path.read_bytes())
            records = json.loads((tmp_packet / "records.json").read_text())
            records["mnemonics"] = ["endbr64"]
            (tmp_packet / "records.json").write_text(json.dumps(records))
            result = subprocess.run(
                [sys.executable, str(tmp_packet / "verify.py"),
                 "--binary", "work/hl-node-94.bin",
                 "--packet-dir", str(tmp_packet)],
                cwd=str(REPO), capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)

    def test_corruption_control_tampered_excerpt(self):
        # Corruption control 2: a tampered excerpt must fail.
        with tempfile.TemporaryDirectory() as tmp:
            tmp_packet = Path(tmp) / "packet"
            tmp_packet.mkdir()
            for path in PACKET.iterdir():
                if path.name != "MANIFEST.sha256":
                    (tmp_packet / path.name).write_bytes(path.read_bytes())
            excerpt = tmp_packet / "window.objdump.txt"
            text = excerpt.read_text().replace("51601c0", "51601c1", 1)
            excerpt.write_text(text)
            result = subprocess.run(
                [sys.executable, str(tmp_packet / "verify.py"),
                 "--binary", "work/hl-node-94.bin",
                 "--packet-dir", str(tmp_packet)],
                cwd=str(REPO), capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
