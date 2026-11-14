"""Pinned target proof and in-memory corruption controls; missing target is an error."""
import json
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import re002_node115_versioned_imports as tool


class VersionedImportsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = Path(tool.elf.target_path()).read_bytes()
        cls.observed = tool.observe(cls.data)
        cls.rows = cls.observed["derived"]["imports"]

    def changed(self, offset, replacement):
        data = bytearray(self.data)
        data[offset:offset + len(replacement)] = replacement
        return tool.derive(data)

    def test_authenticated_packet(self):
        self.assertEqual(self.observed, json.loads(tool.PACKET.read_text()))
        self.assertEqual(self.observed["derived"]["table_census"]["symbols"], 510)
        self.assertEqual(self.observed["derived"]["table_census"]["version_carriers"], 498)

    def test_exact_named_bindings(self):
        self.assertEqual([(r["dynsym_index"], r["name"], r["binding"], r["version_index"], r["library"]) for r in self.rows], [
            (140, "pidfd_spawnp", 2, 20, "libc.so.6"),
            (168, "pidfd_getpid", 2, 20, "libc.so.6"),
            (286, "_ZNSt18condition_variable4waitERSt11unique_lockISt5mutexE", 1, 44, "libstdc++.so.6")])
        self.assertTrue(all(r["section_index"] == 0 and r["symbol_type"] == 2 for r in self.rows))

    def test_binding_corruption_changes_join(self):
        row = self.rows[0]
        changed = self.changed(row["dynsym_offset"] + 4, b"\x12")
        self.assertNotEqual(changed, self.observed["derived"])
        self.assertEqual(changed["imports"][0]["binding"], 1)

    def test_symbol_name_corruption_changes_join(self):
        self.assertNotEqual(self.changed(self.rows[0]["symbol_name_offset"], b"X"), self.observed["derived"])

    def test_version_index_corruption_rejected(self):
        with self.assertRaises(tool.elf.DerivationError):
            self.changed(self.rows[0]["versym_offset"], struct.pack("<H", 0x7fff))

    def test_version_flags_corruption_changes_join(self):
        row = self.rows[0]
        self.assertNotEqual(self.changed(row["vernaux_offset"] + 4, struct.pack("<H", row["version_flags"] ^ 2)), self.observed["derived"])

    def test_target_corruption_rejected(self):
        data = bytearray(self.data)
        data[0] ^= 1
        with self.assertRaises(tool.elf.DerivationError):
            tool.observe(data)


if __name__ == "__main__":
    unittest.main()
