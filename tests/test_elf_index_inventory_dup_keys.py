"""elf_index must reject duplicate keys in the retained inventory input.

Sibling of open #142 (catalogue generate) and of #151 (harness_plan):
the inventory file that elf_index's main() compares its parsed unwind
count against is loaded with plain json.loads, so a duplicated
fde_count_eh_frame_hdr key is silently resolved to its last value —
a corrupted inventory passes the gate whenever the last copy matches.
Catalogue's loads of the same inventory files are covered by #142;
this loader is not.
"""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from elf_index import load_inventory


def _load_text(text):
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / 'inv.json'
        p.write_text(text)
        return load_inventory(p)


class InventoryDuplicateKeyTests(unittest.TestCase):
    def test_duplicate_fde_count_rejected(self):
        text = ('{"first_party_files": {}, "fde_count_eh_frame_hdr": 999,'
                ' "fde_count_eh_frame_hdr": 1}')
        with self.assertRaises(ValueError):
            _load_text(text)

    def test_duplicate_nested_key_rejected(self):
        with self.assertRaises(ValueError):
            _load_text('{"first_party_files": {"base": ["a.rs"], "base": ["b.rs"]},'
                       ' "fde_count_eh_frame_hdr": 1}')

    def test_clean_inventory_still_loads(self):
        doc = _load_text('{"first_party_files": {}, "fde_count_eh_frame_hdr": 1}')
        self.assertEqual(doc['fde_count_eh_frame_hdr'], 1)


if __name__ == '__main__':
    unittest.main()
