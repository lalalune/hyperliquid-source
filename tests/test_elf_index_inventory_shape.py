"""Malformed retained inventories fail closed in the elf_index CLI.

main() reads the retained inventory's unwind count before validating it,
so an inventory that is missing the count — or is not a record at all —
must meet the module's 'Invalid retained unwind count' diagnostic, not
escape as a raw KeyError or TypeError. Staging idiom follows
test_elf_index_manifest_lookup.py: the tool is loaded as its own module
instance and run against a staged root whose manifest and artifact pass
the real check, so the inventory dereference is reached; generate is
stubbed so a valid inventory completes the CLI.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
spec = importlib.util.spec_from_file_location(
    'elf_index_inventory_shape', Path(__file__).resolve().parents[1] / 'tools/elf_index.py')
ei = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ei)

REL = 'artifacts/node/115/hl-node'


class InventoryShapeTests(unittest.TestCase):
    def run_main(self, inventory):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        blob = b'staged-node115'
        target = root / REL
        target.parent.mkdir(parents=True)
        target.write_bytes(blob)
        (root / 'provenance').mkdir()
        (root / 'provenance/artifacts.json').write_text(json.dumps(
            {'files': [{'path': REL, 'size': len(blob),
                        'sha256': hashlib.sha256(blob).hexdigest()}]}))
        path = root / 'research/imported/hl-node-115.inventory.json'
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps(inventory))
        with patch.object(ei, 'ROOT', root), \
             patch.object(ei, 'generate', lambda *a, **k: {'ok': 1}), \
             patch.object(sys, 'argv', ['elf_index.py', '--release', '115']):
            return ei.main()

    def test_missing_unwind_count_is_invalid(self):
        with self.assertRaisesRegex(ValueError, 'Invalid retained unwind count'):
            self.run_main({'other': 1})

    def test_inventory_not_a_record_is_invalid(self):
        with self.assertRaisesRegex(ValueError, 'Invalid retained unwind count'):
            self.run_main([1, 2])

    def test_valid_inventory_reaches_generate(self):
        self.assertEqual(self.run_main({'fde_count_eh_frame_hdr': 3}), 0)


if __name__ == '__main__':
    unittest.main()
