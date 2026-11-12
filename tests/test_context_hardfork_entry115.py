"""Target-backed static replay and comparator corruption controls, not decoder equivalence."""
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-008-context-hardfork-entry-115'
spec = importlib.util.spec_from_file_location('context_hardfork_replay', PACKET / 'replay.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class ContextHardforkEntry115(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = bytearray(m.TARGET.read_bytes())
        cls.expected = json.loads((PACKET / 'joins.json').read_text())

    def test_real_image_replay(self):
        self.assertEqual(m.replay(self.data), self.expected)
        self.assertEqual(len(m.excerpt_bytes()), 511)

    def test_continuation_whitespace_is_not_evidence(self):
        text = (PACKET / 'entry.asm').read_text()
        compact = '\n'.join(line.rstrip() for line in text.splitlines()) + '\n'
        padded = '\n'.join(line + ' ' for line in compact.splitlines()) + '\n'
        with patch.object(Path, 'read_text', return_value=compact):
            expected = m.excerpt_bytes()
        with patch.object(Path, 'read_text', return_value=padded):
            self.assertEqual(m.excerpt_bytes(), expected)
        self.assertEqual(len(expected), 511)

    def test_fresh_marker_table_denominator(self):
        groups = self.expected['table']['groups']
        routes = {i:g['target'] for g in groups for i in g['indices']}
        self.assertEqual(sorted(routes), list(range(225)))
        fresh = [routes[i] for i in range(0xc0, 0xe0)]
        self.assertEqual(len(fresh), 32)
        self.assertEqual(fresh.count('0x32b0477'), 13)
        self.assertEqual(routes[0xc1], '0x32b0eba')
        self.assertEqual(routes[0xe0], '0x32b0477')
        # Cached state1 never reaches this table on the observed entry path.
        # No validity/reachability claim for the remaining cached states.

    def changed(self, offset, *, rejected=False):
        old = self.data[offset]
        self.data[offset] ^= 1
        try:
            if rejected:
                with self.assertRaises(ValueError):
                    m.inspect(self.data)
            else:
                self.assertNotEqual(m.inspect(self.data), self.expected)
        finally:
            self.data[offset] = old

    def test_instruction_corruption(self):
        self.changed(0x32af3e0, rejected=True)

    def test_signed_relative_table_corruption(self):
        self.changed(0x718010 + 0xc0 * 4)

    def test_fde_extent_corruption(self):
        self.changed(0x11dada0 + 12, rejected=True)

    def test_cie_encoding_corruption(self):
        self.changed(0x103d604 + 22, rejected=True)

    def test_helper_relocation_corruption(self):
        self.changed(self.expected['relocations'][0]['record_file_offset'] + 16)

    def test_identity_corruption(self):
        self.data[0] ^= 1
        try:
            with self.assertRaisesRegex(ValueError, 'SHA-256'):
                m.replay(self.data)
        finally:
            self.data[0] ^= 1


if __name__ == '__main__':
    unittest.main(verbosity=2)
