"""Node #115 abci_hashes exchange_abci_hash JSON shape. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import abci_hashes_tree_json_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-abci-hashes-tree-json-115/evidence.json'


class AbciHashesTreeJsonTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_shape(self):
        self.assertEqual(self.result['node_writer']['direct_calls_in_fn'], ['0x5025add', '0x5025c81'])
        example = self.result['derived_example']
        self.assertEqual(example['length'], 147)
        self.assertTrue(example['json'].startswith('[[0,"0x000102'))
        self.assertIn('],[3,"0x2021', example['json'])
        self.assertNotIn(' ', example['json'])
        self.assertEqual(packet.render_tree([]), '[]')
        self.assertFalse(self.result['gates_changed'])

    def test_committed_packet_matches(self):
        self.assertEqual(packet.render(self.result), PACKET.read_bytes())
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(packet.main(['--out', tmp, '--check']), 0)

    def _patch(self, va, new):
        broken = bytearray(self.data)
        sec = next(s for s in sections(self.data)
                   if s['type'] != 8 and s['address'] <= va < s['address'] + s['size'])
        off = sec['offset'] + va - sec['address']
        broken[off:off + len(new)] = new
        return bytes(broken)

    def _rejects(self, data):
        with self.assertRaises(ValueError):
            packet.bind(data, self.fdes)

    def test_element_open_rejected(self):
        # '[' -> '{' for the first element
        self._rejects(self._patch(0x5025a5f + 3, b'\x7b'))

    def test_separator_rejected(self):
        # ',' between index and child -> ':'
        self._rejects(self._patch(0x5025abf + 4, b'\x3a'))

    def test_field_colon_rejected(self):
        # ':' after the key -> '='
        self._rejects(self._patch(0x506d581 + 3, b'\x3d'))

    def test_stride_rejected(self):
        # add r14, 0x30 -> 0x28
        self._rejects(self._patch(0x5025cf6 + 3, b'\x28'))

    def test_leaf_offset_rejected(self):
        # lea rdx, [elem+9] -> [elem+8]
        self._rejects(self._patch(0x5025b28 + 3, b'\x08'))

    def test_trim_rejected(self):
        # xor r8d, r8d -> xor r8d, r9d (trim byte no longer 0)
        self._rejects(self._patch(0x4e1c25d + 2, b'\xc8'))

    def test_empty_literal_rejected(self):
        # "0x" literal -> "0X"
        self._rejects(self._patch(packet.EMPTY_HEX + 1, b'X'))

    def test_recursion_rejected(self):
        # retarget the first recursive call
        self._rejects(self._patch(0x5025add + 1, b'\x2f'))


if __name__ == '__main__':
    unittest.main()
