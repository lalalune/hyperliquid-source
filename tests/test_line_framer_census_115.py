"""Node #115 line framer census. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item  # noqa: E402
from elf_index import sections  # noqa: E402
from fde_extents import fde_extents  # noqa: E402
import line_framer_census_115 as packet  # noqa: E402

PACKET = ROOT / 'research/work-items/RE-008-line-framer-census-115/evidence.json'


class LineFramerCensusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_census(self):
        r = self.result
        self.assertEqual((r['call_sites'], r['functions']), (96, 96))
        self.assertEqual(r['classes'], {'bare': 36, 'bracket_other': 6, 'time_writer': 21, 'twin_time': 33})
        self.assertEqual(r['bracket_first_value_writers'],
                         {'0x2506050': 29, '0x4779470': 4, '0x4e2d7f0': 2, '0x3d3f240': 1,
                          '0x3d40850': 1, '0x50fc010': 1, '0x50a3510': 1})
        self.assertEqual(r['name_ties_within_two_call_levels'], {'0x50e50b0': ['visor_abci_states']})
        self.assertFalse(r['gates_changed'])

    def test_committed_packet_matches(self):
        self.assertEqual(packet.render(self.result), PACKET.read_bytes())
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(packet.main(['--out', tmp, '--check']), 0)

    def _patch(self, va, new):
        sec = next(s for s in sections(self.data)
                   if s['type'] != 8 and s['address'] <= va < s['address'] + s['size'])
        off = sec['offset'] + va - sec['address']
        broken = bytearray(self.data)
        broken[off:off + len(new)] = new
        return bytes(broken)

    def _rejects(self, data):
        with self.assertRaises(ValueError):
            packet.bind(data, self.fdes)

    def test_twin_a_quote_rejected(self):
        self._rejects(self._patch(0x2506079 + 3, b'\x27'))

    def test_twin_b_quote_rejected(self):
        self._rejects(self._patch(0x47794ad + 3, b'\x27'))

    def test_display_a_letter_rejected(self):
        # 'T' -> 'U'
        self._rejects(self._patch(0x26a1394 + 1, b'\x55'))

    def test_display_b_letter_rejected(self):
        self._rejects(self._patch(0x4783144 + 1, b'\x55'))

    def test_twin_a_display_ref_rejected(self):
        self._rejects(self._patch(0x25060a0 + 3, b'\x00'))

    def test_hex_prefix_rejected(self):
        # "0x" -> "0X"
        self._rejects(self._patch(0x4e2d811 + 6, b'\x58'))

    def test_hex_table_ref_rejected(self):
        self._rejects(self._patch(0x3d3f283 + 3, b'\x00'))

    def test_display_time_slot_rejected(self):
        self._rejects(self._patch(0x478316b + 2, b'\x00'))


if __name__ == '__main__':
    unittest.main()
