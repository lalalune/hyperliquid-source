"""Node #115 Locus uaR item decoder. Mutations stay in a copied image."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
import locus_uar_item_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-locus-uar-item-115/evidence.json'


class LocusUarItemTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        cls.result = packet.bind(cls.data)

    def test_item_is_single_entry_enum(self):
        item = self.result['item_decoder']
        self.assertEqual(item['variant_reader'], '0x3bdc730')
        variants = self.result['variant_reader']['mapped_variants']
        self.assertEqual([(v['type_name'], v['variant']) for v in variants],
                         [('Perp', 0), ('Spot', 1), ('Token', 2), ('Pdi', 3)])
        self.assertEqual(len(self.result['variant_reader']['entries']), 7)
        self.assertFalse(self.result['variant_reader']['index_reader_mapped'])
        self.assertFalse(self.result['gates_changed'])

    def test_committed_packet_matches(self):
        self.assertEqual(packet.render(self.result), PACKET.read_bytes())
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(packet.main(['--out', tmp, '--check']), 0)

    def _off(self, data, va):
        sec = next(s for s in sections(data)
                   if s['type'] != 8 and s['address'] <= va < s['address'] + s['size'])
        return sec['offset'] + va - sec['address']

    def _patch(self, data, va, new):
        off = self._off(data, va)
        broken = bytearray(data)
        broken[off:off + len(new)] = new
        return bytes(broken)

    def _bump_rel32(self, data, va, by=1):
        rel = struct.unpack('<i', packet.read_va(data, va, 4))[0]
        return self._patch(data, va, struct.pack('<i', rel + by))

    def _rejects(self, data, why):
        with self.assertRaisesRegex(ValueError, why):
            packet.bind(data)

    def test_map_length_rejected(self):
        # fixmap length 1 -> 2
        self._rejects(self._patch(self.data, 0x2f3c5e7, b'\x02'), 'fixmap length')

    def test_map16_marker_rejected(self):
        # cmp 0xde -> 0xdd
        self._rejects(self._patch(self.data, 0x2f3c4c5, b'\xdd'), 'map16')

    def test_length_error_tag_rejected(self):
        # error tag 4 -> 5
        self._rejects(self._patch(self.data, 0x2f3c5af, b'\x05'), 'error tag 4')

    def test_variant_call_rejected(self):
        self._rejects(self._bump_rel32(self.data, 0x2f3c5f2), 'branch at 0x2f3c5f1')

    def test_item_call_rejected(self):
        self._rejects(self._bump_rel32(self.data, 0x329efe9), '0x329efe2')

    def test_perp_text_rejected(self):
        # Perp -> Qerp
        self._rejects(self._patch(self.data, 0x45a0d0, b'Q'), "string at 0x45a0d0")

    def test_token_length_rejected(self):
        # Token length 5 -> 6
        self._rejects(self._patch(self.data, 0x3bdc862, b'\x06'), 'name length at 0x3bdc861')

    def test_pdi_variant_rejected(self):
        # Pdi stores variant 3 -> 4
        self._rejects(self._patch(self.data, 0x3bdc8ad, b'\x04'), 'variant store at 0x3bdc8a9')

    def test_table_entry_rejected(self):
        self._rejects(self._bump_rel32(self.data, packet.TABLE + 4 * 1), 'entry 1')

    def test_next_table_lea_rejected(self):
        self._rejects(self._bump_rel32(self.data, packet.NEXT_TABLE_LEA + 3, 4), 'lea at 0x3bdca18')

    def test_success_tag_rejected(self):
        self._rejects(self._patch(self.data, 0x3bdc8e6, b'\x08'), 'success tag')

    def test_holder_rejected(self):
        saved = packet.HOLDERS
        packet.HOLDERS = {**saved, 0x3bdc747: packet.ITEM}
        try:
            with self.assertRaisesRegex(ValueError, 'not in function'):
                packet.bind(self.data)
        finally:
            packet.HOLDERS = saved


if __name__ == '__main__':
    unittest.main()
