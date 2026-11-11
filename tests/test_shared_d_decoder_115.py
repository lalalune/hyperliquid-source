"""Node #115 shared D decoder 0x3215260. Mutations stay in a copied image."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
import shared_d_decoder_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-shared-d-decoder-115/evidence.json'


class SharedDDecoderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        cls.result = packet.bind(cls.data)

    def test_d_is_date_map_of_a_c(self):
        self.assertEqual(self.result['fixmap']['key_type_name'], 'Date')
        fields = self.result['value']['fields']
        self.assertEqual([fields[str(i)]['key'] for i in range(2)], ['a', 'c'])
        self.assertEqual(self.result['value']['missing_field'], 'set to 0, not an error')
        self.assertEqual(self.result['same_layout_as']['pr'], '#6319')
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

    def test_spot_caller_rejected(self):
        self._rejects(self._bump_rel32(self.data, 0x320935e), 'branch at 0x320935d')

    def test_marker_compare_rejected(self):
        self._rejects(self._patch(self.data, 0x32152b6, b'\x91'), 'fixmap below')

    def test_map_visitor_call_rejected(self):
        self._rejects(self._bump_rel32(self.data, 0x3215396), 'branch at 0x3215395')

    def test_date_name_rejected(self):
        # Date -> Datf
        self._rejects(self._patch(self.data, packet.DATE + 3, b'f'), 'string at 0x459fd0')

    def test_key_length_rejected(self):
        self._rejects(self._patch(self.data, 0x3730eec, b'\x05'), 'type name length 4')

    def test_key_byte_rejected(self):
        # cmp al,'c' -> 'd'
        self._rejects(self._patch(self.data, 0x3242c53, b'd'), "compared with 'c'")

    def test_slot_call_rejected(self):
        self._rejects(self._bump_rel32(self.data, 0x3242edd), 'call at 0x3242edb')

    def test_duplicate_name_rejected(self):
        # name 'a' -> 'b'
        self._rejects(self._patch(self.data, packet.NAME_A, b'b'), 'string at 0x793f7f')

    def test_default_rejected(self):
        # cmove -> cmovne for field c
        self._rejects(self._patch(self.data, 0x3243454, b'\x45'), 'c is 0 when not seen')

    def test_holder_rejected(self):
        saved = packet.HOLDER
        packet.HOLDER = dict(saved)
        packet.HOLDER[packet.SEQ_VISITOR] = saved[packet.SEQ_VISITOR] + (0x3730efd,)
        try:
            with self.assertRaisesRegex(ValueError, 'not in function'):
                packet.holders(self.data)
        finally:
            packet.HOLDER = saved


if __name__ == '__main__':
    unittest.main()
