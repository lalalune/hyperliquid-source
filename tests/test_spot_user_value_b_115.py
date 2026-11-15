"""Node #115 spot per-user value field b. Mutations stay in a copied image."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
import spot_user_value_b_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-spot-user-value-b-115/evidence.json'


class SpotUserValueBTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        cls.result = packet.bind(cls.data)

    def test_b_is_token_map_of_t_h_e(self):
        self.assertEqual(self.result['fixmap']['key_type_name'], 'Token')
        fields = self.result['value']['fields']
        self.assertEqual([fields[str(i)]['key'] for i in range(3)], ['t', 'h', 'e'])
        self.assertEqual(fields['0']['reader']['type_name'], 'Wei')
        self.assertEqual(fields['2']['reader']['type_name'], 'UsdcBigSpotNtl')
        self.assertEqual(self.result['value']['missing_field'], 'set to 0, not an error')
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

    def test_spot_value_call_rejected(self):
        self._rejects(self._bump_rel32(self.data, packet.SPOT_VALUE_CALL + 1), 'branch at 0x3208d6b')

    def test_marker_compare_rejected(self):
        self._rejects(self._patch(self.data, 0x31a7446, b'\x91'), 'fixmap below')

    def test_map_visitor_call_rejected(self):
        self._rejects(self._bump_rel32(self.data, 0x31a7526), 'branch at 0x31a7525')

    def test_token_name_rejected(self):
        # Token -> Tokem
        self._rejects(self._patch(self.data, packet.TOKEN + 4, b'm'), 'string at 0x7c8235')

    def test_value_call_rejected(self):
        self._rejects(self._bump_rel32(self.data, 0x3747f3a), 'branch at 0x3747f39')

    def test_key_byte_rejected(self):
        # cmp ecx,'h' -> 'i'
        self._rejects(self._patch(self.data, 0x3077990, b'i'), "compared with 'h'")

    def test_field_table_rejected(self):
        self._rejects(self._bump_rel32(self.data, packet.FIELD_TABLE + 8), 'field table entry 2')

    def test_type_name_length_rejected(self):
        self._rejects(self._patch(self.data, 0x3077c72, b'\x0d'), 'type name length 14')

    def test_duplicate_name_rejected(self):
        # name 't' -> 'u'
        self._rejects(self._patch(self.data, 0x793679, b'u'), 'string at 0x793679')

    def test_default_rejected(self):
        # cmove -> cmovne for field e
        self._rejects(self._patch(self.data, 0x3078303, b'\x45'), 'e is 0 when not seen')

    def test_holder_rejected(self):
        saved = packet.HOLDER
        packet.HOLDER = dict(saved)
        packet.HOLDER[packet.SEQ_VISITOR] = saved[packet.SEQ_VISITOR] + (0x3747f39,)
        try:
            with self.assertRaisesRegex(ValueError, 'not in function'):
                packet.holders(self.data)
        finally:
            packet.HOLDER = saved


if __name__ == '__main__':
    unittest.main()
