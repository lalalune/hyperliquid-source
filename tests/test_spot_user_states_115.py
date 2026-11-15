"""Node #115 SpotClearinghouse user_states. Mutations stay in a copied image."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
import spot_user_states_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-spot-user-states-115/evidence.json'


class SpotUserStatesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        cls.result = packet.bind(cls.data)

    def test_user_states_is_sequenced_map_of_b_d_s(self):
        self.assertEqual(self.result['fixmap']['expected'], 'a sequenced map')
        self.assertEqual(self.result['pair']['key_length'], 20)
        keys = [self.result['value']['fields'][str(i)]['key'] for i in range(3)]
        self.assertEqual(keys, ['b', 'D', 'S'])
        self.assertEqual(self.result['value']['fields']['1']['decoder'], '0x3215260')
        self.assertEqual(self.result['perp_user_states']['struct_name'],
                         'struct UserStates with 6 elements')
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

    def test_scl_call_rejected(self):
        self._rejects(self._bump_rel32(self.data, packet.SCL_CALL + 1), 'branch at 0x31b62de')

    def test_marker_compare_rejected(self):
        self._rejects(self._patch(self.data, 0x3154218, b'\x91'), 'fixmap below')

    def test_expected_text_rejected(self):
        # a sequenced map -> a sequenced mop
        self._rejects(self._patch(self.data, packet.EXPECTED_TEXT + 13, b'o'), 'string at 0x7de6ec')

    def test_sequence_call_rejected(self):
        self._rejects(self._bump_rel32(self.data, 0x46fa65c), 'branch at 0x46fa65b')

    def test_key_length_rejected(self):
        self._rejects(self._patch(self.data, 0x32a849e, b'\x15'), 'key length 0x14')

    def test_value_call_rejected(self):
        self._rejects(self._bump_rel32(self.data, 0x32a87c4), 'branch at 0x32a87c3')

    def test_key_byte_rejected(self):
        # cmp ecx,'S' -> 'T'
        self._rejects(self._patch(self.data, 0x3208fe3, b'T'), "compared with 'S'")

    def test_field_table_rejected(self):
        self._rejects(self._bump_rel32(self.data, packet.FIELD_TABLE + 4), 'field table entry 1')

    def test_decoder_call_rejected(self):
        self._rejects(self._bump_rel32(self.data, 0x32093fc), 'branch at 0x32093fb')

    def test_duplicate_name_rejected(self):
        # name 'b' -> 'c'
        self._rejects(self._patch(self.data, 0x7932e5, b'c'), 'string at 0x7932e5')

    def test_perp_record_rejected(self):
        self._rejects(self._patch(self.data, 0x795220 + 23, b'7'), 'string at 0x795220')

    def test_holder_rejected(self):
        saved = packet.HOLDER
        packet.HOLDER = dict(saved)
        packet.HOLDER[packet.SEQUENCE] = saved[packet.SEQUENCE] + (0x45dffb8,)
        try:
            with self.assertRaisesRegex(ValueError, 'not in function'):
                packet.holders(self.data)
        finally:
            packet.HOLDER = saved


if __name__ == '__main__':
    unittest.main()
