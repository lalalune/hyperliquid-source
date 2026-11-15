"""Node #115 Locus field scl. Mutations stay in a copied image."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
import locus_scl_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-locus-scl-115/evidence.json'


class LocusSclTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        cls.result = packet.bind(cls.data)

    def test_scl_is_spot_clearinghouse(self):
        self.assertEqual(self.result['struct_name']['text'],
                         'struct SpotClearinghouse with 14 elements')
        self.assertEqual(len(self.result['fields']), 15)
        self.assertEqual(self.result['fields']['1']['key'], 'user_states')
        self.assertEqual(len(self.result['missing_field_errors']), 8)
        self.assertFalse(self.result['fields']['13']['required'])
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

    def test_locus_call_rejected(self):
        self._rejects(self._bump_rel32(self.data, packet.LOCUS_CALL + 1), 'branch at 0x332cd98')

    def test_marker_compare_rejected(self):
        # cmp al,0x90 -> 0x91
        self._rejects(self._patch(self.data, 0x31b54d8, b'\x91'), 'fixmap below')

    def test_key_slot_rejected(self):
        self._rejects(self._bump_rel32(self.data, packet.KEY_CALL + 2, 8), 'not through slot')

    def test_key_clamp_rejected(self):
        # cmp cl,0xe -> 0xf
        self._rejects(self._patch(self.data, 0x33f3042, b'\x0f'), 'clamped to 14')

    def test_field_table_rejected(self):
        self._rejects(self._bump_rel32(self.data, packet.FIELD_TABLE + 4 * 3), 'field table entry 3')

    def test_duplicate_branch_rejected(self):
        self._rejects(self._bump_rel32(self.data, 0x31b62cd), 'branch at 0x31b62cb')

    def test_field_name_rejected(self):
        # user_states -> uaer_states
        self._rejects(self._patch(self.data, 0x79310b, b'a'), 'string at 0x79310a')

    def test_name_length_rejected(self):
        self._rejects(self._patch(self.data, 0x31b7fb8 + 17, b'\x0c'), 'does not store length 11')

    def test_decoder_call_rejected(self):
        self._rejects(self._bump_rel32(self.data, 0x31b6186), 'branch at 0x31b6185')

    def test_missing_template_rejected(self):
        self._rejects(self._bump_rel32(self.data, 0x31b6a25), 'lea at 0x31b6a22')

    def test_struct_name_rejected(self):
        # 14 elements -> 15 elements
        self._rejects(self._patch(self.data, 0x796322 + 31, b'5'), 'string at 0x796322')

    def test_record_length_rejected(self):
        self._rejects(self._patch(self.data, packet.NAME_RECORD + 8, b'\x2a'), 'has length 42')

    def test_holder_rejected(self):
        saved = packet.KEY_READER
        packet.KEY_READER = packet.SCL
        try:
            with self.assertRaisesRegex(ValueError, 'not in function'):
                packet.holders(self.data)
        finally:
            packet.KEY_READER = saved


if __name__ == '__main__':
    unittest.main()
