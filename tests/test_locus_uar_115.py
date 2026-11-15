"""Node #115 Locus field 7 (uaR) decoder. Mutations stay in a copied image."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
import locus_uar_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-locus-uar-115/evidence.json'


class LocusUarTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        cls.result = packet.bind(cls.data)

    def test_uar_is_user_map_of_sequences(self):
        uar = self.result['uar']
        self.assertEqual(self.result['locus_field'], {'index': 7, 'key': 'uaR', 'decoder': '0x32da770'})
        self.assertEqual(uar['key']['type_name'], 'User')
        self.assertEqual(uar['key']['length'], 20)
        self.assertEqual(uar['key']['bytes_reader'], '0x32e36c0')
        self.assertEqual(uar['value']['map_form'], 'refused: expected a sequence')
        self.assertEqual(sorted(uar['wide_markers']), ['0xdc', '0xdd', '0xde', '0xdf'])
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

    def test_user_text_rejected(self):
        # User -> Vser
        self._rejects(self._patch(self.data, 0x45a0ec, b'V'), "string at 0x45a0ec")

    def test_key_length_rejected(self):
        # key length 0x14 -> 0x15
        self._rejects(self._patch(self.data, 0x2f660fa, b'\x15'), 'key reader')

    def test_sequence_text_rejected(self):
        # a sequence -> a sequencf
        self._rejects(self._patch(self.data, 0x7a03c9 + 9, b'f'), "string at 0x7a03c9")

    def test_refusal_tag_rejected(self):
        # unexpected-type tag 0xb (map) -> 0xc
        self._rejects(self._patch(self.data, 0x3848e3c, b'\x0c'), 'refusal')

    def test_marker_entry_rejected(self):
        entry = packet.MARKER_TABLE + 4 * 0xde
        self._rejects(self._bump_rel32(self.data, entry), 'marker 0xde')

    def test_wide_arm_jump_rejected(self):
        # map32 arm no longer joins the map path
        self._rejects(self._bump_rel32(self.data, 0x32daa2d), 'branch at 0x32daa2c')

    def test_expectation_relocation_rejected(self):
        rela = next(s for s in sections(self.data) if s['name'] == '.rela.dyn')
        body = self.data[rela['offset']:rela['offset'] + rela['size']]
        for i, (off, info, addend) in enumerate(struct.iter_unpack('<QQq', body)):
            if off == packet.EXPECT_SLOT:
                at = rela['offset'] + 24 * i + 16
                break
        broken = bytearray(self.data)
        broken[at:at + 8] = struct.pack('<q', packet.EXPECT_FN + 1)
        self._rejects(bytes(broken), 'relocation at 0x646c9a8')

    def test_duplicate_key_lea_rejected(self):
        self._rejects(self._bump_rel32(self.data, 0x377b343), 'lea at 0x377b340')

    def test_user_to_state_reader_rejected(self):
        # 0x3314a40 no longer calls the same 20-byte key reader; its pin rejects
        self._rejects(self._bump_rel32(self.data, 0x3314c50), '0x3314c4f')

    def test_item_call_rejected(self):
        self._rejects(self._bump_rel32(self.data, 0x329efe9), '0x329efe2')

    def test_locus_arm_call_rejected(self):
        self._rejects(self._bump_rel32(self.data, 0x332d074), '0x332d06d')

    def test_holder_rejected(self):
        saved = packet.HOLDERS
        packet.HOLDERS = {**saved, 0x2f6610d: packet.VALUE}
        try:
            with self.assertRaisesRegex(ValueError, 'not in function'):
                packet.bind(self.data)
        finally:
            packet.HOLDERS = saved


if __name__ == '__main__':
    unittest.main()
