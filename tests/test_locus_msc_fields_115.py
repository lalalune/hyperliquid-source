"""Node #115 Locus field names and box offsets. Mutations stay in a copied image."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import locus_msc_fields_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-locus-msc-fields-115/evidence.json'


class LocusFieldsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_table(self):
        fields = {f['name']: f['box_offset'] for f in self.result['fields']}
        self.assertEqual(fields['ctx'], '0x0')
        self.assertEqual(fields['chn'], '0xb9a')
        self.assertEqual(fields['msc'], '0xa38')
        self.assertEqual(self.result['layout']['end'], '0xb9b')
        self.assertEqual(self.result['matcher']['indices']['msc'], 15)
        self.assertEqual(self.result['sha256'], packet.SHA256)
        self.assertFalse(self.result['gates_changed'])

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

    def test_name_table_rejected(self):
        # ctx -> cty
        self._rejects(self._patch(packet.NAME_TABLE + 2, b'y'))

    def test_record_string_rejected(self):
        # 16 elements -> 17 elements
        self._rejects(self._patch(packet.RECORD_STR[0] + 19, b'7'))

    def test_matcher_name_rejected(self):
        # chn block byte immediate 'n' -> 'm'
        self._rejects(self._patch(packet.BLOCK0 + packet.BLOCK_LEN * 5 + 15, b'm'))

    def test_matcher_arm_rejected(self):
        # arm 'mov cl, 1' -> 'mov cl, 2'
        self._rejects(self._patch(0x5473180 + 1, b'\x02'))

    def test_matcher_length_rejected(self):
        # cmp rdx, 3 -> cmp rdx, 4
        self._rejects(self._patch(packet.MATCHER + 8, b'\x04'))

    def test_chn_offset_rejected(self):
        # mov byte [rbx+0xb9a], al -> [rbx+0xb9b]
        self._rejects(self._patch(0x2fc32ad + 2, b'\x9b'))

    def test_decode_call_rejected(self):
        # retarget the ctx decode call by one byte
        self._rejects(self._patch(0x2fc225c + 1, b'\x00'))

    def test_msc_default_rejected(self):
        # default 0.4 -> 0.5
        self._rejects(self._patch(packet.DEFAULT_F64[0], struct.pack('<d', 0.5)))


if __name__ == '__main__':
    unittest.main()
