"""Node #115 per-user value: serde name sources. Mutations stay in a copied image."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
import user_value_names_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-user-value-names-115/evidence.json'


class UserValueNamesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        cls.result = packet.bind(cls.data)

    def test_visitors_match_only_one_byte_keys(self):
        sites = self.result['field_visitors']['dispatch_sites']
        self.assertEqual(len(sites), 11)
        for row in sites.values():
            self.assertEqual(row['letters'], 'DSlpru')
        indexed = [row['index'] for row in sites.values() if 'index' in row]
        self.assertEqual(len(indexed), 6)
        for index in indexed:
            self.assertEqual(index, {'u': 0, 'p': 1, 'D': 2, 'l': 3, 'S': 4, 'r': 5})

    def test_no_long_names(self):
        self.assertEqual(self.result['fields_arrays']['six_key_windows'], [])
        self.assertIn('0x6483c28', self.result['fields_arrays']['control_windows'])
        self.assertEqual(sorted(self.result['duplicate_field']['names'].values()), sorted('upDlSr'))
        self.assertEqual(self.result['long_names_pinned'], {})
        self.assertEqual(len(self.result['six_element_struct_descriptors']), 19)
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
            packet.bind(data)

    def test_length_guard_rejected(self):
        # cmp r12d, 1 -> cmp r12d, 2 (a two-byte key arm)
        self._rejects(self._patch(0x1a21c5c + 3, b'\x02'))

    def test_length_miss_rejected(self):
        # jne after the length guard moved by one byte
        raw = self.data
        sec = next(s for s in sections(raw) if s['address'] <= 0x1a21c62 < s['address'] + s['size'])
        off = sec['offset'] + 0x1a21c62 - sec['address']
        value = struct.unpack_from('<i', raw, off)[0] + 1
        self._rejects(self._patch(0x1a21c62, struct.pack('<i', value)))

    def test_bound_rejected(self):
        # cmp ecx, 0x31 -> 0x32
        self._rejects(self._patch(0x1a21c6d + 2, b'\x32'))

    def test_letter_arm_rejected(self):
        # the 'u' entry of table 0x522718 sent to the default target
        raw = self.data
        sec = next(s for s in sections(raw) if s['address'] <= 0x522718 < s['address'] + s['size'])
        off = sec['offset'] + 0x522718 - sec['address']
        default = struct.unpack_from('<i', raw, off + 4 * 1)[0]          # 'E' is not a key
        self._rejects(self._patch(0x522718 + 4 * 0x31, struct.pack('<i', default)))

    def test_field_index_rejected(self):
        # the 'p' arm: mov al, 1 -> mov al, 7
        self._rejects(self._patch(0x1a21fc4 + 1, b'\x07'))

    def test_duplicate_name_length_rejected(self):
        # duplicate_field("S"): length 1 -> 2
        self._rejects(self._patch(0x1a22e1f + 16, b'\x02'))

    def test_duplicate_template_rejected(self):
        # duplicate field -> duplicate fielD
        self._rejects(self._patch(packet.DUPLICATE_TEMPLATE + 15, b'D'))

    def test_control_table_rejected(self):
        # leverage length 8 -> 9 in the control table
        self._rejects(self._patch(0x6483c40, struct.pack('<Q', 9)))


if __name__ == '__main__':
    unittest.main()
