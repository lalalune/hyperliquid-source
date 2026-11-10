"""Node #115 per-user value D decoder. Mutations stay in a copied image."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
import user_value_d_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-user-value-d-115/evidence.json'


class UserValueDTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        cls.result = packet.bind(cls.data)

    def test_d_is_a_date_keyed_map(self):
        self.assertEqual({v['text'] for v in self.result['strings'].values()},
                         {'Date', 'duplicate key', 'a', 'c'})
        self.assertEqual({k: v['path'] for k, v in self.result['markers'].items()},
                         {'0xdc': 'array', '0xdd': 'array', '0xde': 'map', '0xdf': 'map'})
        entry = self.result['entry']
        self.assertEqual(entry['entry_size'], '0x18')
        self.assertEqual((entry['map_form']['a'], entry['map_form']['c']), ('0x8', '0x10'))
        self.assertEqual(self.result['collector']['duplicate_key']['tag'], '0x8000000000000001')
        self.assertEqual(self.result['collector']['small_form_max_entries'], '0x40')

    def test_value_keys_one_byte_only(self):
        keys = self.result['keys']
        self.assertEqual(keys['value_decoder_key_index'], {'a': 0, 'c': 1, 'other': 2})
        self.assertEqual(keys['long_key_names'], [])
        self.assertTrue(all(n == 0 for n in keys['pcmpeqb_rip_sites'].values()))
        self.assertFalse(self.result['gates_changed'])

    def test_committed_packet_matches(self):
        self.assertEqual(packet.render(self.result), PACKET.read_bytes())
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(packet.main(['--out', tmp, '--check']), 0)

    def _off(self, va):
        sec = next(s for s in sections(self.data)
                   if s['type'] != 8 and s['address'] <= va < s['address'] + s['size'])
        return sec['offset'] + va - sec['address']

    def _patch(self, va, new):
        off = self._off(va)
        broken = bytearray(self.data)
        broken[off:off + len(new)] = new
        return bytes(broken)

    def _rejects(self, data, *drop):
        saved = packet.PINS
        packet.PINS = {k: v for k, v in saved.items() if k not in drop}
        try:
            with self.assertRaises(ValueError):
                packet.bind(data)
        finally:
            packet.PINS = saved

    def test_value_key_letter_rejected(self):
        # cmp al,'a' -> cmp al,'b' on the string-key path
        self._rejects(self._patch(0x1be17dc, b'b'), 0x1be17af)

    def test_long_compare_rejected(self):
        # a 16-byte constant compare placed in unpinned value-decoder bytes
        self._rejects(self._patch(0x1be1657, b'\x66\x0f\x74\x05'))

    def test_length_guard_rejected(self):
        # byte-key path: cmp rdx,1 -> cmp rdx,0x10
        self._rejects(self._patch(0x1be1869, b'\x10'), 0x1be1866)

    def test_key_name_rejected(self):
        # `Date` -> `Datf`
        self._rejects(self._patch(0x459fd3, b'f'))

    def test_marker_table_rejected(self):
        # map16 marker given the array16 arm
        dc = self.data[self._off(packet.MARKER_TABLE + 4 * 0xdc):][:4]
        self._rejects(self._patch(packet.MARKER_TABLE + 4 * 0xde, dc))

    def test_entry_value_offset_rejected(self):
        # map entry value store at +0x8 -> +0x10
        self._rejects(self._patch(0x27a9675, b'\x10'), 0x27a9660)

    def test_small_limit_rejected(self):
        # 0x40-entry limit -> 0x41
        self._rejects(self._patch(0x2dac9de, b'\x41'), 0x2dac9db)

    def test_lea_target_rejected(self):
        # unpinned error-object lea in the D decoder moved by one byte
        rel = struct.unpack_from('<i', self.data, self._off(0x18d52b5 + 3))[0] + 1
        self._rejects(self._patch(0x18d52b5 + 3, struct.pack('<i', rel)))

    def test_seq_key_decoder_call_rejected(self):
        # array element key call target moved by one byte
        rel = struct.unpack_from('<i', self.data, self._off(0x1bd5c8f + 1))[0] + 1
        self._rejects(self._patch(0x1bd5c8f + 1, struct.pack('<i', rel)), 0x1bd5c7b)


if __name__ == '__main__':
    unittest.main()
