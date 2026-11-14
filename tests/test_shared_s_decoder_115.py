"""Node #115 shared S decoder 0x31c32d0. Mutations stay in a copied image."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
import shared_s_decoder_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-shared-s-decoder-115/evidence.json'


class SharedSDecoderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        cls.result = packet.bind(cls.data)

    def test_s_is_struct_of_s_r(self):
        fields = self.result['fields']
        self.assertEqual([fields[str(i)]['key'] for i in range(2)], ['s', 'r'])
        self.assertEqual(self.result['missing_field'], 'set to 0, not an error')
        self.assertIsNone(self.result['shape']['struct_name_record'])
        self.assertEqual(self.result['same_layout_as']['pr'], '#6239')
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
        self._rejects(self._bump_rel32(self.data, 0x32093fc), 'branch at 0x32093fb')

    def test_marker_compare_rejected(self):
        self._rejects(self._patch(self.data, 0x31c332b, b'\x91'), 'fixmap below')

    def test_key_length_rejected(self):
        # cmp rdx,1 -> cmp rdx,2
        self._rejects(self._patch(self.data, 0x31c3889, b'\x02'), 'length 1')

    def test_key_byte_rejected(self):
        # cmp al,'s' -> 't'
        self._rejects(self._patch(self.data, 0x31c3899, b't'), "compared with 's'")

    def test_slot_call_rejected(self):
        self._rejects(self._bump_rel32(self.data, 0x31c3a7d), 'call at 0x31c3a7b')

    def test_duplicate_name_rejected(self):
        # name 's' -> 't'
        self._rejects(self._patch(self.data, packet.NAME_S, b't'), 'string at 0x793170')

    def test_default_rejected(self):
        # cmove -> cmovne for field r
        self._rejects(self._patch(self.data, 0x31c3ff4, b'\x45'), 'r is 0 when not seen')

    def test_twin_bytes_rejected(self):
        # change the first S decoder's 'r' compare; the decoder's own pins stay intact
        self._rejects(self._patch(self.data, packet.FIRST_S + 0x523, b'q'),
                      'offset 0x522 differ')

    def test_twin_slot_rejected(self):
        self._rejects(self._bump_rel32(self.data, packet.FIRST_S + 0x75c),
                      f'call at {packet.FIRST_S + 0x75a:#x}')

    def test_holder_rejected(self):
        saved = packet.PINS
        packet.PINS = dict(saved)
        packet.PINS[0x1adfb42] = ('3c72', 'misplaced pin')
        try:
            with self.assertRaisesRegex(ValueError, 'not in function'):
                packet.holders(self.data)
        finally:
            packet.PINS = saved


if __name__ == '__main__':
    unittest.main()
