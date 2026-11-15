"""Node #115 per-user value field l. Mutations stay in a copied image."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
import user_value_l_time_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-user-value-l-time-115/evidence.json'


class UserValueLTimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        cls.result = packet.bind(cls.data)

    def test_l_is_formatted_date_time(self):
        self.assertEqual(self.result['expected_text'], 'a formatted date and time string')
        self.assertEqual(self.result['newtype_name'], 'Time')
        self.assertEqual(self.result['f32']['unexpected_tag'], 3)
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

    def test_first_caller_rejected(self):
        self._rejects(self._bump_rel32(self.data, 0x1a221f1), 'call at 0x1a221f0')

    def test_name_length_rejected(self):
        self._rejects(self._patch(self.data, 0x30bd6b9, b'\x05'), 'name length at 0x30bd6b8')

    def test_time_string_rejected(self):
        self._rejects(self._patch(self.data, packet.NAME_TIME, b'Tame'), 'is not Time')

    def test_extstruct_name_rejected(self):
        # '_ExtStru' -> '_FxtStru' in the second decoder only
        self._rejects(self._patch(self.data, packet.SECOND_L + 0x19, b'F'), "_ExtStru")

    def test_slot_rejected(self):
        self._rejects(self._bump_rel32(self.data, packet.FIRST_L + 0x152, 8),
                      'value read is not through slot')

    def test_table_entry_rejected(self):
        entry = packet.TABLE + 4 * (0xca - 0xc0)
        self._rejects(self._bump_rel32(self.data, entry), 'table entry for 0xca')

    def test_float_tag_rejected(self):
        self._rejects(self._patch(self.data, 0x155d7f6, b'\x02'), 'unexpected float')

    def test_expected_text_rejected(self):
        self._rejects(self._patch(self.data, packet.EXPECTED_TEXT + 2, b'F'),
                      'not the expected text')

    def test_text_length_rejected(self):
        self._rejects(self._patch(self.data, 0x1560963, b'\x1f'), 'length 0x20')


if __name__ == '__main__':
    unittest.main()
