"""Node #115 position field l as enum Leverage. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import position_l_field_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-position-l-field-115/evidence.json'


class PositionLFieldTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_censuses(self):
        self.assertEqual(self.result['name_lists'], {'0x6483c28': ['l', 'leverage', 'raw_usd', 'u'],
                                                     '0x6483c68': ['C', 'Cross', 'I', 'Isolated']})
        self.assertEqual(self.result['reference_census']['I'], ['0x4209b80', '0x420a0d0'])
        self.assertEqual(self.result['reference_census']['u'], ['0x4209b80', '0x420a0d0'])
        self.assertEqual(self.result['callers']['0x420a0d0'], [{'call': '0x448afdc', 'function': '0x448ae20'}])
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

    def test_json_tag_rejected(self):
        # cmp dword [rdi], 1 -> 2
        self._rejects(self._patch(0x420a0e5 + 2, b'\x02'))

    def test_json_l_offset_rejected(self):
        # lea rcx, [r15+4] -> [r15+8]
        self._rejects(self._patch(0x420a2fd + 3, b'\x08'))

    def test_json_u_offset_rejected(self):
        # mov rsi, [r15+8] -> [r15+0x10]
        self._rejects(self._patch(0x420a36a + 3, b'\x10'))

    def test_pack_c_value_rejected(self):
        # mov edx, [r15+4] -> [r15+8]
        self._rejects(self._patch(0x4209c4e + 3, b'\x08'))

    def test_key_string_rejected(self):
        # "I" -> "J"
        self._rejects(self._patch(0x7c84d3, b'J'))

    def test_variant_name_rejected(self):
        # "Isolated" -> "Jsolated"
        self._rejects(self._patch(0x459480, b'J'))

    def test_list_length_rejected(self):
        # name list length 4 -> 5
        self._rejects(self._patch(0x420ab71 + 1, b'\x05'))

    def test_caller_rejected(self):
        # call 0x420a0d0 -> call 0x420a0d1
        self._rejects(self._patch(0x448afdc + 1, b'\xf0'))

    def test_expecting_user_rejected(self):
        # one "enum Leverage" lea moves by one byte
        self._rejects(self._patch(0x25eb59b + 3, b'\x7b'))


if __name__ == '__main__':
    unittest.main()
