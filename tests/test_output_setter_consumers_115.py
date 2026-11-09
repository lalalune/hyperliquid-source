"""Node #115 output setter result path and second parent future. Mutations stay in a copied image."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import output_setter_consumers_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-output-setter-consumers-115/evidence.json'


class OutputSetterConsumersTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_result_lands_in_box(self):
        path = self.result['result_path']
        self.assertEqual(path['setter_offsets_in_box'], {'first': '0x12a0', 'second': '0x12d8'})
        self.assertIn('0x548ce30', path['in_0x5a6bfb0'])
        self.assertEqual(self.result['sha256'], packet.SHA256)
        self.assertFalse(self.result['gates_changed'])

    def test_parent_cases(self):
        parent = self.result['parent_0x2cde430']
        self.assertEqual(parent['cases'], {'2': '0x2cde67c', '3': '0x2cdf519'})
        self.assertIn('0x2cb6500', parent['per_case'])

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

    def test_handoff_size_rejected(self):
        # mov edx, 0xb70 -> 0xb78 in poller 0x2aeaef0
        self._rejects(self._patch(0x2aec3d2 + 1, b'\x78'))

    def test_handoff_slot_rejected(self):
        # call [slot 0x64e7440] -> [slot 0x64e7448]
        self._rejects(self._patch(0x2aec3ef + 2, struct.pack('<i', 0x64e7448 - (0x2aec3ef + 6))))

    def test_block_offset_rejected(self):
        # lea rdi, [rsp+0x7e0] -> [rsp+0x7e8]
        self._rejects(self._patch(0x548d6f5 + 4, b'\xe8'))

    def test_box_size_rejected(self):
        # mov edi, 0x4e38 -> 0x4e40
        self._rejects(self._patch(0x548d82f + 1, b'\x40'))

    def test_mode_byte_rejected(self):
        # mov byte [r13+0x248], 2 -> 3
        self._rejects(self._patch(0x2cde6d0 + 7, b'\x03'))

    def test_switch_entry_rejected(self):
        # table entry for tag 3 moved by 1
        entry = struct.unpack('<i', packet.read_va(self.data, packet.TABLE + 4, 4))[0]
        self._rejects(self._patch(packet.TABLE + 4, struct.pack('<i', entry + 1)))

    def test_error_tag_rejected(self):
        # mov qword [rbx], 0x10 -> 0x11
        self._rejects(self._patch(0x2b7b6f2 + 3, b'\x11'))

    def test_matcher_tag_rejected(self):
        # mov qword [rbx], 3 -> 4
        self._rejects(self._patch(0x56551ef + 3, b'\x04'))


if __name__ == '__main__':
    unittest.main()
