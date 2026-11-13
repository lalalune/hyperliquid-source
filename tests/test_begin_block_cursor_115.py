"""Node #115 begin_block A cursor loop. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import begin_block_cursor_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-begin-block-cursor-115/evidence.json'


class BeginBlockCursorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_shape(self):
        self.assertEqual(self.result['function'], '0x54b66b0')
        self.assertEqual(self.result['call_census'], {'0x4dcdfc0': 2, '0x4dce210': 2, '0x5582180': 4})
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

    def test_limit_field_rejected(self):
        # mov rax, [rax+0x4270] -> [rax+0x4278]
        self._rejects(self._patch(0x54bff42 + 3, b'\x78'))

    def test_cursor_tag_rejected(self):
        # cmp byte [r15+0x42b0], 1 -> 2
        self._rejects(self._patch(0x54bfe17 + 7, b'\x02'))

    def test_map_offset_rejected(self):
        # lea rbx, [r15+0x6f8] -> +0x6f0
        self._rejects(self._patch(0x54bfe09 + 3, b'\xf0'))

    def test_decrement_rejected(self):
        # dec rax -> inc rax
        self._rejects(self._patch(0x54c0013 + 2, b'\xc0'))

    def test_record_kind_rejected(self):
        # cmp byte [r13+0x3c], 4 -> 5
        self._rejects(self._patch(0x54c00ef + 4, b'\x05'))

    def test_wrap_compare_rejected(self):
        # jg -> jge
        self._rejects(self._patch(0x54c029a, b'\x7d'))

    def test_key_width_rejected(self):
        # mov edx, 20 -> 21
        self._rejects(self._patch(0x54c028a + 1, b'\x15'))

    def test_per_key_call_rejected(self):
        # call 0x5582180 retargeted by one
        self._rejects(self._patch(0x54c0345 + 1, b'\x37'))


if __name__ == '__main__':
    unittest.main()
