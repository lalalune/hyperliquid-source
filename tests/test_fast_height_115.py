"""Node #115 fast_height read and shared height counter. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import fast_height_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-fast-height-115/evidence.json'


class FastHeightTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_censuses(self):
        self.assertEqual(self.result['tracked_read']['direct_callers'], ['0x5a6c364'])
        self.assertEqual(self.result['read_body']['direct_callers'], ['0x4f1bace'])
        self.assertIn('engine.rs:262:17', self.result['wrappers']['mismatch'])
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

    def test_name_rejected(self):
        # fast_height -> fast_heighu
        self._rejects(self._patch(packet.NAME[0] + 10, b'u'))

    def test_clone_offset_rejected(self):
        # mov rax, [rbx+0xb08] -> [rbx+0xb10]
        self._rejects(self._patch(0x4fc174c + 3, b'\x10'))

    def test_replace_rejected(self):
        # mov [rsp+0x1668], r12 -> [rsp+0x1670]
        self._rejects(self._patch(0x5a6c3d6 + 4, b'\x70'))

    def test_builder_move_rejected(self):
        # mov [rsp+0x468], r15 -> [rsp+0x470]
        self._rejects(self._patch(0x5a08fd2 + 4, b'\x70'))

    def test_wrapper_tag_rejected(self):
        # cmp dword [r12], 2 -> 3
        self._rejects(self._patch(0x5a055f2 + 4, b'\x03'))

    def test_wrapper_increment_rejected(self):
        # lock inc [rcx+0x10] -> [rcx+0x18]
        self._rejects(self._patch(0x5a06e37 + 4, b'\x18'))

    def test_threshold_rejected(self):
        # 3.0 -> 3.5
        self._rejects(self._patch(packet.THRESHOLD + 6, b'\x0c'))

    def test_engine_location_rejected(self):
        # line 262 -> 263
        self._rejects(self._patch(packet.LOC_ENGINE + 16, b'\x07'))


if __name__ == '__main__':
    unittest.main()
