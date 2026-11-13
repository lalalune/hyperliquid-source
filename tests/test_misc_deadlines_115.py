"""Node #115 pmc update in begin_block A and the tce range check. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import misc_deadlines_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-misc-deadlines-115/evidence.json'


class MiscDeadlinesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_range_model(self):
        self.assertFalse(packet.in_range(4))
        self.assertTrue(packet.in_range(5))
        self.assertTrue(packet.in_range(10080))
        self.assertFalse(packet.in_range(10081))
        self.assertIn('5..=10080', self.result['tce_handler']['range'])
        self.assertEqual(self.result['sha256'], packet.SHA256)

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

    def test_reset_value_rejected(self):
        # 0xf6401a -> 0xf6401b
        self._rejects(self._patch(0x54bfe47 + 7, b'\x1b'))

    def test_reset_gate_rejected(self):
        # cmp qword [r15+0x710] -> [r15+0x718]
        self._rejects(self._patch(0x54bfdff + 3, b'\x18'))

    def test_seconds_constant_rejected(self):
        # 600.0 -> 601.0
        self._rejects(self._patch(0x459568 + 5, b'\xc8'))

    def test_store_condition_rejected(self):
        # jg -> jge
        self._rejects(self._patch(0x54c029a, b'\x7d'))

    def test_cursor_length_rejected(self):
        # memcmp length 20 -> 21
        self._rejects(self._patch(0x54c028a + 1, b'\x15'))

    def test_range_upper_rejected(self):
        # lea r8, [rax-0x2761] -> [rax-0x2762]
        self._rejects(self._patch(0x57c9f7e + 3, b'\x9e'))

    def test_error_tag_rejected(self):
        # 0xd1 -> 0xd2
        self._rejects(self._patch(0x57c9f8e + 3, b'\xd2'))

    def test_index_stride_rejected(self):
        # imul r14, r12, 0x510 -> 0x511
        self._rejects(self._patch(0x57ca000 + 3, b'\x11'))


if __name__ == '__main__':
    unittest.main()
