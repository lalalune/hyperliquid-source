"""Node #115 simulate-panic stop checks and the writers of their fields. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import simulate_panic_height_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-simulate-panic-height-115/evidence.json'


class SimulatePanicHeightTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_check_sites(self):
        self.assertEqual([s['function'] for s in self.result['check_sites']],
                         ['0x2bdf270', '0x2c71eb0', '0x5483850', '0x5483f50', '0x5486720', '0x54897e0'])
        self.assertIn('simulate_panic.rs:10:13', self.result['panic']['location'])

    def test_store_census(self):
        stores = self.result['field_stores_non_stack']
        self.assertEqual(stores['0x39a8'], ['0x55f27c2'])
        self.assertEqual(stores['0x4518'], [])
        self.assertEqual(stores['0x4520'], [])
        self.assertEqual(stores['0xb9a'], ['0x2fc32ad'])
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

    def test_begin_selector_value_rejected(self):
        # cmp byte [r13+0xb9a], 3 -> 4
        self._rejects(self._patch(0x5483916 + 7, b'\x04'))

    def test_begin_b_stop_offset_rejected(self):
        # cmp rdx, [r13+0x4518] -> [r13+0x4510]
        self._rejects(self._patch(0x548400d + 3, b'\x10'))

    def test_quorum_entries_polarity_rejected(self):
        # je -> jne at 0x548bfd2
        self._rejects(self._patch(0x548bfd2, b'\x75'))

    def test_location_line_rejected(self):
        # simulate_panic.rs line 10 -> 11
        self._rejects(self._patch(packet.LOCATION + 16, b'\x0b'))

    def test_message_rejected(self):
        self._rejects(self._patch(packet.MESSAGE, b'E'))

    def test_clone_store_rejected(self):
        # mov [r14+0x39a8], rax -> [r14+0x39a0]
        self._rejects(self._patch(0x55f27c2 + 3, b'\xa0'))

    def test_extra_store_rejected(self):
        # turn the +0xb9a store into a +0x39b0-like byte store target offset change
        self._rejects(self._patch(0x2fc32ad + 2, b'\x9b'))

    def test_byte2_store_rejected(self):
        # mov byte [rbx+0x39b0], 2 -> 3
        self._rejects(self._patch(0x2addc04 + 6, b'\x03'))


if __name__ == '__main__':
    unittest.main()
