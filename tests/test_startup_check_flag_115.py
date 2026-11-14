"""Node #115 startup check flag source, .lz4 line-count branch, second caller. Mutations stay in a copy."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import startup_check_flag_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-startup-check-flag-115/evidence.json'


class StartupCheckFlagTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_bound(self):
        self.assertEqual(self.result['mode_writers'],
                         {'0x2ae4604': 2, '0x2ae5469': 1, '0x2cde6d0': 2, '0x2cdf567': 1})
        self.assertEqual(self.result['second_line_count_caller']['slot_calls'], [['0x2c7da78', '0x2c7d950']])
        self.assertEqual(self.result['lz4_branch']['state_dword_reads_in_text'], 572)
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

    def test_mode_value_rejected(self):
        # mov byte [rbx+0x248], 2 -> 3
        self._rejects(self._patch(0x2ae4604 + 6, b'\x03'))

    def test_entry_copy_offset_rejected(self):
        # movups [rbx+0x38] -> [rbx+0x40]
        self._rejects(self._patch(0x2aeaf69 + 3, b'\x40'))

    def test_handoff_offset_rejected(self):
        # movdqu xmm0, [rbx+0xb10] -> [rbx+0xb18]
        self._rejects(self._patch(0x2aebfb3 + 4, b'\x18'))

    def test_mode_two_test_rejected(self):
        # cmp dl, 2 -> cmp dl, 1
        self._rejects(self._patch(0x2af06d9 + 2, b'\x01'))

    def test_join_bit_rejected(self):
        # test byte [rbx], 1 -> 2
        self._rejects(self._patch(0x2b41bcd + 2, b'\x02'))

    def test_check_gate_rejected(self):
        # cmp r12b, 1 -> 2
        self._rejects(self._patch(0x2b41d32 + 3, b'\x02'))

    def test_lz4_suffix_rejected(self):
        # '.lz4' -> '.lz5'
        self._rejects(self._patch(0x1500e71 + 7, b'\x35'))

    def test_tolerance_string_rejected(self):
        # '.tolerance' -> '.toleranse'
        self._rejects(self._patch(0x4388e5 + 10, b's'))


if __name__ == '__main__':
    unittest.main()
