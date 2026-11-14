"""Node #115 non-validator catch-up poll. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import nonvalidator_catchup_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-nonvalidator-catchup-115/evidence.json'


class NonvalidatorCatchupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_shape(self):
        self.assertEqual(self.result['sha256'], packet.SHA256)
        self.assertIn('counter >= 6', self.result['caught_up']['requires'])
        self.assertIn('% 10 == 0', self.result['not_caught_up_log']['when'])
        self.assertFalse(self.result['gates_changed'])

    def test_committed_packet_matches(self):
        self.assertEqual(packet.render(self.result), PACKET.read_bytes())
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(packet.main(['--out', tmp, '--check']), 0)

    def _patch(self, va, new):
        broken = bytearray(self.data)
        sec = next(s for s in sections(self.data)
                   if s['type'] != 8 and s['address'] <= va < s['address'] + s['size'])
        off = sec['offset'] + va - sec['address']
        broken[off:off + len(new)] = new
        return bytes(broken)

    def _rejects(self, data):
        with self.assertRaises(ValueError):
            packet.bind(data, self.fdes)

    def test_block_threshold_rejected(self):
        # cmp rax, 6 -> cmp rax, 7
        self._rejects(self._patch(0x2b1e652 + 3, b'\x07'))

    def test_lag_seconds_rejected(self):
        # mov edx, 2 -> 3
        self._rejects(self._patch(0x2b1e682 + 1, b'\x03'))

    def test_lag_nanos_rejected(self):
        # 500000000 -> 500000001
        self._rejects(self._patch(0x2b1e692 + 1, b'\x01'))

    def test_date_compare_rejected(self):
        # setg -> setge
        self._rejects(self._patch(0x2b1e74a + 1, b'\x9d'))

    def test_fraction_compare_rejected(self):
        # jbe -> jb (caught up on equal time)
        self._rejects(self._patch(0x2b1e795, b'\x72'))

    def test_log_period_rejected(self):
        # % 10 divisor constant changed
        self._rejects(self._patch(0x2b1e7ba + 2, b'\x9b'))

    def test_saturation_rejected(self):
        # cmove -> cmovne
        self._rejects(self._patch(0x2b1e605 + 2, b'\x45'))

    def test_message_rejected(self):
        # change one byte of the not-caught-up message
        self._rejects(self._patch(0x606039 + 34, b'P'))


if __name__ == '__main__':
    unittest.main()
