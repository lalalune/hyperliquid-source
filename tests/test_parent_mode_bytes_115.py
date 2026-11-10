"""Node #115 parent mode bytes and the 60 s line-count loop. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item  # noqa: E402
from elf_index import sections  # noqa: E402
from fde_extents import fde_extents  # noqa: E402
import parent_mode_bytes_115 as packet  # noqa: E402

PACKET = ROOT / 'research/work-items/RE-008-parent-mode-bytes-115/evidence.json'


class ParentModeBytesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_mode_stores_and_pollers(self):
        parents = self.result['parents']
        self.assertEqual(parents['0x2ae41e0']['mode_byte_stores'], {'0x2ae4604': 2, '0x2ae5469': 1})
        self.assertEqual(parents['0x2cde430']['mode_byte_stores'], {'0x2cde6d0': 2, '0x2cdf567': 1})
        self.assertEqual(parents['0x2ae41e0']['stores_to_0x249'], 0)
        self.assertEqual(len(parents['0x2cde430']['other_0x248_stores']), 6)
        self.assertEqual(self.result['pollers']['0x2aeaef0']['direct_calls'], ['0x2ae4627', '0x2ae548c'])
        self.assertEqual(self.result['line_count_loop']['callers'], ['0x2c7bb81'])
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
        # tag-2 mode store 2 -> 0
        self._rejects(self._patch(0x2ae4604 + 6, b'\x00'))

    def test_new_0x249_store_rejected(self):
        # 16-byte store at +0x248 -> +0x249
        self._rejects(self._patch(0x2ae5249 + 3, b'\x49'))

    def test_poller_call_rejected(self):
        # call 0x2aeaef0 -> one byte further
        self._rejects(self._patch(0x2ae4627 + 1, b'\xc5'))

    def test_poller_copy_rejected(self):
        # movups [rbx+0x38] -> [rbx+0x40]
        self._rejects(self._patch(0x2aeaf69 + 3, b'\x40'))

    def test_sleep_seconds_rejected(self):
        # r15d = 60 -> 61
        self._rejects(self._patch(0x2c7d980 + 2, b'\x3d'))

    def test_clock_rejected(self):
        # CLOCK_MONOTONIC (1) -> CLOCK_REALTIME (0)
        self._rejects(self._patch(0x2c7d9b9 + 1, b'\x00'))

    def test_eintr_rejected(self):
        # cmp eax, 4 -> cmp eax, 5
        self._rejects(self._patch(0x2c7d9d1 + 2, b'\x05'))

    def test_zero_block_rejected(self):
        self._rejects(self._patch(packet.ZERO_BLOCK, b'\x01'))


if __name__ == '__main__':
    unittest.main()
