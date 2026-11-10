"""Node #115 abci box height advance. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import height_advance_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-height-advance-115/evidence.json'


class HeightAdvanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_census(self):
        self.assertEqual(self.result['height_advance_runs'], ['0x54838d3', '0x5483fd3'])
        self.assertEqual(self.result['layouts']['A']['called_once_from'], '0x5a04fe9 in wrapper 0x5a04e40')
        self.assertEqual(self.result['layouts']['B']['called_once_from'], '0x5a067ad in wrapper 0x5a06600')
        self.assertEqual(self.result['panic']['location'], 'l1/src/simulate_panic.rs:10:13')
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

    def test_inc_rejected(self):
        # inc rsi -> dec rsi (A)
        self._rejects(self._patch(0x54838d7 + 2, b'\xce'))

    def test_store_offset_rejected(self):
        # mov [r13+0x28], rdx -> [r13+0x20] (B)
        self._rejects(self._patch(0x5483fe5 + 3, b'\x20'))

    def test_saturation_rejected(self):
        # cmovne -> cmove (A)
        self._rejects(self._patch(0x54838e1 + 2, b'\x44'))

    def test_wrapper_call_rejected(self):
        # retarget the wrapper A call by one byte
        self._rejects(self._patch(0x5a04fe9 + 1, b'\x63'))

    def test_stop_flag_rejected(self):
        # test byte [r13+0x39b0], 1 -> 2
        self._rejects(self._patch(0x5483903 + 7, b'\x02'))

    def test_stop_byte_rejected(self):
        # cmp byte [r13+0x170a], 3 -> 4
        self._rejects(self._patch(0x5484016 + 7, b'\x04'))

    def test_panic_message_rejected(self):
        self._rejects(self._patch(0x7db393, b'E'))

    def test_begin_block_call_rejected(self):
        # call 0x54a9c70 -> next byte
        self._rejects(self._patch(0x5484194 + 1, b'\xd8'))


if __name__ == '__main__':
    unittest.main()
