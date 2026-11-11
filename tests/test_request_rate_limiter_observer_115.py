"""Node #115 handle_request_rate_limiter observer. Mutations stay in a copied image."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import request_rate_limiter_observer_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-request-rate-limiter-observer-115/evidence.json'


class RequestRateLimiterObserverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_census(self):
        users = self.result['users']
        self.assertEqual(users['functions'], ['0x2e3ed10'])
        self.assertEqual(users['wrapper_calls'], ['0x2e3fd4b'])
        self.assertEqual(len(users['cell_slot_loads']), 3)
        self.assertEqual(self.result['sha256'], packet.SHA256)
        self.assertFalse(self.result['gates_changed'])

    def test_stride_model(self):
        self.assertEqual(self.result['wrapper']['stride_samples']['1999'], 1)
        self.assertEqual(self.result['wrapper']['stride_samples']['4000'], 2)
        self.assertEqual(self.result['wrapper']['stride_samples']['1000000000'], 500000)

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

    def test_window_limit_rejected(self):
        # observer +0x1f8 = 6000 -> 6001
        self._rejects(self._patch(0x2f19603 + 7, struct.pack('<I', 6001)))

    def test_stride_threshold_rejected(self):
        # cmp r15, 2000 -> 2001
        self._rejects(self._patch(0x15494ef + 3, b'\xd1'))

    def test_stride_magic_rejected(self):
        self._rejects(self._patch(0x15494ff + 2, b'\x7e'))

    def test_sample_predicate_rejected(self):
        # sete al -> setne al
        self._rejects(self._patch(0x1562293, b'\x0f\x95'))

    def test_count_argument_rejected(self):
        # mov rsi, r14 -> mov rsi, r15 (count = N instead of k)
        self._rejects(self._patch(0x1549538, b'\x4c\x89\xfe'))

    def test_new_stride_source_rejected(self):
        # mov r14, [rbx+0x20] -> [rbx+0x28] (calls instead of count sum)
        self._rejects(self._patch(0x1549545 + 3, b'\x28'))

    def test_rollover_flag_rejected(self):
        # mov qword [rbx+0x10], 1 -> 0
        self._rejects(self._patch(0x1547bf2 + 4, b'\x00'))

    def test_cell_state_rejected(self):
        # cell state dword 3 -> 0
        self._rejects(self._patch(packet.CELL + 0x270, b'\x00'))

    def test_name_rejected(self):
        self._rejects(self._patch(packet.NAME[0], b'H'))


if __name__ == '__main__':
    unittest.main()
