"""Node #115 step-wrapper quorum entry origin. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import digest_quorum_entries_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-digest-quorum-entries-115/evidence.json'


class DigestQuorumEntriesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_censuses(self):
        calls = self.result['calls']
        self.assertEqual(calls['produce_a'], ['0x5a055b0'])
        self.assertEqual(calls['produce_b'], ['0x5a06db6'])
        self.assertEqual(calls['take'], ['0x5488dd2', '0x548bf13'])
        self.assertEqual(calls['insert'], ['0x54ca888', '0x54cb058'])
        self.assertEqual(self.result['entry']['size'], '0x68')
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

    def test_slice_pointer_slot_rejected(self):
        # mov rsi, [rsp+0x180] -> [rsp+0x188]
        self._rejects(self._patch(0x5a05671 + 4, b'\x88'))

    def test_entry_stride_rejected(self):
        # imul rdi, rbx, 0x68 -> 0x60
        self._rejects(self._patch(0x5a05686 + 3, b'\x60'))

    def test_store_offset_rejected(self):
        # lea rsi, [r12+0x3d98] -> +0x3d90
        self._rejects(self._patch(0x548beed + 4, b'\x90'))

    def test_result_pointer_field_rejected(self):
        # mov [rax+0x20], rdx -> [rax+0x18]
        self._rejects(self._patch(0x548c22d + 3, b'\x18'))

    def test_threshold_rejected(self):
        # sub rax, 1000 -> 1001
        self._rejects(self._patch(0x5afa20e + 2, b'\xe9'))

    def test_filter_field_rejected(self):
        # cmp qword [rbp-0x68], 0 -> [rbp-0x60]
        self._rejects(self._patch(0x5afa2b0 + 3, b'\xa0'))

    def test_producer_store_rejected(self):
        # lea rdi, [rbp+0x3d98] -> +0x3da0
        self._rejects(self._patch(0x54cb042 + 3, b'\xa0'))

    def test_take_call_retarget_rejected(self):
        # call 0x5afa1f0 at 0x548bf13 retargeted by one byte
        self._rejects(self._patch(0x548bf13 + 1, b'\xd9'))


if __name__ == '__main__':
    unittest.main()
