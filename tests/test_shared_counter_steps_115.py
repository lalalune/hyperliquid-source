"""Node #115 shared height counter: which engine values check it. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import shared_counter_steps_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-shared-counter-steps-115/evidence.json'


class SharedCounterStepsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_censuses(self):
        self.assertEqual(self.result['callers'], {
            '0x56185e0': ['0x54439ad', '0x59ec2a8'], '0x56186c0': ['0x4fcb795'],
            '0x59ec200': ['0x4fcae48'], '0x5a04e40': ['0x5618630'], '0x5a06600': ['0x5618710']})
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

    def test_slow_tag_zero_rejected(self):
        # mov qword [rsp+0x1240], 0 -> 2
        self._rejects(self._patch(0x5a6c52f + 8, b'\x02'))

    def test_fast_tag_rejected(self):
        # mov qword [rsp+0xe20], 2 -> 0
        self._rejects(self._patch(0x5a6c0e0 + 8, b'\x00'))

    def test_wrapper_a_tag_value_rejected(self):
        # cmp dword [r12], 2 -> 3
        self._rejects(self._patch(0x5a055f2 + 4, b'\x03'))

    def test_wrapper_b_increment_rejected(self):
        # lock inc -> lock dec
        self._rejects(self._patch(0x5a06e37 + 3, b'\x49'))

    def test_arc_clone_rejected(self):
        # lock inc [rax] -> lock dec [rax]
        self._rejects(self._patch(0x4fc1753 + 3, b'\x08'))

    def test_clone_store_rejected(self):
        # mov [rsp+0x1668], r12 -> [rsp+0x1670]
        self._rejects(self._patch(0x5a6c3d6 + 4, b'\x70'))

    def test_fill_tag_test_rejected(self):
        # cmp dword [rsi], 2 -> 1
        self._rejects(self._patch(0x38c65aa + 2, b'\x01'))

    def test_runner_flag_offset_rejected(self):
        # movzx eax, byte [r14+0xb20] -> +0xb40
        self._rejects(self._patch(0x4fcb5b0 + 4, b'\x40'))


if __name__ == '__main__':
    unittest.main()
