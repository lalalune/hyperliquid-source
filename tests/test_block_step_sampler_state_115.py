"""Node #115 block-step sampler state and 15-second gate. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import block_step_sampler_state_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-block-step-sampler-state-115/evidence.json'


class BlockStepSamplerStateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_census(self):
        samplers = self.result['samplers']
        self.assertEqual(samplers['0x5b298d0']['direct_calls'], 18)
        self.assertEqual(samplers['0x5b298d0']['caller_frames'], ['0x54a9c70'])
        self.assertEqual(samplers['0x5b2a130']['direct_calls'], 5)
        self.assertEqual(samplers['0x5b2a130']['caller_frames'], ['0x54864a0', '0x5a06600'])
        self.assertIn('group_and_seq_sampler.rs:169:10', samplers['shared']['observer'])
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

    def test_interval_rejected(self):
        # movabs rax, 15.0 -> 16.0 (0x4030000000000000)
        self._rejects(self._patch(0x51d0874 + 8, b'\x30'))

    def test_gate_offset_a_rejected(self):
        # sampler A lea rdi, [rbx+0x20] -> [rbx+0x28]
        self._rejects(self._patch(0x5b29a03 + 3, b'\x28'))

    def test_gate_offset_b_rejected(self):
        # sampler B lea rdi, [rbx+0x20] -> [rbx+0x28]
        self._rejects(self._patch(0x5b2a263 + 3, b'\x28'))

    def test_gate_exit_rejected(self):
        # je -> jne at the gate result in sampler B
        self._rejects(self._patch(0x5b2a272 + 1, b'\x85'))

    def test_ring_stride_rejected(self):
        # lea rcx, [rax+0x268] -> [rax+0x260]
        self._rejects(self._patch(0x5b2a3b7 + 3, b'\x60'))

    def test_second_value_offset_rejected(self):
        # cmp [rbx+0x12d8], rax -> [rbx+0x12a0]
        self._rejects(self._patch(0x54ab455 + 3, b'\xa0'))

    def test_location_line_rejected(self):
        # group_and_seq_sampler.rs:169 -> 170
        self._rejects(self._patch(packet.LOCATION + 16, b'\xaa'))

    def test_setter_branch_rejected(self):
        # je 0x51d08bc -> jne (None when set)
        self._rejects(self._patch(0x51d085b, b'\x75'))


if __name__ == '__main__':
    unittest.main()
