"""Node #115 slow abci driver thread-pool step. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import slow_abci_apply_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-slow-abci-apply-115/evidence.json'


class SlowAbciApplyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_shape(self):
        self.assertEqual(self.result['outer_map']['item_size'], '0x28 (0x3ec1bd3)')
        self.assertEqual(self.result['inner_map']['input_size'], '0x168 (0x3ebdd63)')
        self.assertEqual(self.result['inner_map']['action_map_slot_calls'], 21)
        self.assertEqual(len(self.result['threshold_census']), 10)
        self.assertEqual(self.result['sha256'], packet.SHA256)
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

    def test_pool_offset_rejected(self):
        # [rax+0xb58] -> [rax+0xb60]
        self._rejects(self._patch(0x5a34e26 + 3, b'\x60'))

    def test_worker_registry_rejected(self):
        # [rdx+0x110] -> [rdx+0x118]
        self._rejects(self._patch(0x59edc70 + 3, b'\x18'))

    def test_item_size_rejected(self):
        # lea rsi, [r14+r14*4] -> [r14+r14*2]
        self._rejects(self._patch(0x3ec1bd3 + 3, b'\x76'))

    def test_item_pointer_rejected(self):
        # [rbx+0x20] -> [rbx+0x28]
        self._rejects(self._patch(0x3713594 + 3, b'\x28'))

    def test_action_size_rejected(self):
        # imul 0x168 -> 0x170
        self._rejects(self._patch(0x3ebdd63 + 3, b'\x70'))

    def test_stop_tag_rejected(self):
        # cmp word 0x1a3 -> 0x1a4
        self._rejects(self._patch(0x37133b8 + 5, b'\xa4'))

    def test_step_name_rejected(self):
        # spawn_slow... -> spawn_slOw...
        self._rejects(self._patch(packet.NAME[0] + 8, b'O'))

    def test_threshold_census_rejected(self):
        # turn the fold's first push into movsd xmm0, [rip+0] inside 0x59edc50
        self._rejects(self._patch(0x59edcac, b'\xf2\x0f\x10\x05\x00\x00\x00\x00'))


if __name__ == '__main__':
    unittest.main()
