"""Node #115 block-step sampler items and per-item walk. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import block_step_sampler_items_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-block-step-sampler-items-115/evidence.json'


class BlockStepSamplerItemsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_census(self):
        census = self.result['census']
        for target in ('0x4dc50c0', '0x4dc2420', '0x4da4e80'):
            self.assertEqual(census[target], {'direct_calls': 1, 'caller_frames': ['0x5b2a130']})
        self.assertEqual(census['0x5b926e0']['direct_calls'], 2)
        self.assertEqual(self.result['sha256'], packet.SHA256)
        self.assertFalse(self.result['gates_changed'])

    def test_minute_arithmetic(self):
        self.assertEqual(self.result['after_walk']['minute_samples'],
                         {'0': 0, '359': 5, '360': 6, '3599': 59, '3600': 60, '86399': 1439})

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

    def test_stride_rejected(self):
        # lea rcx, [rax+0x268] -> [rax+0x260]
        self._rejects(self._patch(0x5b2a3b7 + 3, b'\x60'))

    def test_grouping_offset_rejected(self):
        # mov edx, [r12+0x240] -> [r12+0x244]
        self._rejects(self._patch(0x5b2a3e5 + 4, b'\x44'))

    def test_pushed_qword_offset_rejected(self):
        # mov r15, [r12+0x200] -> [r12+0x208]
        self._rejects(self._patch(0x5b2a403 + 4, b'\x08'))

    def test_len_threshold_rejected(self):
        # cmp rax, 3 -> cmp rax, 4
        self._rejects(self._patch(0x5b2a436 + 3, b'\x04'))

    def test_minute_threshold_rejected(self):
        # cmp esi, 6 -> cmp esi, 7
        self._rejects(self._patch(0x5b2a57f + 2, b'\x07'))

    def test_lookup_target_rejected(self):
        # call 0x4dc50c0 -> call 0x4dc50c1
        self._rejects(self._patch(0x5b2a21a + 1, b'\xa2'))

    def test_tag_store_rejected(self):
        # mov [rsp+7], bpl -> [rsp+8]
        self._rejects(self._patch(0x4dc50d4 + 4, b'\x08'))

    def test_grow_relocation_rejected(self):
        # retarget the grow slot call by one byte
        self._rejects(self._patch(0x5b2a41b + 2, b'\x68'))


if __name__ == '__main__':
    unittest.main()
