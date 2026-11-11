"""Node #115 block-step sampler post-walk collect and observer day fields. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import block_step_sampler_report_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-block-step-sampler-report-115/evidence.json'


class BlockStepSamplerReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_collect_census(self):
        collect = self.result['collect']
        self.assertEqual(collect['direct_callers'], ['0x5b2a51a', '0x5b2a662'])
        self.assertEqual(len(collect['call_census']['0x5b926e0']['calls']), 8)
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

    def test_minimum_capacity_rejected(self):
        # mov ebx, 4 -> 5
        self._rejects(self._patch(0x5b92786 + 1, b'\x05'))

    def test_element_size_rejected(self):
        # mov ecx, 8 -> 0x10 (size of the collected element)
        self._rejects(self._patch(0x5b928ec + 1, b'\x10'))

    def test_btree_node_length_rejected(self):
        # movzx edx, word [rax+0x13e] -> [rax+0x13f]
        self._rejects(self._patch(0x51360cb + 3, b'\x3f'))

    def test_result_read_rejected(self):
        # free size shl rsi, 3 -> shl rsi, 4
        self._rejects(self._patch(0x5b2a52e + 3, b'\x04'))

    def test_extra_call_rejected(self):
        # turn the grow call's alignment move into a call to the collect's own start
        rel = (packet.COLLECT - (0x5b928f1 + 5)).to_bytes(4, 'little', signed=True)
        self._rejects(self._patch(0x5b928f1, b'\xe8' + rel + b'\x90'))

    def test_date_compare_rejected(self):
        # cmp [rbx+0x240], edi -> [rbx+0x244]
        self._rejects(self._patch(0x1547562 + 2, b'\x44'))

    def test_count_sum_rejected(self):
        # add rcx, r14 -> add rcx, r15
        self._rejects(self._patch(0x1547714 + 2, b'\xf9'))

    def test_call_counter_saturation_rejected(self):
        # cmove rcx, rdx -> cmovne rcx, rdx
        self._rejects(self._patch(0x154773a + 2, b'\x45'))

    def test_clock_slot_rejected(self):
        # call [rip+disp] -> one slot later
        raw = packet.read_va(self.data, 0x1547559 + 2, 4)
        disp = int.from_bytes(raw, 'little', signed=True) + 8
        self._rejects(self._patch(0x1547559 + 2, disp.to_bytes(4, 'little', signed=True)))


if __name__ == '__main__':
    unittest.main()
