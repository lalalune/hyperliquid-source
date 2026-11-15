"""Node #115 slow abci driver apply-block closure. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import slow_abci_apply_block_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-slow-abci-apply-block-115/evidence.json'


class SlowAbciApplyBlockTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_chain_and_census(self):
        self.assertEqual(self.result['wrapper']['body_calls'], ['0x4f1532c', '0x4f15ae2'])
        self.assertEqual(self.result['step_direct_calls'], ['0x4fcae48'])
        self.assertIn('0x5a07ec0 (layout A step)', self.result['step_chain'][3])
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

    def test_lock_offset_rejected(self):
        # lock cmpxchg [r15+0x6a8] -> [r15+0x6b0]
        self._rejects(self._patch(0x4fcac88 + 5, b'\xb0'))

    def test_step_call_rejected(self):
        # call 0x59ec200 retargeted by one byte
        self._rejects(self._patch(0x4fcae48 + 1, b'\xb4'))

    def test_layout_a_link_rejected(self):
        # 0x5a04e40 -> 0x5a07ec0 call retargeted
        self._rejects(self._patch(0x5a05fc9 + 1, b'\xf3'))

    def test_draw_modulus_rejected(self):
        # mov edi, 50 -> 51
        self._rejects(self._patch(0x4fcaf46 + 1, b'\x33'))

    def test_draw_result_test_rejected(self):
        # sete al -> setne al
        self._rejects(self._patch(0x1562293 + 1, b'\x95'))

    def test_recorder_bytes_rejected(self):
        # any byte in the recorder extent (here: the div operand register)
        self._rejects(self._patch(0x4770e5b + 2, b'\xf3'))

    def test_recorder_name_rejected(self):
        # profiled_rw_lock_increment -> profiled_rw_lock_incremenT
        self._rejects(self._patch(0x7e1450 + 25, b'T'))

    def test_recorder_constant_rejected(self):
        # 0.05 -> another f64 (low byte changed)
        self._rejects(self._patch(0x453538, b'\x00'))


if __name__ == '__main__':
    unittest.main()
