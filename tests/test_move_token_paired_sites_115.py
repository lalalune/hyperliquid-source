"""Node #115 move_token paired call sites (stage 102). Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import move_token_paired_sites_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-move-token-paired-sites-115/evidence.json'


class MoveTokenPairedSitesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)
        cls.rows = {r['site']: r for r in cls.result['sites']}

    def test_shapes_and_totals(self):
        self.assertEqual(self.result['shapes'], {'P': 14, 'Z': 9, 'S': 1})
        self.assertEqual(self.result['p_r9_is_cls_index'], 14)
        self.assertEqual(self.result['totals_after_stage_102']['unresolved'], 0)
        self.assertEqual(self.rows['0x5588e9a']['no_op_when'], 'rbx == 0 (destination kind 0)')
        self.assertFalse(self.result['gates_changed'])

    def test_committed_packet_matches(self):
        self.assertEqual(packet.render(self.result), PACKET.read_bytes())
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(packet.main(['--out', tmp, '--check']), 0)

    def _patch(self, va, new):
        broken = bytearray(self.data)
        sec = next(s for s in sections(self.data) if s['type'] != 8 and s['address'] <= va < s['address'] + s['size'])
        off = sec['offset'] + va - sec['address']
        broken[off:off + len(new)] = new
        return bytes(broken)

    def _rejects(self, data):
        with self.assertRaises(ValueError):
            packet.bind(data, self.fdes)

    def _pin(self, site, name):
        return int(self.rows[site]['pins'][name], 16)

    def test_early_exit_compare_rejected(self):
        # cmp r15,[rsp+0x1b0] -> [rsp+0x1b8]
        self._rejects(self._patch(0x5580d7e + 4, b'\xb8'))

    def test_sete_rejected(self):
        # sete al -> setne al
        self._rejects(self._patch(self._pin('0x556b1f5', 'sete') + 1, b'\x95'))

    def test_r8_constant_rejected(self):
        # mov r8d,1 -> mov r8d,2
        self._rejects(self._patch(self._pin('0x558aad2', 'r8') + 2, b'\x02'))

    def test_plus58_load_rejected(self):
        # mov rcx,[..+0x58] -> [..+0x50]
        va = self._pin('0x558de33', 'load_plus58')
        self._rejects(self._patch(va + 3, b'\x50'))

    def test_arg1_store_rejected(self):
        # movups [rsp+0x8],xmm0 -> [rsp+0x10]
        self._rejects(self._patch(self._pin('0x5593c22', 'arg1_zero_xmm') + 4, b'\x10'))

    def test_zero_arg0_rejected(self):
        # mov qword [rsp],0 -> mov qword [rsp],1
        self._rejects(self._patch(self._pin('0x558ffd8', 'arg0_zero') + 4, b'\x01'))

    def test_push_zero_rejected(self):
        # push 0 -> push 1 before the S call
        self._rejects(self._patch(0x5588e95 + 1, b'\x01'))

    def test_call_target_rejected(self):
        # retarget one move_token call by one byte
        self._rejects(self._patch(0x55886ac + 1, b'\x72'))


if __name__ == '__main__':
    unittest.main()
