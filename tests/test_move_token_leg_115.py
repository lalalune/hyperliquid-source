"""Node #115 move_token leg 0x54df920 and the 0x55817e0 early exit. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import move_token_leg_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-move-token-leg-115/evidence.json'


class MoveTokenLegTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_census(self):
        self.assertEqual(self.result['leg_0x54df920']['direct_calls'], 13)
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

    def test_short_balance_tag_rejected(self):
        # mov bp, 0x34 -> 0x35
        self._rejects(self._patch(0x54dfc05 + 2, b'\x35'))

    def test_overflow_tag_rejected(self):
        # mov bp, 0x106 -> 0x107
        self._rejects(self._patch(0x54dfbcd + 2, b'\x07'))

    def test_credit_direction_rejected(self):
        # add r14, r15 -> sub r14, r15
        self._rejects(self._patch(0x54dff8a, b'\x4d\x29\xfe'))

    def test_debit_field_rejected(self):
        # mov [r15+0x4a8], rax -> [r15+0x4b0]
        self._rejects(self._patch(0x54e012d + 3, b'\xb0'))

    def test_leg_selector_rejected(self):
        # cmp r15, 1 -> cmp r15, 3
        self._rejects(self._patch(0x54dfbe0 + 3, b'\x03'))

    def test_early_exit_arg_rejected(self):
        # mov [rsp], r12 -> mov [rsp], r13
        self._rejects(self._patch(0x5581bfe, b'\x4c\x89\x2c\x24'))

    def test_outer_ecx_rejected(self):
        # xor ecx, ecx -> xor edx, edx
        self._rejects(self._patch(0x558310a, b'\x31\xd2'))

    def test_location_rejected(self):
        # impl_ntl.rs line 70 -> 71
        self._rejects(self._patch(0x648ba50 + 16, b'\x47'))


if __name__ == '__main__':
    unittest.main()
