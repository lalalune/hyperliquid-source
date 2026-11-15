"""Node #115 blp mode call, side predicate and move_token pair. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import blp_mode_call_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-blp-mode-call-115/evidence.json'


class BlpModeCallTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_censuses(self):
        self.assertEqual(self.result['mode_call_0x5609fb0']['direct_calls'], 7)
        self.assertEqual(self.result['move_0x5580d10']['direct_calls'], 51)
        self.assertEqual(self.result['mode_call_0x5609fb0']['switch_arms'],
                         {'0': '0x57cbfeb', '1': '0x57cbe4b', '2': '0x57cbf16', '3': '0x57cbfe6'})
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

    def test_first_mode_rejected(self):
        # mov r8d, 3 -> mov r8d, 2
        self._rejects(self._patch(0x558193d + 2, b'\x02'))

    def test_side_mask_rejected(self):
        # and ecx, 1 -> and ecx, 3
        self._rejects(self._patch(0x55a0e61 + 2, b'\x03'))

    def test_predicate_side_rejected(self):
        # xor al, 1 -> xor al, 0
        self._rejects(self._patch(0x369b5cd + 1, b'\x00'))

    def test_predicate_key_length_rejected(self):
        # memcmp length 0x14 -> 0x10
        self._rejects(self._patch(0x369b3f9 + 1, b'\x10'))

    def test_mode_arm_rejected(self):
        # mov eax, 3 -> mov eax, 2 in the mode 3 arm
        self._rejects(self._patch(0x57cbfe6 + 1, b'\x02'))

    def test_ctr_offset_rejected(self):
        # [rsi+0xab0] -> [rsi+0xab8]
        self._rejects(self._patch(0x5580d32 + 3, b'\xb8'))

    def test_leg_mode_rejected(self):
        # mov r8d, 1 -> mov r8d, 0 for the to_spot leg
        self._rejects(self._patch(0x55812a9 + 2, b'\x00'))

    def test_string_rejected(self):
        # 'move_token from_spot' -> 'move_token frem_spot'
        self._rejects(self._patch(packet.FROM_SPOT[0] + 14, b'e'))


if __name__ == '__main__':
    unittest.main()
