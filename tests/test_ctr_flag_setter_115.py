"""Node #115 ctr flag setter 0x55817e0 and its call site. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import ctr_flag_setter_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-ctr-flag-setter-115/evidence.json'


class CtrFlagSetterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_censuses(self):
        setter = self.result['setter']
        self.assertEqual(setter['direct_calls'], ['0x5583117', '0x55845da', '0x5588e6f', '0x558942a'])
        self.assertEqual(setter['caller_frames'], ['0x5582180', '0x5588d90', '0x55890d0'])
        self.assertEqual(setter['check_calls'], ['0x5581946', '0x5581a37', '0x5581ac0', '0x5581b7d'])
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

    def test_flag_value_rejected(self):
        # mov al, 1 -> mov al, 0
        self._rejects(self._patch(0x5583120 + 1, b'\x00'))

    def test_key_tag_rejected(self):
        # mov qword [rsp+0xb0], 2 -> 3
        self._rejects(self._patch(0x55830e5 + 8, b'\x03'))

    def test_ctr_offset_rejected(self):
        # [r13+0xab0] -> [r13+0xab8]
        self._rejects(self._patch(0x5583288 + 3, b'\xb8'))

    def test_first_check_mode_rejected(self):
        # mov r8d, 3 -> 2
        self._rejects(self._patch(0x558193d + 2, b'\x02'))

    def test_ok_tag_rejected(self):
        # cmp word [rsp+0x30], 0x1a2 -> 0x1a3
        self._rejects(self._patch(0x558194b + 5, b'\xa3'))

    def test_tail_call_rejected(self):
        # call move_token rel32 + 1
        self._rejects(self._patch(0x5581c1c + 1, b'\xf0'))

    def test_move_token_string_rejected(self):
        # "move_token to_spot" -> "move_token to_spoT"
        self._rejects(self._patch(0x432bcb + 18, b'T'))

    def test_location_line_rejected(self):
        # impl_ntl.rs:70 -> 71
        self._rejects(self._patch(0x64a9918 + 16, b'\x47'))


if __name__ == '__main__':
    unittest.main()
