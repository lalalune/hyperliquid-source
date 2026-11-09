"""Node #115 output-flag struct origin and setter byte +0x18. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import output_flags_origin_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-output-flags-origin-115/evidence.json'


class OutputFlagsOriginTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_dispatch(self):
        parent = self.result['parent_future']
        self.assertEqual(parent['cases'], {'2': '0x2ae45b7', '3': '0x2ae5421'})
        self.assertEqual(parent['mode_byte_future_plus_0x28'], {'tag 2': 2, 'tag 3': 1})
        self.assertIn('run-validator', self.result['subcommands']['run-validator'])
        self.assertEqual(self.result['sha256'], packet.SHA256)
        self.assertFalse(self.result['gates_changed'])

    def test_setter_byte(self):
        byte = self.result['setter_plus_0x18']
        self.assertEqual(byte['rsp13_accesses_in_setter_fde'], ['0x51cf388', '0x51d0857'])
        self.assertIn('15.0', byte['set'])

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

    def test_tag_rejected(self):
        # mov qword [rbx], 2 -> 4
        self._rejects(self._patch(0x56550e4 + 3, b'\x04'))

    def test_validator_name_rejected(self):
        # 'run-vali' -> 'run-valx'
        self._rejects(self._patch(0x5654e05 + 7, b'x'))

    def test_non_validator_name_rejected(self):
        # 'run-non-validato' -> 'run-non-validatx'
        self._rejects(self._patch(packet.NON_VALIDATOR[0] + 15, b'x'))

    def test_parent_copy_rejected(self):
        # movups xmm0, [rbx+0x10] -> [rbx+0x18]
        self._rejects(self._patch(0x2ae4548 + 3, b'\x18'))

    def test_mode_byte_rejected(self):
        # mov byte [rbx+0x248], 1 -> 2
        self._rejects(self._patch(0x2ae5469 + 6, b'\x02'))

    def test_jump_table_rejected(self):
        # case 0 entry +1
        raw = bytearray(packet.read_va(self.data, packet.JUMP_TABLE, 4))
        raw[0] = (raw[0] + 1) & 0xff
        self._rejects(self._patch(packet.JUMP_TABLE, bytes(raw)))

    def test_setter_test_offset_rejected(self):
        # cmp byte [rsp+0x13], 0 -> [rsp+0x14]
        self._rejects(self._patch(0x51d0856 + 3, b'\x14'))

    def test_constant_rejected(self):
        # 15.0 -> 16.0 (0x4030...)
        self._rejects(self._patch(0x51d0876 + 6, b'\x30'))


if __name__ == '__main__':
    unittest.main()
