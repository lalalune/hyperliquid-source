"""Node #115 line writer constructors and where writers are stored. Mutations stay in a copied image."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import abci_step_observer_logdir_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-abci-step-observer-logdir-115/evidence.json'


class AbciStepObserverLogdirTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_census(self):
        w = self.result['writer_constructors']
        self.assertEqual((w['daily']['calls'], w['hourly']['calls']), (32, 27))
        self.assertEqual(w['functions_calling_either'], 22)
        self.assertEqual(self.result['observer_constructor']['calls'], 35)
        self.assertEqual(self.result['functions_calling_both'],
                         ['0x2af45f0', '0x2cc1120', '0x51c9cb0', '0x5a6bfb0'])
        self.assertEqual(self.result['sha256'], packet.SHA256)
        self.assertFalse(self.result['gates_changed'])

    def test_only_constructor_fills_state_offsets(self):
        census = self.result['writer_copy_census']
        self.assertEqual(census['non_stack_state_offset_mod_0x260'],
                         [['0x1548dad', '0x98'], ['0x1548dc4', '0x148']])
        self.assertEqual(census['mov_edx_0xb0'], 1189)

    def test_committed_packet_matches(self):
        self.assertEqual(packet.render(self.result), PACKET.read_bytes())
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(packet.main(['--out', tmp, '--check']), 0)

    def _offset(self, va):
        sec = next(s for s in sections(self.data)
                   if s['type'] != 8 and s['address'] <= va < s['address'] + s['size'])
        return sec['offset'] + va - sec['address']

    def _patch(self, va, new):
        broken = bytearray(self.data)
        off = self._offset(va)
        broken[off:off + len(new)] = new
        return bytes(broken)

    def _rejects(self, data):
        with self.assertRaises(ValueError):
            packet.bind(data, self.fdes)

    def test_hourly_byte_rejected(self):
        # mov byte [rbx+0xa8], 1 -> 0
        self._rejects(self._patch(0x1546046 + 6, b'\x00'))

    def test_slash_check_rejected(self):
        # cmp byte [r14], '/' -> '.'
        self._rejects(self._patch(0x1546747 + 3, b'\x2e'))

    def test_data_template_rejected(self):
        # {}/data/{} -> {}/dbta/{}
        self._rejects(self._patch(0x448b77 + 4, b'b'))

    def test_writer_name_rejected(self):
        # daily_liner -> daily_lineR
        self._rejects(self._patch(packet.DAILY_NAME[0] + 10, b'R'))

    def test_root_relocation_rejected(self):
        # root slot no longer resolves to the root cell: retarget the load
        self._rejects(self._patch(0x1546758 + 3, struct.pack('<i', 0)))

    def test_writer_placement_rejected(self):
        # lea rdi, [r12+0x720] -> [r12+0x7b8] (0x720 + 0x98)
        self._rejects(self._patch(0x51c9e9a + 4, b'\xb8\x07'))

    def test_observer_copy_length_rejected(self):
        # mov edx, 0x260 -> 0xb0 for the third observer copy
        self._rejects(self._patch(0x51c9e86 + 1, b'\xb0\x00'))

    def test_root_cell_initializer_rejected(self):
        # break the {}/code template the root initializer formats
        self._rejects(self._patch(0x43de2f + 3, b'C'))


if __name__ == '__main__':
    unittest.main()
