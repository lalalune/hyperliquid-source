"""Node #115 abci layout selection. Mutations stay in a copied image."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import abci_layout_selection_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-abci-layout-selection-115/evidence.json'


class AbciLayoutSelectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_both_paths_in_one_function(self):
        sel = self.result['select_0x5a6bfb0']
        self.assertIn('0x5a6c16a', sel['b_path'])
        self.assertIn('0x5a0901f', sel['a_path'])
        self.assertEqual(self.result['step_callers']['0x5a07ec0'], ['0x5a05fc9', '0x5a0901f'])
        self.assertEqual(self.result['step_callers']['0x5a08720'], ['0x5a077e1', '0x5a6c16a'])
        self.assertEqual(self.result['step_callers']['0x56185e0'], ['0x54439ad', '0x59ec2a8'])
        self.assertFalse(self.result['gates_changed'])

    def test_twins_differ_only_in_rip_fields(self):
        twins = self.result['twin_callees']
        self.assertEqual(twins['differing_byte_offsets'], [36, 37, 76, 77, 116])
        self.assertEqual([t for _, t in twins['rip_fields']], ['0x64e6480', '0x64df508', '0x64e6488'])

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

    def test_poller_flag_byte_rejected(self):
        # movzx edx, byte [r12+0x2a1a] -> [r12+0x2a1b]
        self._rejects(self._patch(0x2aec3e0 + 5, b'\x1b'))

    def test_b_step_call_rejected(self):
        # call 0x5a08720 -> call 0x5a07ec0
        self._rejects(self._patch(0x5a6c16a + 1, struct.pack('<i', 0x5a07ec0 - (0x5a6c16a + 5))))

    def test_a_box_offset_rejected(self):
        # mov [rsp+0x1660], rbx -> [rsp+0x1668]
        self._rejects(self._patch(0x5a6c39c + 4, b'\x68'))

    def test_flag_store_rejected(self):
        # mov byte [rsp+0x5939], 1 -> 0
        self._rejects(self._patch(0x5a6c5e0 + 7, b'\x00'))

    def test_wrapper_box_load_rejected(self):
        # mov r14, [rsi+0x420] -> [rsi+0x428]
        self._rejects(self._patch(0x5a08f92 + 3, b'\x28'))

    def test_dispatcher_add_rejected(self):
        # add rbx, 0xb9b -> 0xb9c
        self._rejects(self._patch(0x5395f86 + 3, b'\x9c'))

    def test_twin_ecx_write_rejected(self):
        # mov ecx, ebp -> mov edx, ebp in the A twin
        self._rejects(self._patch(0x5490560, b'\x89\xea'))

    def test_twin_body_rejected(self):
        # change a non-displacement byte in the B twin (cmp r12, 2 -> 3)
        self._rejects(self._patch(0x5490602 + 3, b'\x03'))


if __name__ == '__main__':
    unittest.main()
