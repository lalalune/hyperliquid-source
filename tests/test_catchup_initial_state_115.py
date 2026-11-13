"""Node #115 catch-up task initial engine value and output. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
import catchup_initial_state_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-catchup-initial-state-115/evidence.json'


class CatchupInitialStateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        cls.result = packet.bind(cls.data)

    def test_shape(self):
        self.assertEqual(self.result['sha256'], packet.SHA256)
        self.assertEqual(self.result['shim']['rel32_fields_different_target'],
                         {'0x2d2766f': ['0x2d25620', '0x5a07ec0']})
        self.assertIn('initial_slow_state_for_join', self.result['future_builder']['task_name'])
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
            packet.bind(data)

    def test_shim_extra_difference_rejected(self):
        # mov dword [rsp+0x478], 0 -> 1 makes the shim differ from 0x5a08f80 outside a rel32 field
        self._rejects(self._patch(0x2d27651 + 7, b'\x01'))

    def test_input_tag_rejected(self):
        # input +0x0 = 2 -> 3
        self._rejects(self._patch(0x2b1e1d9 + 8, b'\x03'))

    def test_box_offset_rejected(self):
        # mov rbx, [rsp+0x990] -> [rsp+0x998]
        self._rejects(self._patch(0x2b1e18c + 4, b'\x98'))

    def test_singleton_tag_rejected(self):
        # cmp r12, 2 -> 3
        self._rejects(self._patch(0x38c65f1 + 3, b'\x03'))

    def test_task_name_rejected(self):
        # initial_slow_state_for_join -> Initial_...
        self._rejects(self._patch(0x60601e, b'I'))

    def test_output_box_rejected(self):
        # output +0x10 = box -> rbx stored at +0x18 slot changed
        self._rejects(self._patch(0x2b1eef7 + 4, b'\xd8'))

    def test_vtable_relocation_rejected(self):
        # lea rax, [rip+...] -> points 8 bytes later than the vtable
        disp = int.from_bytes(packet.read_va(self.data, 0x2b3ac57 + 3, 4), 'little', signed=True) + 8
        self._rejects(self._patch(0x2b3ac57 + 3, disp.to_bytes(4, 'little', signed=True)))

    def test_drop_map_offset_rejected(self):
        # mov rax, [rbx+0x400] -> [rbx+0x408]
        self._rejects(self._patch(0x2df77cd + 3, b'\x08'))


if __name__ == '__main__':
    unittest.main()
