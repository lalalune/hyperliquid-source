"""Node #115 l1 hash map at engine value +0x3e0. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import l1_hash_map_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-l1-hash-map-115/evidence.json'


class L1HashMapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_trim_shapes_match(self):
        maps = self.result['maps']
        for key in ('l1', 'digest'):
            self.assertEqual(maps[key]['trim_threshold'], 0x33)
            self.assertEqual(maps[key]['step_back_calls'], 50)
            self.assertEqual((maps[key]['insert_calls'], maps[key]['split_calls']), (1, 1))
        self.assertEqual(maps['l1']['callers'], ['0x5a08267', '0x5a08ac7'])
        self.assertEqual(self.result['l1_split_sites'], ['0x5a04d9a', '0x5a0584e', '0x5a0707c'])
        self.assertEqual(self.result['step_visor_write']['location'], 'l1/src/abci/engine.rs:316:46')
        self.assertFalse(self.result['gates_changed'])

    def test_committed_packet_matches(self):
        self.assertEqual(packet.render(self.result), PACKET.read_bytes())
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(packet.main(['--out', tmp, '--check']), 0)

    def _patch(self, va, new):
        sec = next(s for s in sections(self.data) if s['type'] != 8 and s['address'] <= va < s['address'] + s['size'])
        off = sec['offset'] + va - sec['address']
        broken = bytearray(self.data)
        broken[off:off + len(new)] = new
        return bytes(broken)

    def _rejects(self, data):
        with self.assertRaises(ValueError):
            packet.bind(data, self.fdes)

    def test_trim_threshold_rejected(self):
        # cmp rdx, 0x33 -> 0x34
        self._rejects(self._patch(0x5a04711 + 3, b'\x34'))

    def test_insert_call_rejected(self):
        # call 0x4dce8b0 -> other target
        self._rejects(self._patch(0x5a04708 + 1, b'\xa4'))

    def test_step_map_offset_rejected(self):
        # lea rdi, [r14+0x3e0] -> [r14+0x3e8]
        self._rejects(self._patch(0x5a08255 + 3, b'\xe8'))

    def test_wrapper_saturation_rejected(self):
        # inc rax -> dec rax
        self._rejects(self._patch(0x5a0581d + 2, b'\xc8'))

    def test_wrapper_split_rejected(self):
        # call 0x4de4a60 -> other target
        self._rejects(self._patch(0x5a0584e + 1, b'\x0e'))

    def test_visor_name_rejected(self):
        # visor_abci_state -> Visor_abci_state
        self._rejects(self._patch(0x4564d0, b'V'))

    def test_location_line_rejected(self):
        # engine.rs:316 -> 317
        self._rejects(self._patch(0x64b7f80 + 16, b'\x3d'))

    def test_freeze_field_rejected(self):
        # movups [rax+0x10e8] -> [rax+0x10f0]
        self._rejects(self._patch(0x5a081f4 + 3, b'\xf0'))


if __name__ == '__main__':
    unittest.main()
