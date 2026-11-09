"""Node #115 hyperliquid_data state files and the blocking abci state writer. Mutations stay in a copied image."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import hyperliquid_data_files_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-hyperliquid-data-files-115/evidence.json'


class HyperliquidDataFilesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_census(self):
        path = self.result['path_builder']
        self.assertEqual(path['direct_callers'], ['0x5485ae0', '0x5486000', '0x5942b57', '0x5a396d3'])
        self.assertEqual(sorted(path['wrapper_callers']), ['0x5443a82', '0x59ec380', '0x5a08250', '0x5a08ab0'])
        self.assertEqual(self.result['closure']['serialiser_direct_callers'], ['0x4e4b480', '0x50dec72'])
        self.assertEqual(self.result['sha256'], packet.SHA256)
        self.assertFalse(self.result['gates_changed'])

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

    def test_visor_name_rejected(self):
        # visor_abci_state -> visor_abci_statf
        self._rejects(self._patch(0x4564d0 + 15, b'f'))

    def test_rmp_extension_rejected(self):
        # "rmp" -> "rmq"
        self._rejects(self._patch(0x4659e5 + 2, b'q'))

    def test_json_indent_rejected(self):
        # indent length 2 -> 4
        self._rejects(self._patch(0x50de1b9 + 5, b'\x04'))

    def test_blocking_flag_rejected(self):
        # mov edx, 1 -> mov edx, 0
        self._rejects(self._patch(0x5486046 + 1, b'\x00'))

    def test_height_offset_rejected(self):
        # mov rax, [r12+0x28] -> [r12+0x30]
        self._rejects(self._patch(0x4e4b421 + 4, b'\x30'))

    def test_serialiser_config_rejected(self):
        # config 0x01000400 -> 0x01000401 in the closure
        self._rejects(self._patch(0x4e4b461 + 4, b'\x01'))

    def test_state_location_rejected(self):
        # l1/src/abci/state.rs:195 -> 196
        self._rejects(self._patch(0x649da28 + 16, struct.pack('<I', 196)))

    def test_closure_result_rejected(self):
        # mov [rcx+0x10], r12 -> mov [rcx+0x18], r12
        self._rejects(self._patch(0x4e4b6e8 + 3, b'\x18'))


if __name__ == '__main__':
    unittest.main()
