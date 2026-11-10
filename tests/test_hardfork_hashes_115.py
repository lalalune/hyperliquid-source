"""Node #115 hardfork_hashes read at the slow driver start. Mutations stay in a copied image."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import hardfork_hashes_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-hardfork-hashes-115/evidence.json'


class HardforkHashesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_census(self):
        census = self.result['direct_call_census']
        self.assertEqual(census['0x5647720'], ['0x5a34472'])
        self.assertEqual(len(census['0x5484670']), 6)
        self.assertIn('0x54847aa', census['0x452aab0'])
        self.assertIn('0x5a3459c', census['0x581a4f0'])
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

    def test_name_rejected(self):
        # hardfork_hashes -> hardfork_hashez
        self._rejects(self._patch(0x93b070 + 14, b'z'))

    def test_name_length_rejected(self):
        # mov ecx, 15 -> 14
        self._rejects(self._patch(0x5a3446d + 1, b'\x0e'))

    def test_send_gate_rejected(self):
        # cmp byte [rax], 0 -> 1
        self._rejects(self._patch(0x5a34517 + 2, b'\x01'))

    def test_height_offset_rejected(self):
        # mov r15, [rbx+0x28] -> [rbx+0x30]
        self._rejects(self._patch(0x5484687 + 3, b'\x30'))

    def test_minute_block_rejected(self):
        # cmp rax, [r13+0xb60] -> [r13+0xb68]
        self._rejects(self._patch(0x5647854 + 3, b'\x68'))

    def test_serialiser_config_rejected(self):
        # 0x01000400 -> 0x01000401
        self._rejects(self._patch(0x4e4b8c1 + 4, b'\x01'))

    def test_increment_constant_rejected(self):
        # 0.05 -> 0.06
        self._rejects(self._patch(0x453538, struct.pack('<d', 0.06)))

    def test_worker_call_rejected(self):
        # call 0x5484670 retargeted by one byte
        raw = self.data
        self._rejects(self._patch(0x4fc3764 + 1, bytes([(packet.read_va(raw, 0x4fc3765, 1)[0] + 1) & 0xff])))


if __name__ == '__main__':
    unittest.main()
