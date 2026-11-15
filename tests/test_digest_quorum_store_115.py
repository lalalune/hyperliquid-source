"""Node #115 digest quorum store fill, retain and cap. Mutations stay in a copied image."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import digest_quorum_store_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-digest-quorum-store-115/evidence.json'


class DigestQuorumStoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_bound_values(self):
        sel = self.result['selector']
        self.assertEqual(sel['arms_esi_0_to_3'], ['0x54caec4', '0x54cb082', '0x54cb042', '0x54cb062'])
        calls = self.result['direct_calls']
        self.assertEqual(calls['0x54cae80'][:4], ['0x539200b', '0x5392018', '0x5392025', '0x5392032'])
        self.assertEqual(calls['0x5afa1f0'], ['0x5488dd2', '0x548bf13'])
        self.assertEqual(self.result['sha256'], packet.SHA256)
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

    def test_cap_rejected(self):
        # sub rax, 1000 -> 1001
        self._rejects(self._patch(0x5afa20e + 2, b'\xe9'))

    def test_length_field_rejected(self):
        # mov rax, [rsi+0x78] -> [rsi+0x70]
        self._rejects(self._patch(0x5afa208 + 3, b'\x70'))

    def test_sixty_rejected(self):
        self._rejects(self._patch(packet.SIXTY, struct.pack('<d', 61.0)))

    def test_counter_compare_rejected(self):
        # jb -> jae
        self._rejects(self._patch(0x51519a8 + 1, b'\x83'))

    def test_filter_offset_rejected(self):
        # cmp [rbp-0x68] -> [rbp-0x60]
        self._rejects(self._patch(0x5afa2b0 + 3, b'\xa0'))

    def test_prune_distance_rejected(self):
        # sub r13, 50000 -> 50001
        self._rejects(self._patch(0x5afa701 + 3, b'\x51'))

    def test_selector_table_rejected(self):
        self._rejects(self._patch(packet.TABLE + 8, b'\x00'))

    def test_dispatcher_esi_rejected(self):
        # mov esi, 2 -> 1
        self._rejects(self._patch(0x5392020 + 1, b'\x01'))


if __name__ == '__main__':
    unittest.main()
