"""Node #115 abci digest hash (BLAKE3) and its input builder. Mutations stay in a copied image."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import abci_digest_hash_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-abci-digest-hash-115/evidence.json'


class AbciDigestHashTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_blake3(self):
        b3 = self.result['hash_fn']['blake3']
        self.assertIn('13 Location refs', b3['update'])
        self.assertIn('0x6a09e667', b3['iv'])
        self.assertEqual(self.result['digest_fn']['location'], 'l1/src/abci/abci_hash.rs:28:37')
        self.assertEqual(self.result['digest_fn']['direct_callers'], ['0x5a07fce'])
        self.assertEqual(self.result['sha256'], packet.SHA256)
        self.assertFalse(self.result['gates_changed'])

    def test_builder(self):
        build = self.result['build_fn']
        self.assertEqual(build['r15_lea_rax_entries_before_alloc'], 73)
        self.assertTrue(build['slots'].startswith('59 x 0x18'))

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

    def test_iv_rejected(self):
        # first IV word 0x6a09e667 -> 0x6a09e666
        self._rejects(self._patch(packet.IV, struct.pack('<I', 0x6a09e666)))

    def test_platform_rejected(self):
        # mov al, 4 -> mov al, 5
        self._rejects(self._patch(0x160beff + 1, b'\x05'))

    def test_update_slot_rejected(self):
        # call [slot 0x64df510] -> [slot 0x64df518]
        self._rejects(self._patch(0x41c5387 + 2, struct.pack('<i', 0x231a183 + 8)))

    def test_blake3_path_rejected(self):
        # blake3/src/lib.rs -> blake4
        self._rejects(self._patch(packet.BLAKE3_LIB[0] + len(b'/home/ubuntu/hl/code_Mainnet/z_vendor/blake'), b'4'))

    def test_location_line_rejected(self):
        # abci_hash.rs:28 -> :29
        self._rejects(self._patch(packet.ABCI_HASH_LOC + 16, b'\x1d'))

    def test_height_offset_rejected(self):
        # mov rax, [r15+0x28] -> [r15+0x30]
        self._rejects(self._patch(0x548dbc7 + 3, b'\x30'))

    def test_slot_count_rejected(self):
        # cap 0x3b -> 0x3c
        self._rejects(self._patch(0x4e352fd + 5, b'\x3c'))

    def test_parts_result_rejected(self):
        # cmp al, 4 -> cmp al, 5
        self._rejects(self._patch(0x4e35329 + 1, b'\x05'))


if __name__ == '__main__':
    unittest.main()
