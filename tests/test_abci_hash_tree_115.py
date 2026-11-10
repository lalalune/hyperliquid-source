"""Node #115 abci hash tree fold and root digest. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import abci_hash_tree_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-abci-hash-tree-115/evidence.json'


class AbciHashTreeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_censuses(self):
        tree = self.result['tree']
        self.assertEqual(tree['slots_relocated_to_it'], ['0x64df500'])
        self.assertEqual(tree['self_calls'], ['0x141a3f1', '0x141a595'])
        self.assertEqual(tree['callers_outside'], ['0x269a829', '0x4e34999', '0x4e35359'])
        self.assertEqual(tree['grow_direct_calls'], ['0x141a6b3'])
        self.assertIn('0x548db1a', self.result['root']['slot_calls'])
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

    def test_leaf_tag_rejected(self):
        # mov byte [rbp], 0 -> 1
        self._rejects(self._patch(0x141a32d + 3, b'\x01'))

    def test_node_tag_rejected(self):
        # mov byte [rbp], 1 -> 0
        self._rejects(self._patch(0x141a74d + 3, b'\x00'))

    def test_skip_sentinel_rejected(self):
        # movabs rcx, 0x8000000000000001 -> ...02 (node loop)
        self._rejects(self._patch(0x141a3c5 + 2, b'\x02'))

    def test_element_size_rejected(self):
        # mov r8d, 0x30 -> 0x28
        self._rejects(self._patch(0x141a6a5 + 2, b'\x28'))

    def test_hasher_size_rejected(self):
        # mov edx, 0x778 -> 0x770
        self._rejects(self._patch(0x141a292 + 1, b'\x70'))

    def test_hex_prefix_rejected(self):
        # mov word [rdi], 0x7830 ("0x") -> 0x5830 ("0X")
        self._rejects(self._patch(0x2eabb62 + 4, b'\x58'))

    def test_hex_table_rejected(self):
        # lowercase 'a' -> 'A'
        self._rejects(self._patch(packet.HEX_TABLE + 10, b'A'))

    def test_root_config_rejected(self):
        # mov dword [rsp+0x28], 0x400 -> 0x500
        self._rejects(self._patch(0x41c5185 + 5, b'\x05'))


if __name__ == '__main__':
    unittest.main()
