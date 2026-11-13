"""Node #115 abci hash tree encoding. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import abci_hash_tree_encoding_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-abci-hash-tree-encoding-115/evidence.json'


class AbciHashTreeEncodingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_censuses(self):
        self.assertEqual(self.result['node']['direct_calls'], ['0x41c51a5', '0x41c7893'])
        self.assertEqual(self.result['element']['direct_calls'], ['0x4144559', '0x4144689'])
        self.assertEqual(self.result['sha256'], packet.SHA256)
        self.assertFalse(self.result['gates_changed'])

    def test_derived_encoding(self):
        self.assertEqual(packet.enc_array_len(2), b'\x92')
        self.assertEqual(packet.enc_array_len(16), b'\xdc\x00\x10')
        self.assertEqual(packet.enc_uint(58), b'\x3a')
        self.assertEqual(packet.enc_uint(0x80), b'\xcc\x80')
        leaf = packet.enc_leaf(bytes(32))
        self.assertEqual(leaf[:4], b'\xd9\x42' + b'0x')
        self.assertEqual(len(leaf), 68)
        ex = self.result['derived_example']
        self.assertEqual((ex['length'], ex['prefix_hex'], ex['second_element_head_hex']),
                         (141, '929200d94230', '9203d94230'))

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

    def test_config_dword_rejected(self):
        # 0x400 -> 0x500
        self._rejects(self._patch(0x41c5185 + 5, b'\x05'))

    def test_pair_header_rejected(self):
        # mov edx, 2 -> 3 (three-element element array)
        self._rejects(self._patch(0x41c7800 + 1, b'\x03'))

    def test_fixarray_marker_rejected(self):
        # or sil, 0x90 -> 0x80 (map marker)
        self._rejects(self._patch(0x3d52357 + 3, b'\x80'))

    def test_uint8_marker_rejected(self):
        # 0xcc -> 0xd0 (int8)
        self._rejects(self._patch(0x3d51925 + 3, b'\xd0'))

    def test_str8_marker_rejected(self):
        # 0xd9 -> 0xc4 (bin8)
        self._rejects(self._patch(0x41c6160 + 3, b'\xc4'))

    def test_hex_prefix_rejected(self):
        # "0x" -> "0X"
        self._rejects(self._patch(0x2eabb62 + 4, b'\x58'))

    def test_hex_table_rejected(self):
        # lowercase table -> uppercase 'A'
        self._rejects(self._patch(packet.HEX_TABLE + 10, b'A'))

    def test_element_stride_rejected(self):
        # add r15, 0x30 -> 0x28
        self._rejects(self._patch(0x414469c + 3, b'\x28'))


if __name__ == '__main__':
    unittest.main()
