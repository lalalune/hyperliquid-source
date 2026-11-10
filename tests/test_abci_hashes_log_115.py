"""Node #115 abci_hashes line record. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import abci_hashes_log_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-abci-hashes-log-115/evidence.json'


class AbciHashesLogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_bindings(self):
        self.assertEqual(self.result['calls'], {'0x548d9e9': '0x548d8c0', '0x548dbf9': '0x548dad0'})
        self.assertIn('"exchange_abci_hash"', self.result['line']['format'])
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

    def test_field_name_rejected(self):
        # exchange_abci_hash -> exchange_abci_hasH
        self._rejects(self._patch(0x924eea + 17, b'H'))

    def test_height_source_rejected(self):
        # mov rax, [r15+0x28] -> [r15+0x20] in step A
        self._rejects(self._patch(0x548dbc7 + 3, b'\x20'))

    def test_tree_slot_rejected(self):
        # mov [rsp+0x48], r12 -> [rsp+0x40] in step B
        self._rejects(self._patch(0x548d9d5 + 4, b'\x40'))

    def test_digest_value_offset_rejected(self):
        # lea rcx, [rbx+0x10] -> [rbx+0x18]
        self._rejects(self._patch(0x537d641 + 3, b'\x18'))

    def test_node_tag_rejected(self):
        # cmp byte [rdx], 1 -> 2
        self._rejects(self._patch(0x506d58c + 2, b'\x02'))

    def test_leaf_hex_length_rejected(self):
        # mov ecx, 0x20 -> 0x14 in the leaf writer
        self._rejects(self._patch(0x506d5d6 + 1, b'\x14'))

    def test_line_call_rejected(self):
        # retarget the step A call of the line function
        self._rejects(self._patch(0x548dbf9 + 1, b'\x00\x00\x00\x00'))

    def test_flush_gate_rejected(self):
        # cmp byte [r14+0xaa] -> [r14+0xab]
        self._rejects(self._patch(0x4e3a8f6 + 3, b'\xab'))


if __name__ == '__main__':
    unittest.main()
