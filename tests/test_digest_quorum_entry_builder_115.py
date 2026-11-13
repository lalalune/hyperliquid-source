"""Node #115 digest quorum entry builder. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import digest_quorum_entry_builder_115 as packet

EVIDENCE = packet.PACKET / 'evidence.json'


class DigestQuorumEntryBuilderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_census(self):
        self.assertEqual(self.result['builder']['calls'], ['0x5151abb', '0x57d4078'])
        self.assertEqual(self.result['prune']['calls'], ['0x5afa72f', '0x5afacce'])
        self.assertEqual(self.result['store_delay']['writers'], ['0x539025b', '0x539b07b', '0x28d0cde'])
        self.assertEqual(self.result['sha256'], packet.SHA256)
        self.assertFalse(self.result['gates_changed'])

    def test_committed_packet_matches(self):
        self.assertEqual(packet.render(self.result), EVIDENCE.read_bytes())
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

    def test_flag_byte_offset_rejected(self):
        # cmp byte [r15+0x20], 0 -> [r15+0x21]
        self._rejects(self._patch(0x5377abe + 3, b'\x21'))

    def test_key_length_rejected(self):
        # mov edx, 0x20 -> 0x1f
        self._rejects(self._patch(0x5377b39 + 1, b'\x1f'))

    def test_key_output_offset_rejected(self):
        # movups [r12+0x40], xmm0 -> [r12+0x48]
        self._rejects(self._patch(0x5377d7c + 5, b'\x48'))

    def test_none_value_rejected(self):
        # inc rax -> dec rax (None would be 0x7fff..ff)
        self._rejects(self._patch(0x5377c45 + 2, b'\xc8'))

    def test_extract_none_test_rejected(self):
        # lea rax, [r15+1] -> [r15+2]
        self._rejects(self._patch(0x5151ac0 + 3, b'\x02'))

    def test_prune_bound_rejected(self):
        # sub r13, 50000 -> 50001
        self._rejects(self._patch(0x5afa701 + 3, b'\x51'))

    def test_delay_field_rejected(self):
        # movq [r13+0x3e20] -> [r13+0x3e28]
        self._rejects(self._patch(0x539025b + 5, b'\x28'))

    def test_delay_ok_tag_rejected(self):
        # cmp eax, 0x1a2 -> 0x1a3
        self._rejects(self._patch(0x539b067 + 1, b'\xa3'))


if __name__ == '__main__':
    unittest.main()
