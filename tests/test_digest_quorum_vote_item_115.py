"""Node #115 digest quorum vote item insert. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import digest_quorum_vote_item_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-digest-quorum-vote-item-115/evidence.json'


class DigestQuorumVoteItemTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_twin_and_census(self):
        twin = self.result['twin_update']
        self.assertEqual(len(twin['callee_pairs']), 3)
        self.assertEqual(twin['other_differing_bytes'], [('0x5afaa84', 10, 11), ('0x5afac33', 10, 11)])
        self.assertEqual(twin['location_file'], 'l1/src/abci/hash_signature_tracker.rs')
        self.assertEqual(self.result['insert']['direct_calls']['0x537b870'], ['0x5afab8f'])
        self.assertEqual(self.result['sha256'], packet.SHA256)
        self.assertFalse(self.result['gates_changed'])

    def test_committed_packet_matches(self):
        self.assertEqual(packet.render(self.result), PACKET.read_bytes())
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(packet.main(['--out', tmp, '--check']), 0)

    def _patch(self, va, new):
        broken = bytearray(self.data)
        sec = next(s for s in sections(self.data)
                   if s['type'] != 8 and s['address'] <= va < s['address'] + s['size'])
        off = sec['offset'] + va - sec['address']
        broken[off:off + len(new)] = new
        return bytes(broken)

    def _rejects(self, data):
        with self.assertRaises(ValueError):
            packet.bind(data, self.fdes)

    def test_addr_tag_offset_rejected(self):
        # movzx ecx, [r8+0x21] -> [r8+0x22]
        self._rejects(self._patch(0x537b8b2 + 4, b'\x22'))

    def test_key_compare_length_rejected(self):
        # memcmp 0x14 -> 0x15
        self._rejects(self._patch(0x537bb19 + 1, b'\x15'))

    def test_cap_rejected(self):
        # cmp rax, 0x897 -> 0x898
        self._rejects(self._patch(0x537bf33 + 2, b'\x98'))

    def test_resolve_byte_rejected(self):
        # mov byte [rbx+0x20], 0 -> 1
        self._rejects(self._patch(0x537c192 + 3, b'\x01'))

    def test_selected_digest_offset_rejected(self):
        # movdqu [rbx+0x21], xmm0 -> [rbx+0x22]
        self._rejects(self._patch(0x537c1a8 + 4, b'\x22'))

    def test_collection_offset_rejected(self):
        # lea rsi, [r14+0x20] -> [r14+0x28]
        self._rejects(self._patch(0x537c0ed + 3, b'\x28'))

    def test_twin_immediate_rejected(self):
        # mov edi, 0xb in the twin -> 0xc
        self._rejects(self._patch(0x5afaa84 + (0x5afadd0 - 0x5afa7f0), b'\x0c'))

    def test_location_line_rejected(self):
        # hash_signature_tracker.rs:107 -> 108
        self._rejects(self._patch(0x64bc860 + 0x10, b'\x6c'))


if __name__ == '__main__':
    unittest.main()
