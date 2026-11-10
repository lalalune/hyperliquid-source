"""Node #115 digest quorum vote insert path. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import digest_quorum_vote_insert_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-digest-quorum-vote-insert-115/evidence.json'


class DigestQuorumVoteInsertTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_census(self):
        census = self.result['census']
        self.assertEqual(census['update']['callers'], ['0x5862560', '0x5862770'])
        self.assertEqual(census['update2']['callers'], ['0x5869400', '0x5869610'])
        self.assertEqual(census['vote_insert']['direct_calls'], ['0x5afab8f'])
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

    def test_signer_mismatch_tag_rejected(self):
        # mov cx, 0x12e -> 0x12f
        self._rejects(self._patch(0x5862635 + 2, b'\x2f'))

    def test_signer_compare_rejected(self):
        # je equal -> jne
        self._rejects(self._patch(0x5862633, b'\x75'))

    def test_height_bound_rejected(self):
        # jae -> jb
        self._rejects(self._patch(0x5862666 + 1, b'\x82'))

    def test_store_offset_rejected(self):
        # lea rsi, [rdx+0x3d98] -> [rdx+0x3d99]
        self._rejects(self._patch(0x5862671 + 3, b'\x99'))

    def test_layout_b_offset_rejected(self):
        # lea rsi, [rdx+0x4908] -> [rdx+0x4909]
        self._rejects(self._patch(0x5862881 + 3, b'\x09'))

    def test_sender_key_length_rejected(self):
        # mov edx, 0x14 -> 0x15
        self._rejects(self._patch(0x5afa949 + 1, b'\x15'))

    def test_vote_insert_call_rejected(self):
        # call 0x537b870 rel32 low byte +1
        self._rejects(self._patch(0x5afab8f + 1, b'\xdd'))

    def test_slot_relocation_target_rejected(self):
        # store +0x18 lea -> +0x19
        self._rejects(self._patch(0x537b96c + 3, b'\x19'))


if __name__ == '__main__':
    unittest.main()
