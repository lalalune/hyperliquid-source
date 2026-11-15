"""Node #115 digest quorum vote resolution. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import digest_quorum_votes_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-digest-quorum-votes-115/evidence.json'


class DigestQuorumVotesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_census(self):
        census = self.result['census']
        self.assertEqual(census['walker']['direct_calls'], ['0x5afa5f4'])
        self.assertEqual(census['predicate']['direct_calls'], ['0x36c82e4'])
        self.assertEqual(census['voter_sum']['direct_calls'], ['0x422e100'])
        self.assertEqual(len(census['stake_check']['direct_calls']), 13)
        self.assertIn('0x5374b70', census['stake_check']['callers'])
        self.assertFalse(self.result['gates_changed'])

    def test_predicate_samples(self):
        self.assertEqual(self.result['predicate']['samples'],
                         {'sum=3,S=2': False, 'sum=3,S=3': True, 'sum=300,S=201': True,
                          'sum=300,S=200': False, 'tag=0': False, 'sum=2**63,S=2**63': True})

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

    def test_multiplier_rejected(self):
        # mov edx, 3 -> 2
        self._rejects(self._patch(0x422e24d + 1, b'\x02'))

    def test_compare_sense_rejected(self):
        # setb al -> setae al
        self._rejects(self._patch(0x422e25e + 1, b'\x93'))

    def test_pending_flag_offset_rejected(self):
        # cmp byte [rdx+0x20], 0 -> [rdx+0x21]
        self._rejects(self._patch(0x5374d59 + 2, b'\x21'))

    def test_resolution_clear_rejected(self):
        # mov byte [rax+0x20], 0 -> 1
        self._rejects(self._patch(0x5375588 + 3, b'\x01'))

    def test_resolved_key_offset_rejected(self):
        # movups [rax+0x21], xmm0 -> [rax+0x22]
        self._rejects(self._patch(0x5375596 + 3, b'\x22'))

    def test_error_tag_rejected(self):
        # mov word [rsp+0x20], 0x9b -> 0x9c
        self._rejects(self._patch(0x36c80a3 + 5, b'\x9c'))

    def test_second_gate_rejected(self):
        # seta bl -> setae bl
        self._rejects(self._patch(0x5375500 + 1, b'\x93'))

    def test_predicate_call_rejected(self):
        # call 0x422e0f0 retargeted by one byte
        self._rejects(self._patch(0x36c82e4 + 1, b'\x08'))


if __name__ == '__main__':
    unittest.main()
