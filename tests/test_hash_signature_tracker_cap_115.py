"""Node #115 hash_signature_tracker cap, signer replace and 10/11 tag. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import hash_signature_tracker_cap_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-hash-signature-tracker-cap-115/evidence.json'


class HashSignatureTrackerCapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_censuses(self):
        self.assertEqual(self.result['cap']['count_direct_calls'], ['0x537b11e', '0x537bf2e'])
        self.assertEqual(self.result['repeat_signer']['key_insert_calls'], ['0x537b342', '0x537c152'])
        self.assertEqual(self.result['repeat_signer']['sender_insert_calls'], ['0x537b2f6', '0x537c106'])
        self.assertEqual(self.result['sha256'], packet.SHA256)
        self.assertFalse(self.result['gates_changed'])

    def test_committed_packet_matches(self):
        self.assertEqual(packet.render(self.result), PACKET.read_bytes())
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(packet.main(['--out', tmp, '--check']), 0)

    def _offset(self, va):
        sec = next(s for s in sections(self.data)
                   if s['type'] != 8 and s['address'] <= va < s['address'] + s['size'])
        return sec['offset'] + va - sec['address']

    def _patch(self, va, new):
        broken = bytearray(self.data)
        off = self._offset(va)
        broken[off:off + len(new)] = new
        return bytes(broken)

    def _rejects(self, data):
        with self.assertRaises(ValueError):
            packet.bind(data, self.fdes)

    def test_cap_rejected(self):
        # cmp rax, 0x897 -> 0x898
        self._rejects(self._patch(0x537bf33 + 2, b'\x98'))

    def test_resolved_skip_rejected(self):
        # je 0x4e40d90 -> jne (count the resolved digest)
        self._rejects(self._patch(0x4e40ff0 + 1, b'\x85'))

    def test_btree_hit_polarity_rejected(self):
        # xor al, 1 -> xor al, 0
        self._rejects(self._patch(0x4e4107f + 1, b'\x00'))

    def test_ring_hit_polarity_rejected(self):
        # sete al -> setne al
        self._rejects(self._patch(0x4e410bd + 1, b'\x95'))

    def test_collection_choice_rejected(self):
        # cmp byte [rax], 1 -> 0
        self._rejects(self._patch(0x4e40ffb + 2, b'\x00'))

    def test_replace_rejected(self):
        # mov ecx, 1 (Some(old)) -> 0
        self._rejects(self._patch(0x4dd2b8b + 1, b'\x00'))

    def test_tag_rejected(self):
        # mov edi, 11 -> 10 in the second update
        self._rejects(self._patch(0x5afb063 + 1, b'\x0a'))

    def test_location_line_rejected(self):
        # hash_signature_tracker.rs:107 -> 108
        self._rejects(self._patch(packet.LOC_107 + 16, b'\x6c'))


if __name__ == '__main__':
    unittest.main()
