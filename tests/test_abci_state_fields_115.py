"""Node #115 Exchange field names and abci hash slots. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import abci_state_fields_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-abci-state-fields-115/evidence.json'


class AbciStateFieldsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_table(self):
        fields = {f['name']: f['hash_slot_box_offset'] for f in self.result['fields']}
        self.assertEqual(len(fields), 59)
        self.assertEqual(fields['locus'], 'Locus group')
        self.assertEqual(fields['scheduled_freeze_height'], '0x10e8')
        self.assertEqual(fields['staking'], '0x3f08')
        self.assertEqual(fields['c_staking'], '0xd88')
        self.assertEqual(fields['lhvt'], '0x3d98')
        self.assertEqual(fields['advt'], '0x3e50')
        self.assertEqual(fields['msc'], '0x3908')
        self.assertEqual(self.result['msc_span'], ['0x3908', '0x3a00'])
        self.assertEqual([n for n, _ in self.result['single_byte_fields']],
                         ['spot_disabled', 'evm_enabled', 'hip3_no_cross', 'dex_abstraction_enabled'])
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

    def test_pool_rejected(self):
        # locus -> Locus
        self._rejects(self._patch(packet.POOL, b'L'))

    def test_locus_index_rejected(self):
        # xor ecx, ecx -> mov cl, 1
        self._rejects(self._patch(0x5477b69, b'\xb1\x01'))

    def test_advt_compare_rejected(self):
        # advt -> advu
        self._rejects(self._patch(0x5477ee8 + 5, b'\x75'))

    def test_msc_index_rejected(self):
        # mov cl, 0x3a -> 0x3b
        self._rejects(self._patch(0x5477c5a + 1, b'\x3b'))

    def test_unknown_index_rejected(self):
        # mov cl, 0x3b -> 0x3c
        self._rejects(self._patch(0x5478203 + 1, b'\x3c'))

    def test_bridge2_jump_rejected(self):
        # je rel32 + 0x10: lands off the bridge2 return block
        self._rejects(self._patch(0x5477b84 + 2, b'\xbb'))

    def test_builder_census_rejected(self):
        # first lea [r15+0x7c0] -> lea [r14+0x7c0]
        self._rejects(self._patch(0x4e34d06 + 2, b'\x86'))

    def test_msc_span_rejected(self):
        # last lea [r15+0x3908] -> [r15+0x39b0]: the pair is no longer inside msc
        self._rejects(self._patch(0x4e35146 + 3, b'\xb0\x39'))


if __name__ == '__main__':
    unittest.main()
