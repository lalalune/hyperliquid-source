"""Node #115 framers in 0x25ebdb0..0x25f7350 and their writer names. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import framer_writer_names_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-framer-writer-names-115/evidence.json'


class FramerWriterNamesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_census(self):
        self.assertEqual(self.result['counts'], {'framers': 30, 'time_writer': 28, 'bare': 2, 'tied': 2})
        tied = {r['framer']: r['writer'] for r in self.result['framers'] if r['writer'] != 'untied'}
        self.assertEqual(tied, {'0x25f19b0': 'abci_hashes', '0x25f4be0': 'abci_digest_quorum'})
        self.assertEqual(self.result['sha256'], packet.SHA256)
        self.assertFalse(self.result['gates_changed'])

    def test_twins_and_edges(self):
        self.assertEqual([t['differing_fields'] for t in self.result['twins']], [11, 11, 9, 7, 10, 3])
        self.assertEqual(self.result['tied_edges']['0x25f19b0'],
                         {'wrapper': '0x2d4ca40', 'call': '0x2bb38e9', 'in': '0x2bb37c0'})
        self.assertEqual(sorted(self.result['wrapper_caller_clusters']['0x2accee0']['framers'])[0], '0x25ecc10')

    def test_committed_packet_matches(self):
        self.assertEqual(packet.render(self.result), PACKET.read_bytes())
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(packet.main(['--out', tmp, '--check']), 0)

    def _patch(self, va, new):
        broken = bytearray(self.data)
        sec = next(s for s in sections(self.data) if s['type'] != 8 and s['address'] <= va < s['address'] + s['size'])
        off = sec['offset'] + va - sec['address']
        broken[off:off + len(new)] = new
        return bytes(broken)

    def _rejects(self, data):
        with self.assertRaises(ValueError):
            packet.bind(data, self.fdes)

    def test_field_name_rejected(self):
        # exchange_abci_hash -> exchange_abci_hasH in the catch-up string copy
        self._rejects(self._patch(0x5ff773 + 17, b'H'))

    def test_d_field_rejected(self):
        # the one-byte field name d -> e
        self._rejects(self._patch(0x5fec4d, b'e'))

    def test_framer_body_rejected(self):
        # a non-displacement byte inside the abci_hashes framer twin
        self._rejects(self._patch(0x25f19b0, b'\x90'))

    def test_serializer_body_rejected(self):
        self._rejects(self._patch(0x28b5780, b'\x90'))

    def test_wrapper_body_rejected(self):
        self._rejects(self._patch(0x2d4ca40, b'\x90'))

    def test_caller_window_rejected(self):
        # mov rdi, [rsp+0x18] -> [rsp+0x20] before the wrapper call
        self._rejects(self._patch(0x2bb38e4 + 4, b'\x20'))

    def test_caller_edge_rejected(self):
        # retarget the call at 0x2bb38e9 by one byte
        raw = packet.read_va(self.data, 0x2bb38ea, 1)
        self._rejects(self._patch(0x2bb38ea, bytes([(raw[0] + 1) & 0xff])))

    def test_time_writer_census_rejected(self):
        # break one framer's call to the time writer 0x2506050 (call at 0x25ebe18)
        raw = packet.read_va(self.data, 0x25ebe19, 1)
        self._rejects(self._patch(0x25ebe19, bytes([(raw[0] + 1) & 0xff])))


if __name__ == '__main__':
    unittest.main()
