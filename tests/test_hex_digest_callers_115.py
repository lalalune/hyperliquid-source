"""Node #115 0x-prefixed hex encoder call census. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import hex_digest_callers_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-hex-digest-callers-115/evidence.json'


class HexDigestCallersTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_census(self):
        census = self.result['census']
        self.assertEqual((census['slot_calls'], census['fixed_shape_sites'], census['other_sites']), (629, 609, 20))
        self.assertEqual(census['slot_loads'], 39)
        shapes = {k: v['sites'] for k, v in self.result['fixed_shapes'].items()}
        self.assertEqual(shapes, {'20_bytes': 440, '32_bytes': 123, '16_bytes': 46})
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

    def test_prefix_rejected(self):
        # "0x" -> "0X"
        self._rejects(self._patch(0x2eabb62 + 4, b'X'))

    def test_trim_test_rejected(self):
        # test r8b, r11b -> test r8b, r10b
        self._rejects(self._patch(0x2eabb84 + 2, b'\xd0'))

    def test_hex_table_rejected(self):
        # lowercase table -> 'A' at index 10
        self._rejects(self._patch(packet.TABLE + 10, b'A'))

    def test_capacity_check_rejected(self):
        # lea rax, [rcx*2+1] -> [rcx*2+2]
        self._rejects(self._patch(0x2eabb51 + 4, b'\x02'))

    def test_leaf_length_rejected(self):
        # leaf site mov ecx, 0x20 -> 0x21
        self._rejects(self._patch(0x41c51fb + 1, b'\x21'))

    def test_shape_capacity_rejected(self):
        # first 20-byte site: mov esi, 0x2a -> 0x2b (capacity no longer 2*len+2)
        self._rejects(self._patch(0x21f392d + 1, b'\x2b'))

    def test_leaf_trim_rejected(self):
        # leaf site xor r8d, r8d -> xor r9d, r9d: site leaves the fixed 32-byte shape
        self._rejects(self._patch(0x41c5200 + 2, b'\xc9'))

    def test_direct_call_rejected(self):
        # turn the slot call at the first 20-byte site into call rel32 to the encoder
        site = 0x21f393d
        rel = (packet.ENCODER - (site + 5)).to_bytes(4, 'little', signed=True)
        self._rejects(self._patch(site, b'\xe8' + rel + b'\x90'))


if __name__ == '__main__':
    unittest.main()
