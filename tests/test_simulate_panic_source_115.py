"""Node #115 Exchange / Locus deserialisers behind the abci box. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import simulate_panic_source_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-simulate-panic-source-115/evidence.json'


class SimulatePanicSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_bound_facts(self):
        ex = self.result['exchange_visitors']
        self.assertEqual(ex['expected'], 'struct Exchange with 59 elements')
        self.assertEqual(ex['all_relocations_to_string'],
                         ['0x641f220', '0x64222d8', '0x6464800', '0x647d590', '0x6499c28'])
        self.assertEqual(self.result['locus_visitor']['expected'], 'struct Locus with 16 elements')
        self.assertEqual(self.result['sha256'], packet.SHA256)

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

    def test_exchange_string_rejected(self):
        self._rejects(self._patch(0x457700 + 7, b'X'))

    def test_locus_string_rejected(self):
        self._rejects(self._patch(0x794eba + 7, b'X'))

    def test_exchange_record_length_rejected(self):
        self._rejects(self._patch(0x641f220 + 8, b'\x21'))

    def test_key_rejected(self):
        # 'exchange' -> 'exchangf'
        self._rejects(self._patch(0x1b454db + 9, b'\x66'))

    def test_box_size_rejected(self):
        self._rejects(self._patch(0x1b450f1 + 1, b'\xa9'))

    def test_selector_store_rejected(self):
        # [rbx+0xb9a] -> [rbx+0xb9b]
        self._rejects(self._patch(0x2fc32ad + 2, b'\x9b'))

    def test_out_pointer_rejected(self):
        self._rejects(self._patch(0x2fc21f0 + 2, b'\xfe'))

    def test_caller_census_rejected(self):
        # break the second caller of 0x199ce60 (e8 -> 90)
        self._rejects(self._patch(0x1b4587b, b'\x90'))


if __name__ == '__main__':
    unittest.main()
