"""Target-grounded controls for the static fees packet (no node execution)."""
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import fees_compute_static as fc
from elf_index import sections


class FeesComputeEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not fc.TARGET.is_file() or fc.TARGET.stat().st_size != 91774280:
            raise unittest.SkipTest('Requires materialized node #94 Git LFS input')
        cls.result = fc.inspect(fc.TARGET)
        cls.data = fc.TARGET.read_bytes()
        cls.sections = sections(cls.data)

    def offset(self, va):
        matches = [s for s in self.sections if s['type'] != 8
                   and s['address'] <= va < s['address'] + s['size']]
        self.assertEqual(len(matches), 1)
        s = matches[0]
        return s['offset'] + va - s['address']

    def mutated(self, va, raw):
        data = bytearray(self.data)
        off = self.offset(va)
        data[off:off + len(raw)] = raw
        return bytes(data)

    def test_retained_record_matches_authenticated_target(self):
        record = fc.ROOT / 'research/work-items/fees-compute-94/evidence.json'
        self.assertEqual(self.result, json.loads(record.read_text()))

    def test_fde_bounds_and_body_identity(self):
        fn = self.result['function']
        self.assertEqual(fn['start_va'], '0x37153f0')
        self.assertEqual(fn['end_va_exclusive'], '0x3715e8b')
        self.assertEqual(fn['bytes'], 2715)

    def test_location_anchors(self):
        locs = self.result['locations']
        self.assertEqual((locs['fees']['line'], locs['fees']['column']), (50, 42))
        self.assertEqual(locs['perp_meta']['line'], 194)
        self.assertEqual(locs['impl_ntl']['inline_sites'], 6)
        self.assertEqual(locs['qtys_mod']['line'], 843)
        self.assertEqual(locs['core_num']['rustc_commit'],
                         'e408947bfd200af42db322daf0fadfe7e26d3bd1')

    def test_identity_rejects_truncation_and_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input'
            path.write_bytes(self.data[:4096])
            with self.assertRaisesRegex(ValueError, 'size/SHA-256'):
                fc.inspect(path)
            path.write_bytes(self.mutated(fc.START, b'\x90'))
            with self.assertRaisesRegex(ValueError, 'size/SHA-256'):
                fc.inspect(path)

    def test_body_fde_and_window_mutations_rejected(self):
        for va in (fc.START, fc.START + 0x299, 0x3715bc9, 0x3715c29):
            with self.assertRaisesRegex(ValueError, 'Fee body bytes changed'):
                fc.analyze(self.mutated(va, b'\xcc'))
        with self.assertRaisesRegex(ValueError, 'Fee FDE record changed'):
            fc.analyze(self.mutated(fc.FDE_VA + 8, b'\x55\x55\x55\x55'))

    def test_anchor_mutations_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Location layout changed'):
            fc.analyze(self.mutated(fc.FEES_LOC + 16, struct.pack('<I', 51)))
        with self.assertRaisesRegex(ValueError, 'Location path changed'):
            fc.analyze(self.mutated(fc.FEES_PATH_VA + 6, b'X'))
        with self.assertRaisesRegex(ValueError, 'Location layout changed'):
            fc.analyze(self.mutated(fc.NTL_LOC + 16, struct.pack('<I', 665)))
        with self.assertRaisesRegex(ValueError, '0.1 fee constant changed'):
            fc.analyze(self.mutated(fc.TENTH_VA, struct.pack('<d', 0.2)))
        with self.assertRaisesRegex(ValueError, '1.0 constant changed'):
            fc.analyze(self.mutated(fc.ONE_VA, struct.pack('<d', 2.0)))

    def test_relocation_mutations_rejected(self):
        rela = next(s for s in self.sections if s['name'] == '.rela.dyn')
        raw = self.data[rela['offset']:rela['offset'] + rela['size']]
        slots = {}
        for off in range(0, len(raw), 24):
            address, info, addend = struct.unpack_from('<QQq', raw, off)
            if info == 8 and address in (fc.GOT_PANIC_DISPLAY, fc.GOT_LOCK_HELPER,
                                         fc.GOT_PANIC_FMT, fc.GOT_SELF,
                                         fc.FEES_LOC, fc.NTL_LOC):
                slots[address] = (rela['address'] + off, addend)
        self.assertEqual(len(slots), 6)
        messages = {fc.GOT_PANIC_DISPLAY: 'Panic display callee changed',
                    fc.GOT_LOCK_HELPER: 'Lock helper GOT changed',
                    fc.GOT_PANIC_FMT: 'Panic fmt callee changed',
                    fc.GOT_SELF: 'Self GOT slot changed',
                    fc.FEES_LOC: 'FEES Location relocation changed|Location path changed|Ambiguous or unmapped',
                    fc.NTL_LOC: 'Location path changed|Location relocation missing|Ambiguous or unmapped|Location layout changed'}
        for va, (slot_va, addend) in slots.items():
            with self.assertRaisesRegex(ValueError, messages[va]):
                fc.analyze(self.mutated(slot_va + 16, struct.pack('<q', addend + 4)))

    def test_call_census(self):
        census = self.result['call_census']
        self.assertEqual(census['got_indirect'],
                         ['0x24fc475', '0x4329c95', '0x432a525'])
        self.assertEqual(census['direct_e8'], 0)


if __name__ == '__main__':
    unittest.main()
