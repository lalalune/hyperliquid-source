"""Target-grounded controls for the static chrono datetime-Sub packet (no node execution)."""
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import chrono_dtsub_static as ds
from elf_index import sections


class ChronoDtSubEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not ds.TARGET.is_file() or ds.TARGET.stat().st_size != 91774280:
            raise unittest.SkipTest('Requires materialized node #94 Git LFS input')
        cls.result = ds.inspect(ds.TARGET)
        cls.data = ds.TARGET.read_bytes()
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
        record = ds.ROOT / 'research/work-items/RE-001-chrono-datetime-sub-94/evidence.json'
        self.assertEqual(self.result, json.loads(record.read_text()))

    def test_fde_bounds_and_body_identity(self):
        wrapper = self.result['wrapper']
        self.assertEqual(wrapper['start_va'], '0x151d080')
        self.assertEqual(wrapper['end_va_exclusive'], '0x151d1a4')
        self.assertEqual(wrapper['bytes'], 292)
        self.assertEqual(wrapper['sha256'],
                         '3f96a01676715f243bd1b5a5e72e1558584e55a767468634fcf142c158191b15')
        self.assertEqual(self.result['target_sha256'],
                         '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f')

    def test_chrono_location_anchors(self):
        locations = {(item['path'], item['line'], item['column'])
                     for item in self.result['chrono_anchors']['locations']}
        self.assertIn(('time_delta.rs', 475, 27), locations)
        self.assertIn(('time_delta.rs', 473, 26), locations)
        self.assertIn(('naive/time/mod.rs', 670, 16), locations)

    def test_negation_and_range_anchors(self):
        negation = self.result['chrono_anchors']['negation']
        self.assertEqual(negation['nanos_complement'], 1000000000)
        self.assertEqual(negation['secs_borrow'], -1)
        gates = self.result['chrono_anchors']['range_gates']
        self.assertEqual(gates['datetime']['low'], '0xffff574000000000')
        self.assertEqual(gates['datetime']['high'], '0xfffeae7ffffeae81')
        # The same constants the ema window-guard packet bounds.
        sentinel = self.result['chrono_anchors']['sentinel']
        self.assertEqual(sentinel['value'], '0x8000000000000000')

    def test_unsigned_day_division_identity(self):
        # The decoded sequence computes n // 86400 exactly for the
        # non-negative day carry (shr 63 / shr 13, logical shifts).
        for n in list(range(0, 4_000_000, 7919)) + [10**9, 10**12]:
            self.assertEqual(ds.unsigned_day_quotient(n), n // ds.SECS_PER_DAY)

    def test_identity_rejects_size_and_sha_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input'
            path.write_bytes(self.data[:4096])
            with self.assertRaisesRegex(ValueError, 'size/SHA-256'):
                ds.inspect(path)
            path.write_bytes(self.mutated(ds.START, b'\x90'))
            with self.assertRaisesRegex(ValueError, 'size/SHA-256'):
                ds.inspect(path)

    def test_body_and_fde_mutations_rejected(self):
        for va in (ds.START, ds.START + 0x19, ds.START + 0x66, ds.START + 0xab,
                   ds.START + 0xb9):
            with self.assertRaisesRegex(ValueError, 'body bytes changed'):
                ds.analyze(self.mutated(va, b'\xcc'))
        with self.assertRaisesRegex(ValueError, 'Wrapper FDE record changed'):
            ds.analyze(self.mutated(ds.FDE_VA + 8, b'\x22\x22\x22\x22'))

    def test_location_mutations_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Location layout changed'):
            ds.analyze(self.mutated(ds.LOCATIONS[0][1] + 8, struct.pack('<I', 476)))
        rela = next(s for s in self.sections if s['name'] == '.rela.dyn')
        raw = self.data[rela['offset']:rela['offset'] + rela['size']]
        path_va = None
        for off in range(0, len(raw), 24):
            address, info, addend = struct.unpack_from('<QQq', raw, off)
            if info == 8 and address == ds.LOCATIONS[1][1]:
                path_va = addend
        self.assertIsNotNone(path_va)
        with self.assertRaisesRegex(ValueError, 'chrono path changed'):
            ds.analyze(self.mutated(path_va + 40, b'X'))

    def test_relocation_mutations_rejected(self):
        rela = next(s for s in self.sections if s['name'] == '.rela.dyn')
        raw = self.data[rela['offset']:rela['offset'] + rela['size']]
        slots = {}
        for off in range(0, len(raw), 24):
            address, info, addend = struct.unpack_from('<QQq', raw, off)
            if info == 8 and address in (ds.GOT_C1, ds.GOT_C2, ds.GOT_PANIC_NEW,
                                         ds.GOT_PANIC_SHARED, ds.GOT_SELF):
                slots[address] = (rela['address'] + off, addend)
        self.assertEqual(len(slots), 5)
        messages = {ds.GOT_C1: 'callee1 GOT slot changed',
                    ds.GOT_C2: 'callee2 GOT slot changed',
                    ds.GOT_PANIC_NEW: 'new panic GOT slot changed',
                    ds.GOT_PANIC_SHARED: 'shared panic GOT slot changed',
                    ds.GOT_SELF: 'wrapper GOT slot changed'}
        for va, (slot_va, addend) in slots.items():
            with self.assertRaisesRegex(ValueError, messages[va]):
                ds.analyze(self.mutated(slot_va + 16, struct.pack('<q', addend + 0x10)))

    def test_census_record(self):
        census = self.result['call_census']
        self.assertEqual(census['direct_e8'], 0)
        self.assertEqual(census['lea_references'], 0)
        self.assertEqual(census['got_mediated'],
                         ['0x151c698', '0x2229fd4', '0x470f1b4', '0x4717007'])
        helper = self.result['helper_got']
        self.assertEqual(helper['callee1']['slot'], '0x576e8a8')
        self.assertEqual(helper['callee2']['slot'], '0x576e8b0')


if __name__ == '__main__':
    unittest.main()
