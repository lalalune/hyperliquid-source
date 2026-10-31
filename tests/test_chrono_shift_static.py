"""Target-grounded controls for the static chrono shift-helpers packet (no node execution)."""
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import chrono_shift_static as cs
from elf_index import sections


class ChronoShiftEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not cs.TARGET.is_file() or cs.TARGET.stat().st_size != 91774280:
            raise unittest.SkipTest('Requires materialized node #94 Git LFS input')
        cls.result = cs.inspect(cs.TARGET)
        cls.data = cs.TARGET.read_bytes()
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
        record = cs.ROOT / 'research/work-items/RE-001-chrono-shift-helpers-94/evidence.json'
        self.assertEqual(self.result, json.loads(record.read_text()))

    def test_fde_bounds_and_body_identity(self):
        helpers = self.result['helpers']
        self.assertEqual(helpers['callee1']['start_va'], '0x15206e0')
        self.assertEqual(helpers['callee1']['end_va_exclusive'], '0x1520842')
        self.assertEqual(helpers['callee1']['bytes'], 354)
        self.assertEqual(helpers['callee1']['sha256'],
                         'f6d2c0cb541ca95cf1d97de0b4541242bdf72ea6e800d9715acc50b9f95e7e4e')
        self.assertEqual(helpers['callee2']['start_va'], '0x151f870')
        self.assertEqual(helpers['callee2']['end_va_exclusive'], '0x151fa9c')
        self.assertEqual(helpers['callee2']['bytes'], 556)
        self.assertEqual(helpers['callee2']['sha256'],
                         '5fc9431c76cedeeb8d87bfe5895752d8c87745d079472c66df7c147faed42b05')
        self.assertEqual(self.result['target_sha256'],
                         '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f')

    def test_chrono_location_anchors(self):
        time_lines = sorted(item['line'] for item in
                            self.result['chrono_anchors']['callee1_locations'])
        self.assertEqual(time_lines, [623, 627, 628, 632, 635, 639])
        self.assertTrue(all(item['path'] == 'naive/time/mod.rs'
                            for item in self.result['chrono_anchors']['callee1_locations']))
        date_paths = {item['path'] for item in
                      self.result['chrono_anchors']['callee2_locations']}
        self.assertEqual(date_paths, {'naive/date/mod.rs', 'naive/internals.rs'})
        shared = [item for item in self.result['chrono_anchors']['callee2_locations']
                  if item['line'] == 2334]
        self.assertEqual(len(shared), 1)
        self.assertEqual(shared[0]['column'], 5)

    def test_magic_division_identities(self):
        # Each decoded sequence is exact division over its grid: trunc for the
        # signed helpers, unsigned for the 365 variant.
        for n in range(-3_000_000, 3_000_001, 7_919):
            self.assertEqual(cs.day_quotient(n), cs.trunc_div(n, cs.SECS_PER_DAY))
        for n in range(-800_000_000, 800_000_001, 97):
            self.assertEqual(cs.cycle_quotient(n), cs.trunc_div(n, cs.CYCLE_DAYS))
        for n in range(-50_000_000, 50_000_001, 397):
            self.assertEqual(cs.year_quotient(n), cs.trunc_div(n, cs.YEAR_LIMIT))
        for n in range(0, 800_000_000, 367):
            self.assertEqual(cs.month_quotient(n), n // cs.DAYS_NORMAL)

    def test_mdl_table_shared_anchor(self):
        shared = self.result['chrono_anchors']['shared_with_prior_packets']['mdl_table']
        self.assertEqual(shared['va'], '0x250354')
        self.assertEqual(shared['entries'], 400)
        self.assertEqual(shared['sha256'], cs.MDL_TABLE_SHA256)
        self.assertEqual(cs.MDL_TABLE2, cs.MDL_TABLE + 401)
        first = self.data[self.offset(cs.MDL_TABLE):self.offset(cs.MDL_TABLE) + 16]
        self.assertEqual(first.hex(), '00010101010202020203030303040404')

    def test_identity_rejects_size_and_sha_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input'
            path.write_bytes(self.data[:4096])
            with self.assertRaisesRegex(ValueError, 'size/SHA-256'):
                cs.inspect(path)
            path.write_bytes(self.mutated(cs.C1_START, b'\x90'))
            with self.assertRaisesRegex(ValueError, 'size/SHA-256'):
                cs.inspect(path)

    def test_body_and_fde_mutations_rejected(self):
        for va in (cs.C1_START, cs.C1_START + 0xaf, cs.C1_START + 0xc4,
                   cs.C2_START, cs.C2_START + 0x73, cs.C2_START + 0x1a8):
            with self.assertRaisesRegex(ValueError, 'body bytes changed'):
                cs.analyze(self.mutated(va, b'\xcc'))
        with self.assertRaisesRegex(ValueError, 'callee1 FDE record changed'):
            cs.analyze(self.mutated(cs.C1_FDE_VA + 8, b'\x22\x22\x22\x22'))
        with self.assertRaisesRegex(ValueError, 'callee2 FDE record changed'):
            cs.analyze(self.mutated(cs.C2_FDE_VA + 8, b'\x22\x22\x22\x22'))

    def test_location_mutations_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Location layout changed'):
            cs.analyze(self.mutated(cs.C1_LOCATIONS[0][1] + 8, struct.pack('<I', 628)))
        rela = next(s for s in self.sections if s['name'] == '.rela.dyn')
        raw = self.data[rela['offset']:rela['offset'] + rela['size']]
        path_va = None
        for off in range(0, len(raw), 24):
            address, info, addend = struct.unpack_from('<QQq', raw, off)
            if info == 8 and address == cs.C2_LOCATIONS[0][1]:
                path_va = addend
        self.assertIsNotNone(path_va)
        with self.assertRaisesRegex(ValueError, 'chrono path changed'):
            cs.analyze(self.mutated(path_va + 40, b'X'))

    def test_relocation_mutations_rejected(self):
        rela = next(s for s in self.sections if s['name'] == '.rela.dyn')
        raw = self.data[rela['offset']:rela['offset'] + rela['size']]
        slots = {}
        for off in range(0, len(raw), 24):
            address, info, addend = struct.unpack_from('<QQq', raw, off)
            if info == 8 and (address in (cs.GOT_C1, cs.GOT_C2)
                              or address in cs.PANIC_TARGETS):
                slots[address] = (rela['address'] + off, addend)
        self.assertEqual(len(slots), 5)
        messages = {cs.GOT_C1: 'callee1 GOT slot changed',
                    cs.GOT_C2: 'callee2 GOT slot changed',
                    **{slot: f'panic GOT slot {slot:#x} changed'
                       for slot in cs.PANIC_TARGETS}}
        for va, (slot_va, addend) in slots.items():
            with self.assertRaisesRegex(ValueError, messages[va]):
                cs.analyze(self.mutated(slot_va + 16, struct.pack('<q', addend + 0x10)))

    def test_census_record(self):
        census = self.result['call_census']
        self.assertEqual(census['direct_e8'], 0)
        self.assertEqual(census['lea_references'], 0)
        self.assertEqual(census['got_mediated']['callee1'], 133)
        self.assertEqual(census['got_mediated']['callee2'], 150)
        # The ema window-guard body itself reaches both helpers through
        # exactly these GOT slots (see the window-guard packet).
        guard_sites = [0x474fbf3, 0x474fc46]
        for site in guard_sites:
            off = self.offset(site)
            self.assertEqual(self.data[off:off + 2], b'\xff\x15')
            disp = struct.unpack_from('<i', self.data, off + 2)[0]
            slot = site + 6 + disp
            self.assertIn(slot, (cs.GOT_C1, cs.GOT_C2))


if __name__ == '__main__':
    unittest.main()
