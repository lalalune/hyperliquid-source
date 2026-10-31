"""Target-grounded controls for the static chrono callee-pair packet (no node execution)."""
import json
import struct
import sys
import unittest
import unittest.mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import chrono_callees_static as cc
from elf_index import sections


class ChronoCalleesEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not cc.TARGET.is_file() or cc.TARGET.stat().st_size != 91774280:
            raise unittest.SkipTest('Requires materialized node #94 Git LFS input')
        cls.result = cc.inspect(cc.TARGET)
        cls.data = cc.TARGET.read_bytes()
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
        record = cc.ROOT / 'research/work-items/RE-001-chrono-callees-94/evidence.json'
        self.assertEqual(self.result, json.loads(record.read_text()))

    def test_leap_table_matches_gregorian_model(self):
        model = cc.leap_table_model()
        self.assertEqual(len(model), 400)
        self.assertEqual(model[-1], 97)   # 97 leap days per 400-year cycle
        self.assertEqual(model[0], 0)
        self.assertEqual(model[1], 1)     # cycle year 0 (1 BC) is leap
        self.assertEqual(model[100], 25)  # centuries 100/200/300 are not leap
        self.assertEqual(model[101], 25)
        # The table carries a 401st sentinel byte read by the estimate path.
        sentinel = self.result['tables']['leap_cumulative']['sentinel_entry_400']
        self.assertEqual(sentinel, 97)

    def test_year_flag_table_matches_gregorian_model(self):
        flags = cc.year_flag_model()
        self.assertEqual(len(flags), 400)
        self.assertEqual(sum(1 for f in flags if f < 8), 97)  # leap entries
        self.assertTrue(all(1 <= (f & 7) <= 7 for f in flags))
        self.assertNotIn(8, flags)  # class 0 never occurs; leap years keep < 8
        # 1970 is cycle year 1970 % 400 = 370, a common year whose Jan 1 is day 0.
        self.assertEqual(flags[370], 8 | ((0 + 1) % 7 + 1))

    def test_day_cycle_identity_exhaustive(self):
        table = cc.leap_table_model() + [97]
        for day in range(146097):
            year, ordinal = cc.year_and_ordinal_from_day(day, table)
            self.assertEqual(365 * year + table[year] + ordinal - 1, day, f'day {day}')
            self.assertTrue(1 <= ordinal <= 366, f'ordinal {ordinal} for day {day}')

    def test_division_sequences(self):
        # Day division decomposes signed totals euclideanly.
        for x in (-172800, -86401, -1, 0, 1, 86399, 86400, 86401, 123456789):
            secs, whole = cc.day_division_sequence(x)
            self.assertEqual((secs, whole),
                             (cc.euclid_mod(x, 86400), cc.euclid_div(x, 86400) * 86400))
        # The 400 and 146097 divisions keep trunc-style quotients with
        # explicitly normalized euclidean remainders.
        for value in (-803, -400, -1, 0, 1, 399, 262143):
            q, r = cc.div400_sequence(value)
            self.assertEqual(r, cc.euclid_mod(value, 400))
            self.assertTrue(abs(value - q * 400) < 400)
        for value in (-584388, -146097, -1, 0, 1, 146096, 146097):
            q, r = cc.div146097_sequence(value)
            self.assertEqual(r, cc.euclid_mod(value, 146097))
            self.assertTrue(abs(value - q * 146097) < 146097)

    def test_chrono_panic_anchors(self):
        anchors = self.result['panic_anchors']
        time_lines = sorted(l['line'] for l in anchors['time_mod'])
        self.assertEqual(time_lines, [623, 627, 628, 632, 635, 639])
        date_lines = sorted(l['line'] for l in anchors['date_mod'])
        self.assertEqual(date_lines, [2325, 2326, 2326, 2334])
        internals = anchors['internals'][0]
        self.assertEqual((internals['line'], internals['column']), (80, 9))
        self.assertEqual(internals['table_length_operands'], [400, 401])
        # The datediff core's year-0 Location (2334:5) is reused here.
        self.assertIn(dict(location_va='0x5672188', line=2334, column=5),
                      anchors['date_mod'])

    def test_mutation_control_bodies(self):
        # One byte inside each body must break the authenticated binding.
        for start, old in [(cc.C1_START, cc.C1_BODY), (cc.C2_START, cc.C2_BODY)]:
            mutated = bytearray(old)
            mutated[len(mutated) // 2] ^= 0xFF
            with unittest.mock.patch.object(cc, 'C1_BODY' if start == cc.C1_START else 'C2_BODY',
                                            bytes(mutated)):
                with self.assertRaises(ValueError):
                    cc.analyze(self.data)

    def test_mutation_control_fde_and_location(self):
        # Flip one byte of callee 1's FDE record.
        fde = bytearray(cc.C1_FDE)
        fde[10] ^= 0x01
        with unittest.mock.patch.object(cc, 'C1_FDE', bytes(fde)):
            with self.assertRaises(ValueError):
                cc.analyze(self.data)
        # Corrupt the line field of a time/mod.rs panic Location.
        off = self.offset(0x5672350 + 16)
        data = bytearray(self.data)
        data[off:off + 4] = struct.pack('<I', 9999)
        with self.assertRaises(ValueError):
            cc.analyze(bytes(data))
        # Corrupt the .rela.dyn addend behind GOT slot 0x576e118.
        rela = next(s for s in self.sections if s['name'] == '.rela.dyn')
        base = self.offset(rela['address'])
        data = bytearray(self.data)
        for entry in range(base, base + rela['size'], 24):
            if struct.unpack_from('<Q', data, entry)[0] == cc.GOT_PANIC_A:
                addend = struct.unpack_from('<q', data, entry + 16)[0]
                data[entry + 16:entry + 24] = struct.pack('<q', addend + 8)
                break
        else:
            self.fail('relocation entry for GOT slot A not found')
        with self.assertRaises(ValueError):
            cc.analyze(bytes(data))

    def test_census_and_guard_crosslink(self):
        census = self.result['call_census']
        self.assertEqual(census['callee_time']['got_indirect_sites'], 133)
        self.assertEqual(census['callee_date']['got_indirect_sites'], 150)
        self.assertEqual(census['callee_time']['direct_e8'], 0)
        self.assertEqual(census['callee_date']['direct_e8'], 0)
        # The ema window guard (separate packet) calls both callees in-body.
        self.assertTrue(cc.GUARD_START <= 0x474fbf3 < cc.GUARD_END)
        self.assertTrue(cc.GUARD_START <= 0x474fc46 < cc.GUARD_END)
        self.assertIn(0x474fbf3, cc.C1_CALLERS)
        self.assertIn(0x474fc46, cc.C2_CALLERS)


if __name__ == '__main__':
    unittest.main()
