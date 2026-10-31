"""Target-grounded controls for the static day-count date packet (no node execution)."""
import datetime
import json
import struct
import sys
import unittest
import unittest.mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import daycount_date_static as dd
from elf_index import sections


class DayCountDateEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not dd.TARGET.is_file() or dd.TARGET.stat().st_size != 91774280:
            raise unittest.SkipTest('Requires materialized node #94 Git LFS input')
        cls.result = dd.inspect(dd.TARGET)
        cls.data = dd.TARGET.read_bytes()
        cls.sections = sections(cls.data)

    def test_retained_record_matches_authenticated_target(self):
        record = dd.ROOT / 'research/work-items/RE-001-daycount-date-94/evidence.json'
        self.assertEqual(self.result, json.loads(record.read_text()))

    def test_epoch_identity(self):
        identity = self.result['epoch_identity']
        self.assertEqual(identity['accessor_index'], '0xaf93b')
        self.assertEqual(identity['immediate'], 0x16d)
        self.assertEqual(identity['day_total'], 719528)
        resolved = identity['resolved']
        self.assertEqual((resolved['year'], resolved['ordinal']), (1970, 1))
        self.assertEqual(resolved['packed'], '0xf6401a')
        # Independent oracle agreement.
        oracle = datetime.date(1970, 1, 1)
        self.assertEqual((oracle.year, oracle.timetuple().tm_yday), (1970, 1))
        # 719528 is the standard proleptic day count from 0000-01-01.
        self.assertEqual(-dd.days_from_civil(0, 1, 1), 719528)
        self.assertEqual(dd.days_from_civil(1970, 1, 1), 0)

    def test_shared_tables(self):
        shared = self.result['shared_machinery']
        self.assertEqual(shared['leap_table']['entries'], 400)
        self.assertEqual(shared['leap_table']['sentinel_400'], 97)
        self.assertEqual(shared['year_flags']['entries'], 400)
        self.assertIn('RE-001-chrono-callees-94', shared['year_flags']['shared_with'])

    def test_day_cycle_exhaustive(self):
        table = dd.leap_table_model() + [97]
        for day in range(146097):
            year, ordinal = dd.year_and_ordinal(day, table)
            self.assertEqual(365 * year + table[year] + ordinal - 1, day, f'day {day}')
            self.assertTrue(1 <= ordinal <= 366, f'ordinal {ordinal} for day {day}')

    def test_panic_locations_shared_with_callees_packet(self):
        locations = self.result['shared_machinery']['panic_locations']
        self.assertEqual(sorted(locations),
                         ['date/mod.rs:2325:9', 'date/mod.rs:2326:27',
                          'date/mod.rs:2326:9', 'internals.rs:80:9'])

    def test_census_is_largest_shared_helper(self):
        census = self.result['call_census']
        self.assertEqual(census['got_indirect_sites'], 324)
        self.assertEqual(census['direct_e8'], 0)
        self.assertEqual(census['lea_refs'], 0)
        self.assertEqual(len(dd.CALLERS), 324)
        self.assertEqual(census['accessor_site'], '0x3790ff0 (RE-001-lock-descriptor-94)')
        self.assertIn(0x3790ff0, dd.CALLERS)

    def test_mutation_control_body(self):
        mutated = bytearray(dd.BODY)
        mutated[len(mutated) // 2] ^= 0xFF
        with unittest.mock.patch.object(dd, 'BODY', bytes(mutated)):
            with self.assertRaises(ValueError):
                dd.analyze(self.data)

    def test_mutation_control_epoch_constant(self):
        # Corrupt the +365 immediate: the epoch identity must fail loudly.
        with unittest.mock.patch.object(dd, 'DAY_OFFSET_IMM', 366):
            with self.assertRaises(ValueError):
                dd.analyze(self.data)


if __name__ == '__main__':
    unittest.main()
