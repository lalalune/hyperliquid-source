"""Target-grounded controls for the static chrono difference core packet (no node execution)."""
import datetime
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import datediff_static as dd
from elf_index import sections


class DateDiffEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not dd.TARGET.is_file() or dd.TARGET.stat().st_size != 91774280:
            raise unittest.SkipTest('Requires materialized node #94 Git LFS input')
        cls.result = dd.inspect(dd.TARGET)
        cls.data = dd.TARGET.read_bytes()
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
        record = dd.ROOT / 'research/work-items/RE-001-datediff-chrono-94/evidence.json'
        self.assertEqual(self.result, json.loads(record.read_text()))

    def test_leap_table_matches_gregorian_model(self):
        model = dd.leap_table_model()
        self.assertEqual(len(model), 400)
        # 97 leap days per 400-year cycle; the table counts them before each year.
        self.assertEqual(model[-1], 97)   # before cycle year 399 (year 0 leap included)
        self.assertEqual(max(model), 97)  # 97 leap days per full cycle
        self.assertEqual(model[0], 0)
        self.assertEqual(model[1], 1)     # cycle year 0 (1 BC) is leap
        self.assertEqual(model[100], 25)  # centuries 100/200/300 are not leap
        self.assertEqual(model[101], 25)

    def test_day_count_identity_against_python_calendar(self):
        base = datetime.date(1, 1, 1).toordinal()
        for year in (1, 4, 100, 400, 1970, 2000, 2026):
            for ord0 in (0, 59, 364, 365):
                if ord0 == 365 and not _is_leap(year):
                    continue
                calendar_day = datetime.date(year, 1, 1).toordinal() + ord0
                q, r = divmod(year, 400)
                binary_day = 146097 * q + 365 * r + dd.leap_table_model()[r] + ord0
                self.assertEqual(binary_day - (365 + dd.leap_table_model()[1]),
                                 calendar_day - base)

    def test_era_constants(self):
        constants = self.result['era_constants']
        self.assertEqual(constants['cycle_days'], 146097)
        self.assertEqual(constants['days_per_year'], 365)
        self.assertEqual(constants['secs_per_day'], 86400)
        self.assertEqual(constants['nanos_per_second'], 1000000000)

    def test_identity_rejects_truncation_and_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input'
            path.write_bytes(self.data[:4096])
            with self.assertRaisesRegex(ValueError, 'size/SHA-256'):
                dd.inspect(path)
            path.write_bytes(self.mutated(dd.START, b'\x90'))
            with self.assertRaisesRegex(ValueError, 'size/SHA-256'):
                dd.inspect(path)

    def test_body_fde_and_immediate_mutations_rejected(self):
        for va in (dd.START, dd.START + 0x10, dd.START + 0x163):
            with self.assertRaisesRegex(ValueError, 'Difference core body bytes changed'):
                dd.analyze(self.mutated(va, b'\xcc'))
        with self.assertRaisesRegex(ValueError, 'Difference core FDE record changed'):
            dd.analyze(self.mutated(dd.FDE_VA + 8, b'\x11\x11\x11\x11'))

    def test_leap_table_and_location_mutations_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Leap table no longer matches'):
            dd.analyze(self.mutated(dd.TABLE_VA + 5, b'\x63'))
        with self.assertRaisesRegex(ValueError, 'Panic Location layout changed'):
            dd.analyze(self.mutated(dd.LOC_VA + 8, struct.pack('<I', 2335)))
        with self.assertRaisesRegex(ValueError, 'chrono path changed'):
            rela = next(s for s in self.sections if s['name'] == '.rela.dyn')
            raw = self.data[rela['offset']:rela['offset'] + rela['size']]
            path_va = None
            for off in range(0, len(raw), 24):
                address, info, addend = struct.unpack_from('<QQq', raw, off)
                if info == 8 and address == dd.LOC_VA:
                    path_va = addend
            self.assertIsNotNone(path_va)
            dd.analyze(self.mutated(path_va + 40, b'X'))

    def test_relocation_mutations_rejected(self):
        rela = next(s for s in self.sections if s['name'] == '.rela.dyn')
        raw = self.data[rela['offset']:rela['offset'] + rela['size']]
        slots = {}
        for off in range(0, len(raw), 24):
            address, info, addend = struct.unpack_from('<QQq', raw, off)
            if info == 8 and address in (dd.GOT_PANIC, dd.GOT_SELF, dd.LOC_VA):
                slots[address] = (rela['address'] + off, addend)
        self.assertEqual(len(slots), 3)
        messages = {dd.GOT_PANIC: 'Panic callee GOT slot changed',
                    dd.GOT_SELF: 'Self GOT slot changed',
                    dd.LOC_VA: 'Panic Location relocation missing'}
        for va, (slot_va, addend) in slots.items():
            if va == dd.LOC_VA:
                # Removing the relocation entirely is covered by the missing
                # check; shifting the path addend changes the referenced path.
                with self.assertRaisesRegex(ValueError, 'chrono path changed|Panic Location'):
                    dd.analyze(self.mutated(slot_va + 16, struct.pack('<q', addend + 1)))
            else:
                with self.assertRaisesRegex(ValueError, messages[va]):
                    dd.analyze(self.mutated(slot_va + 16, struct.pack('<q', addend + 8)))

    def test_call_census(self):
        census = self.result['call_census']
        self.assertEqual(census['direct_e8'], 0)
        self.assertEqual(census['got_indirect'],
                         ['0x13cfdc1', '0x1447166', '0x1450a61'])


def _is_leap(year):
    return year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)


if __name__ == '__main__':
    unittest.main()
