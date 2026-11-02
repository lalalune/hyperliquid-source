"""Controls for the bounded c-signer time conversion study."""
import hashlib
import struct
import unittest
from pathlib import Path

from tools import staking_jail_time94 as study


class JailTimeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = study.load_image()
        cls.machine = study.setup_machine(cls.image)

    def test_artifact_digest_is_required(self):
        self.assertEqual(hashlib.sha256(self.image.blob).hexdigest(), study.SHA256)
        with self.assertRaisesRegex(study.EvidenceError, "SHA-256 mismatch"):
            study.load_image(expected="0" * 64)

    def test_selected_ranges_are_unique_file_backed_fdes(self):
        rows = study.get_records(self.image)
        self.assertEqual(len(rows), 6)
        for role, address in study.SELECTED:
            self.assertEqual(rows[role]["start"], address)
            self.assertGreater(rows[role]["end"], address)
            self.assertTrue(study.checked_read(self.image, address, 1, True))

    def test_invalid_and_cross_section_reads_rejected(self):
        with self.assertRaises(study.EvidenceError):
            study.checked_read(self.image, 0, 1, True)
        with self.assertRaises(study.EvidenceError):
            study.checked_read(self.image, study.CLOCK, -1)
        code = next(s for s in self.image.sections if s["name"] == ".text")
        with self.assertRaises(study.EvidenceError):
            study.checked_read(self.image, code["address"] + code["size"] - 1, 2, True)
        nobits = next(s for s in self.image.sections if s["name"] == ".bss" and s["type"] == 8 and s["size"])
        with self.assertRaises(study.EvidenceError):
            study.checked_read(self.image, nobits["address"], 1)

    def test_instruction_witness_rejects_corruption(self):
        study.validate_pins(self.image)
        original = self.image.blob
        altered = bytearray(original)
        offset = self.image.offset(study.CLOCK + 3)
        altered[offset] ^= 1
        try:
            self.image.blob = altered
            with self.assertRaisesRegex(study.EvidenceError, "changed witness"):
                study.validate_pins(self.image)
        finally:
            self.image.blob = original

    def test_ordinal_boundaries_and_zero_year(self):
        fields = study.time_fields()
        vectors = ((0, 1, True), (0, 366, True), (1, 366, False),
                   (400, 366, True), (1900, 366, False), (2000, 366, True),
                   (-262143, 1, True), (-262144, 1, False),
                   (262142, 1, True), (262143, 1, False), (1970, 0, False))
        for year, ordinal, valid in vectors:
            with self.subTest(year=year, ordinal=ordinal):
                actual = study.adapter_run(self.machine, year, ordinal, fields)
                expected = study.date_spec(self.image, year, ordinal)
                self.assertEqual(expected is not None, valid)
                self.assertEqual(actual[0], 0 if valid else 1)
                if valid:
                    self.assertEqual(actual[1], expected)
                    self.assertNotEqual(actual[1], 0)

    def test_file_backed_alias_does_not_map_nobits(self):
        # A thread-local NOBITS range aliases a file-backed section in this ELF.
        tbss = next(s for s in self.image.sections if s["name"] == ".tbss")
        backed = next(s for s in self.image.sections if s["name"] == ".init_array")
        self.assertEqual(tbss["address"], backed["address"])
        self.assertEqual(study.checked_read(self.image, tbss["address"], 8),
                         bytes(self.image.blob[backed["offset"]:backed["offset"] + 8]))

    def test_duplicate_selected_fde_rejected(self):
        from unittest.mock import patch
        actual = study.eh_frame_records(self.image.blob, self.image.sections)
        duplicate = next(r for r in actual[1] if r["start"] == study.CLOCK)
        with patch.object(study, "eh_frame_records", return_value=(actual[0], actual[1] + [duplicate])):
            with self.assertRaisesRegex(study.EvidenceError, "duplicated"):
                study.get_records(self.image)

    def test_calendar_date_boundaries(self):
        fields = study.time_fields()
        for year, month, day, packed in ((0, 1, 1, 0x14), (1970, 1, 1, 0xF6401A),
                                         (2024, 2, 29, 0xFD03C6)):
            with self.subTest(year=year, month=month, day=day):
                actual = study.adapter_run(self.machine, year, 0, fields, month=month, day=day)
                self.assertEqual(actual, (0, packed, 0, 0))
                self.assertEqual(study.calendar_spec(self.image, year, month, day), packed)
        for year, month, day in ((1900, 2, 29), (2023, 2, 29), (2024, 0, 1),
                                 (2024, 13, 1), (2024, 4, 31), (2024, 1, 0)):
            with self.subTest(year=year, month=month, day=day):
                self.assertIsNone(study.calendar_spec(self.image, year, month, day))
                self.assertEqual(study.adapter_run(self.machine, year, 0, fields, month=month, day=day)[0], 1)

    def test_calendar_and_ordinal_must_agree(self):
        fields = study.time_fields()
        consistent = study.adapter_run(self.machine, 2024, 0, fields, month=2, day=29, ordinal_constraint=60)
        self.assertEqual(consistent, (0, 0xFD03C6, 0, 0))
        for ordinal in (59, 61):
            with self.subTest(ordinal=ordinal):
                mismatch = study.adapter_run(self.machine, 2024, 0, fields, month=2, day=29, ordinal_constraint=ordinal)
                self.assertEqual(mismatch, (1, 0xBEEF001, 0, 0))
        invalid_date = study.adapter_run(self.machine, 2023, 0, fields, month=2, day=29, ordinal_constraint=60)
        self.assertEqual(invalid_date, (1, 0xBEEF000, 0, 0))

    def test_ordinal_consistency_mutant_is_detected(self):
        # Flip the branch after cmp supplied ordinal to computed ordinal.
        mutant = study.setup_machine(self.image, {0x151C16A: 0x74})
        actual = study.adapter_run(mutant, 2024, 0, study.time_fields(), month=2, day=29, ordinal_constraint=59)
        self.assertNotEqual(actual, (1, 0xBEEF001, 0, 0))

    def test_calendar_month_limit_mutant_is_detected(self):
        mutant = study.setup_machine(self.image, {0x151BAB3: 0x0c})
        fields = study.time_fields()
        actual = study.adapter_run(mutant, 1970, 0, fields, month=12, day=31)
        self.assertNotEqual(actual[0], 0)
        self.assertIsNotNone(study.calendar_spec(self.image, 1970, 12, 31))

    def test_known_epoch_date(self):
        result = study.adapter_run(self.machine, 1970, 1, study.time_fields())
        self.assertEqual(result, (0, 0xF6401A, 0, 0))
        self.assertEqual(study.adapter_run(self.machine, 0, 1, study.time_fields()), (0, 0x14, 0, 0))

    def test_clock_midnight_and_maximum_leap_second(self):
        self.assertEqual(study.clock_run(self.machine, study.time_fields()), (0, 0, 0, 0))
        value = study.time_fields(1, 11, 59, 1, 60, 1, 999999999)
        self.assertEqual(study.clock_run(self.machine, value), (0, 0, 86399, 1999999999))
        self.assertEqual(study.adapter_run(self.machine, 1970, 1, value), (0, 0xF6401A, 86399, 1999999999))

    def test_clock_failure_order(self):
        cases = (
            (study.time_fields(0, 12), (1, 0, 0, 0)),
            (study.time_fields(0, 11, 60), (1, 0, 0, 0)),
            (study.time_fields(0, 0, 0, 1, 61), (1, 0, 0, 0)),
            (study.time_fields(0, 0, 0, 0, 0, 1, 0), (1, 2, 0, 0)),
            (study.time_fields(0, 0, 0, 0, 0, 1, 1000000000), (1, 0, 0, 0)),
        )
        for fields, expected in cases:
            with self.subTest(fields=fields):
                self.assertEqual(study.clock_run(self.machine, fields), expected)
                self.assertEqual(study.clock_spec(fields), expected)

    def test_all_internal_tags_and_synthetic_zero_date(self):
        for tag in range(256):
            with self.subTest(tag=tag):
                result = study.adapter_run(self.machine, 1970, 1, study.time_fields(), tag=tag)
                self.assertEqual(result[0], 0 if tag in (12, 13) else 1)
                if result[0] == 0:
                    self.assertNotEqual(result[1], 0)
        for entry in (study.ENTRY, 0x217D750):
            for tag in (12, 13):
                with self.subTest(entry=entry, tag=tag):
                    rejected = study.adapter_run(self.machine, 1970, 1, study.time_fields(), tag=tag, entry=entry, forced_date=0)
                    accepted = study.adapter_run(self.machine, 1970, 1, study.time_fields(), tag=tag, entry=entry, forced_date=1)
                    self.assertEqual(rejected, (1, 0xBEEF007, 0, 0))
                    self.assertEqual(accepted, (0, 1, 43210, 123))

    def test_parse_boundary_failure_controls(self):
        fields = study.time_fields()
        self.assertEqual(study.adapter_run(self.machine, 1970, 1, fields, 0, 3), (1, 0xBEEF003, 0, 0))
        self.assertEqual(study.adapter_run(self.machine, 1970, 1, fields, 1, 1), (1, 0xBEEF005, 0, 0))

    def test_boxed_wrapper_preserves_zero_date_guard(self):
        for depth in (1, 2):
            for tag in (12, 13):
                with self.subTest(depth=depth, tag=tag):
                    self.assertEqual(study.boxed_wrapper_run(self.machine, depth, tag, 0), (1, 0xBEEF007, 0, 0, depth))
                    self.assertEqual(study.boxed_wrapper_run(self.machine, depth, tag, 1), (0, 1, 43210, 123, depth))

    def test_second_zero_date_gate_mutant_is_detected(self):
        mutant = study.setup_machine(self.image, {0x219AE79: 0x85})
        result = study.adapter_run(mutant, 1970, 1, study.time_fields(), tag=13, forced_date=0)
        self.assertEqual(result, (0, 0, 7, 123))

    def test_zero_date_gate_mutant_is_detected(self):
        # Invert the adapter's zero-date error branch for the first input arm.
        mutant = study.setup_machine(self.image, {0x219ACEA: 0x85})
        result = study.adapter_run(mutant, 1970, 1, study.time_fields(), forced_date=0)
        self.assertEqual(result, (0, 0, 7, 123))
        self.assertNotEqual(result, (1, 0xBEEF007, 0, 0))

    def test_parser_gate_mutant_is_detected(self):
        # Flip the conditional after the two parser result words.
        mutant = study.setup_machine(self.image, {0x219ACCD: 0x85})
        actual = study.adapter_run(mutant, 1970, 1, study.time_fields(), 0, 3)
        self.assertNotEqual(actual, (1, 0xBEEF003, 0, 0))

    def test_hour_limit_mutant_is_detected(self):
        # The immediate in cmp hour, 12 is changed to 11.
        mutant = study.setup_machine(self.image, {0x151C1E8: 0x0B})
        fields = study.time_fields(0, 11)
        self.assertEqual(study.clock_spec(fields), (0, 0, 39600, 0))
        self.assertNotEqual(study.clock_run(mutant, fields), study.clock_spec(fields))

    def test_leap_second_mutant_is_detected(self):
        mutant = study.setup_machine(self.image, {0x151C23B: 0x3B})
        fields = study.time_fields(0, 0, 0, 1, 60)
        self.assertEqual(study.clock_spec(fields), (0, 0, 59, 1000000000))
        self.assertNotEqual(study.clock_run(mutant, fields), study.clock_spec(fields))

    def test_ordinal_gate_mutant_is_detected(self):
        mutant = study.setup_machine(self.image, {0x151BC1B: 0x74})
        actual = study.adapter_run(mutant, 0, 1, study.time_fields())
        self.assertNotEqual(actual, (0, 0x14, 0, 0))

    def test_table_relative_targets_inside_selected_fde(self):
        base = 0x3CF0E8
        start, end = self.image.exact_fde(study.ENTRY)
        targets = [base + struct.unpack("<i", study.checked_read(self.image, base + 4*i, 4))[0] for i in range(4)]
        self.assertEqual(targets, [0x219ABC4, 0x219AD5E, 0x219AD11, 0x219AD33])
        self.assertTrue(all(start <= x < end for x in targets))


if __name__ == "__main__":
    unittest.main()
