"""End-to-end tests for the OptionTypeInfo verification gate model.

The expectations are target-grounded: every branch is read from the
apply 0x60bedc0 and the serializer 0x60bb9a0 in
research/work-items/RE-001-verification-gate-115/, and the
distribution is the 214-entry count from the #4237/#4263 map
packets.
"""

import unittest

from tools import option_verification_gate_115 as gate


class TestApplyGate(unittest.TestCase):
    def test_verification_4_skips_before_parse(self):
        # 0x60bedeb: verification 4 returns OK before the type
        # dispatch; the value is never parsed, nothing is written.
        for parse_ok in (True, False):
            out = gate.apply_outcome(4, parse_ok, 0, "ttl")
            self.assertEqual(out["status_code"], 0)
            self.assertIsNone(out["message"])
            self.assertFalse(out["parsed"])
            self.assertFalse(out["written"])

    def test_parse_success_is_ok_for_every_verification(self):
        for v in (0, 1, 2, 3, 5):
            out = gate.apply_outcome(v, True, 0, "max_open_files")
            self.assertEqual(out["status_code"], 0)
            self.assertIsNone(out["message"])
            self.assertTrue(out["parsed"])
            self.assertTrue(out["written"])

    def test_parse_failure_verification_1_2_3_not_supported(self):
        # 0x60bf08a..0x60bf09c: one range check covers 1, 2 and 3.
        for v in (1, 2, 3):
            out = gate.apply_outcome(v, False, 0, "comparator")
            self.assertEqual(out["status_code"], 3)
            self.assertEqual(
                out["message"],
                "Deserializing the option comparator is not supported")
            self.assertFalse(out["parsed"])
            self.assertFalse(out["written"])

    def test_parse_failure_verification_0_5_invalid_argument(self):
        # 0x60bf460: the ja target for values outside {1,2,3}.
        for v in (0, 5):
            out = gate.apply_outcome(v, False, 0, "max_open_files")
            self.assertEqual(out["status_code"], 4)
            self.assertEqual(out["message"],
                             "Error parsing:max_open_files")
            self.assertFalse(out["parsed"])
            self.assertFalse(out["written"])

    def test_type_21_22_fallback_arm(self):
        # 0x60bf078: types 21/22 fall to the 0x60bf1e0 arm on a failed
        # parse instead of the verification error paths.
        out = gate.apply_outcome(0, False, 21, "some_vector_option")
        self.assertIsNone(out["status_code"])
        self.assertEqual(out["fallback_arm"], "0x60bf1e0")
        out = gate.apply_outcome(2, False, 22, "some_vector_option")
        self.assertIsNone(out["status_code"])
        self.assertEqual(out["fallback_arm"], "0x60bf1e0")

    def test_verification_4_beats_type_21_22(self):
        # The verification-4 early return precedes the type dispatch,
        # so it wins even for types 21/22.
        out = gate.apply_outcome(4, False, 21, "ttl")
        self.assertEqual(out["status_code"], 0)
        self.assertFalse(out["parsed"])


class TestSerializeGate(unittest.TestCase):
    def test_verification_4_skipped_in_dump(self):
        self.assertEqual(gate.serialize_outcome(4), "skip")

    def test_other_verifications_emit(self):
        for v in (0, 1, 2, 3, 5):
            self.assertEqual(gate.serialize_outcome(v), "emit")


class TestDistribution(unittest.TestCase):
    def test_totals(self):
        self.assertEqual(gate.DISTRIBUTION["total_entries"], 214)
        combined = gate.DISTRIBUTION["combined"]
        self.assertEqual(sum(combined.values()), 214)
        self.assertEqual(combined, {0: 166, 1: 7, 2: 3, 3: 2, 4: 33,
                                    5: 3})

    def test_parts_add_up(self):
        for part in ("dboptions", "cfoptions"):
            counts = gate.DISTRIBUTION[part]["counts"]
            self.assertEqual(sum(counts.values()),
                             gate.DISTRIBUTION[part]["entries"])

    def test_skip_set_sizes(self):
        self.assertEqual(
            len(gate.VERIFICATION_4_NAMES["dboptions"]), 14)
        self.assertEqual(
            len(gate.VERIFICATION_4_NAMES["cfoptions"]), 19)
        self.assertEqual(
            len(gate.VERIFICATION_5_NAMES["cfoptions"]), 3)
        self.assertEqual(
            sum(len(v) for v in
                gate.VERIFICATION_123_NAMES["dboptions"].values()), 3)
        self.assertEqual(
            sum(len(v) for v in
                gate.VERIFICATION_123_NAMES["cfoptions"].values()), 9)

    def test_every_named_entry_matches_its_group(self):
        # The 1/2/3 set is the factory/comparator/extractor group:
        # every name in it must report kNotSupported on a failed parse.
        for part, groups in gate.VERIFICATION_123_NAMES.items():
            for v, names in groups.items():
                for name in names:
                    out = gate.apply_outcome(v, False, 0, name)
                    self.assertEqual(out["status_code"], 3, name)
        # The verification-4 set must skip both directions.
        for part, names in gate.VERIFICATION_4_NAMES.items():
            for name in names:
                out = gate.apply_outcome(4, False, 0, name)
                self.assertEqual(out["status_code"], 0, name)
                self.assertFalse(out["parsed"], name)
                self.assertEqual(gate.serialize_outcome(4), "skip",
                                 name)
        # The verification-5 set must report kInvalidArgument.
        for name in gate.VERIFICATION_5_NAMES["cfoptions"]:
            out = gate.apply_outcome(5, False, 0, name)
            self.assertEqual(out["status_code"], 4, name)
            self.assertEqual(out["message"], "Error parsing:" + name)


if __name__ == "__main__":
    unittest.main()
