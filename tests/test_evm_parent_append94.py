"""Independent final-buffer oracle and authenticated native append controls."""
import copy
import importlib.util
import json
from pathlib import Path
import struct
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research/work-items/RE-009-evm-parent-append-94"
SPEC = importlib.util.spec_from_file_location("parent_append94", PACKET/"verify.py")
v = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(v)


class ParentAppendTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = v.NODE.read_bytes()
        cls.p = v.plan()
        cls.secs = v.sections(cls.data)
        cls.c = v.fields(cls.data, cls.secs)

    def mutate(self, va, replacement):
        out = bytearray(self.data)
        out[v.location(out, self.secs, va, 1)] = replacement
        return out

    def independent_expected(self, initial, addresses, key, value, words, n):
        """Direct destination map; does not inspect native fields or model output."""
        expected = {name: bytearray(raw) for name, raw in initial.items()}
        writes = (
            ("parent", 32*n, key),
            ("parent", 0x160+32*n, value),
            ("parent", 0x2CA, (n+1).to_bytes(2, "little")),
            ("parent", 0x2D0+8*(n+1), addresses["new"].to_bytes(8, "little")),
            ("new", 0x2C0, addresses["parent"].to_bytes(8, "little")),
            ("new", 0x2C8, (n+1).to_bytes(2, "little")),
            ("result", 0, b"".join(word.to_bytes(8, "little") for word in words)),
        )
        for name, offset, raw in writes:
            expected[name][offset:offset+len(raw)] = raw
        return {name: bytes(raw) for name, raw in expected.items()}

    def test_complete_authenticated_evidence_and_raw_exports(self):
        evidence, controls = v.analyze(self.data, self.p)
        self.assertEqual(evidence, json.loads((PACKET/"evidence.json").read_text()))
        self.assertEqual(controls, json.loads((PACKET/"controls.json").read_text()))
        self.assertEqual(evidence["counts"]["retained_bytes"], 428)
        self.assertEqual(evidence["counts"]["decoder_rows_each"], 99)
        self.assertEqual(evidence["counts"]["new_owner_byte_credit"], 0)
        self.assertFalse(evidence["captured_execution"])

    def test_four_frozen_whole_buffers_against_independent_destination_map(self):
        self.assertTrue(self.p["frozen_before_model"])
        self.assertEqual([r["n"] for r in self.p["independent_full_buffer_vectors"]], [0, 1, 9, 10])
        for row in self.p["independent_full_buffer_vectors"]:
            n = row["n"]
            initial, addresses, key, value, words = v.fixture(n, self.p)
            expected = self.independent_expected(initial, addresses, key, value, words, n)
            actual, ret = v.apply_relation(self.c, initial, addresses, key, value, words)
            with self.subTest(n=n):
                self.assertEqual(v.sha(v.flatten(initial)), row["input_sha256"])
                self.assertEqual(v.sha(v.flatten(expected)), row["expected_sha256"])
                self.assertEqual(actual, expected)
                self.assertEqual(len(v.flatten(actual)), 3000)
                self.assertEqual(ret, addresses["result"])
                self.assertEqual(actual["new"][0x2CA:0x2CC], b"\x05\0")
                self.assertEqual(actual["old"], initial["old"])
                self.assertEqual(actual["dummy"], initial["dummy"])

    def test_four_inert_native_controls_have_sixteen_real_counterexamples(self):
        rows = v.control_results(self.data, self.secs, self.p)["controls"]
        self.assertEqual(len(rows), 4)
        for row in rows:
            self.assertEqual(row["changed_bytes"], 1)
            self.assertEqual(row["inert_copy_bytes"], len(self.data))
            self.assertTrue(row["native_validator_rejected"])
            self.assertEqual([c["n"] for c in row["cases"]], [0, 1, 9, 10])
            self.assertTrue(all(c["different_bytes"] > 0 for c in row["cases"]))
        self.assertEqual(rows[0]["cases"][-1]["raw"]["parent_count_hex"], "0c00")
        self.assertEqual(rows[1]["cases"][-1]["raw"]["new_parent_index_count_hex"], "0000000000000000a5a50500")
        self.assertEqual(rows[2]["cases"][-1]["raw"]["new_parent_index_count_hex"], "00000100000000000b000500")
        self.assertEqual(rows[3]["cases"][-1]["raw"]["new_parent_index_count_hex"], "00000100001000000b000000")

    def test_native_identity_fixed_grammar_and_field_validation_fail_closed(self):
        for row in self.p["negative_native_controls"]:
            mutant = self.mutate(int(row["va"], 16), int(row["mutation"], 16))
            with self.assertRaisesRegex(ValueError, "fields changed"):
                v.validate_fields(v.fields(mutant, self.secs))
            with self.assertRaisesRegex(ValueError, "identity mismatch"):
                v.authenticate(mutant, self.p)
        with self.assertRaisesRegex(ValueError, "grammar changed"):
            v.fields(self.mutate(0x1AB482D, 0x90), self.secs)
        with self.assertRaisesRegex(ValueError, "unsupported selected field"):
            v.fields(self.mutate(0x1AB4709, 3), self.secs)
        with self.assertRaisesRegex(ValueError, "identity mismatch"):
            v.authenticate(self.data[:-1], self.p)

    def test_unwind_index_record_and_branch_bindings_are_operative(self):
        for name in ("fde", "cie"):
            p = copy.deepcopy(self.p)
            p["static_binding"]["owner_and_caller"][0][name]["raw"] = "00"
            with self.assertRaisesRegex(ValueError, "unwind record bytes"):
                v.authenticate(self.data, p)
        p = copy.deepcopy(self.p)
        p["static_binding"]["branch_edges"][0]["target"] = "0x1ab45e0"
        with self.assertRaisesRegex(ValueError, "branch changed"):
            v.authenticate(self.data, p)
        secs, index = v.unwind_index(self.data)
        truncated = [e for e in index if e["start"] != 0x1AB3D20]
        with patch.object(v, "unwind_index", return_value=(secs, truncated)):
            with self.assertRaisesRegex(ValueError, "index/LSDA binding"):
                v.authenticate(self.data, self.p)

    def test_both_decoder_listings_reject_missing_duplicate_and_wrong_bytes(self):
        gnu = (PACKET/"native-gnu.txt").read_text()
        llvm = (PACKET/"native-llvm.txt").read_text()
        self.assertEqual(v.check_listing(gnu, self.data, self.secs, self.p),
                         v.check_listing(llvm, self.data, self.secs, self.p))
        row = next(line for line in gnu.splitlines() if line.lstrip().startswith("1ab40d6:"))
        for wrong in (gnu.replace(row, ""), gnu.replace(row, row+"\n"+row), gnu.replace("49 8b 87 c0", "48 8b 87 c0", 1)):
            with self.assertRaises(ValueError):
                v.check_listing(wrong, self.data, self.secs, self.p)

    def test_excluded_height_full_parent_and_nonappend_domains(self):
        initial, addresses, key, value, words = v.fixture(10, self.p)
        with self.assertRaisesRegex(ValueError, "saved-zero-word"):
            v.apply_relation(self.c, initial, addresses, key, value, words, h=1)
        for name, offset, val in (("parent", 0x2CA, 11), ("old", 0x2C8, 9), ("old", 0x2C8, 11)):
            wrong = {k: bytearray(b) for k, b in initial.items()}
            struct.pack_into("<H", wrong[name], offset, val)
            with self.assertRaisesRegex(ValueError, "append premise"):
                v.apply_relation(self.c, wrong, addresses, key, value, words)

    def test_object_alias_wrap_pointer_and_prepared_buffer_premises(self):
        initial, addresses, key, value, words = v.fixture(0, self.p)
        for name, val in (("new", addresses["parent"]), ("result", addresses["old"]+8),
                          ("parent", 2**64-8), ("parent", -8), ("parent", True)):
            with self.assertRaises(ValueError):
                v.apply_relation(self.c, initial, {**addresses, name: val}, key, value, words)
        wrong = dict(initial)
        old = bytearray(wrong["old"])
        struct.pack_into("<Q", old, 0x2C0, 0)
        wrong["old"] = bytes(old)
        with self.assertRaisesRegex(ValueError, "append premise"):
            v.apply_relation(self.c, wrong, addresses, key, value, words)
        for k, val, w in ((key[:-1], value, words), (key, value+b"x", words), (key, value, (0, -1, 0))):
            with self.assertRaises(ValueError):
                v.apply_relation(self.c, initial, addresses, k, val, w)

    def test_file_backing_rejects_nobits_ambiguity_truncation_and_invalid_types(self):
        fake = [{"type": 1, "address": 0x1000, "size": 8, "offset": 0}]
        self.assertEqual(v.span(b"abcdefgh", fake, 0x1002, 3), b"cde")
        for secs in ([], [{**fake[0], "type": 8}], fake+fake):
            with self.assertRaises(ValueError):
                v.span(b"abcdefgh", secs, 0x1000, 1)
        for address, size in ((True, 1), (0x1000, True), (-1, 1), (0x1000, 0), (0x1000, 9)):
            with self.assertRaises(ValueError):
                v.span(b"abcdefgh", fake, address, size)
        with self.assertRaisesRegex(ValueError, "exceeds input"):
            v.span(b"a", fake, 0x1000, 2)

    def test_every_payload_byte_and_raw_saved_word_preserves_unwritten_bytes(self):
        initial, addresses, _, _, _ = v.fixture(10, self.p)
        for lane in range(32):
            key = bytes(0x80 if i == lane else 0 for i in range(32))
            value = bytes(0x7F if i == 31-lane else 0 for i in range(32))
            words = (2**64-1, lane, 0)
            actual, _ = v.apply_relation(self.c, initial, addresses, key, value, words)
            self.assertEqual(actual, self.independent_expected(initial, addresses, key, value, words, 10))


if __name__ == "__main__":
    unittest.main()
