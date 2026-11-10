import json
import pathlib
import struct
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import vaults_transfer_wrappers_115 as T  # noqa: E402

BOUND = 0xCCCCCCCCCCCCCCC


class Shared:
    image = None
    constants = None
    harness = None
    named = None

    @classmethod
    def setup(cls):
        if cls.image is None:
            cls.image = T.load_image()
            cls.constants = T.constant_values(cls.image)
            cls.harness = T.Harness(cls.image)
            cls.named = {case.name: case for case in T.named_cases(cls.constants)}
        return cls


def outcome(name):
    shared = Shared.setup()
    return T.run_case(shared.harness, shared.named[name])


def first_byte(name):
    return outcome(name)[0][2][0]


def u16_at(out, at):
    return struct.unpack_from("<H", out, at)[0]


class ImageTests(unittest.TestCase):
    def test_binary_identity_and_frame_bounds(self):
        image = Shared.setup().image
        ends = {T.G_A: 0x50A5D91, T.G_B: 0x58C2439, T.G_C: 0x543AE12, T.G_D: 0x54F2B09, T.G_E: 0x532FCC8, T.G_F: 0x534BE30,
                T.G_G: 0x520896A, T.G_H: 0x532FA38, T.G_I: 0x5208524, T.G_J: 0x543685C}
        for entry, end in ends.items():
            self.assertEqual(image.exact_fde(entry), (entry, end))
            rows = T.decode_range(image, entry, end)
            self.assertEqual(rows[-1].next, end)
        with self.assertRaises(T.EvidenceError):
            T.load_image(T.BINARY, "0" * 64)
        with self.assertRaises(T.EvidenceError):
            image.exact_fde(T.G_D + 1)
        with self.assertRaises(T.EvidenceError):
            T.decode_range(image, T.G_D, ends[T.G_D] - 1)
        with self.assertRaises(T.EvidenceError):
            image.offset(image.named[".bss"]["address"] + 8)

    def test_constants_come_from_the_bytes(self):
        k = Shared.setup().constants
        self.assertEqual(BOUND, (2 ** 63 - 1) // 10)
        for role in ("limit_amount-wrap", "limit_slot-wrap", "limit_transfer-log"):
            self.assertEqual(k[role], BOUND)
        self.assertEqual(k["divisor"], 1000000.0)
        self.assertEqual(len(k["panic_text"]), 43)
        self.assertEqual(k["panic_text"], "called `Result::unwrap()` on an `Err` value")

    def test_locations_name_the_source_files(self):
        image = Shared.setup().image
        relative = image.relative()
        self.assertEqual(image.location(T.UNWRAP_LOCATION, relative), ("l1/src/dex_registry/clearinghouses.rs", 11, 29))
        self.assertEqual(image.location(T.LOCATION_H, relative), ("l1/src/action/vault_transfer.rs", 27, 18))


class HandDerivedOutcomes(unittest.TestCase):
    """Each expectation is worked out from the listing by hand, not taken from the rule lists."""

    def test_gate_a_denied_state(self):
        got, log = outcome("a-denied")
        self.assertEqual((got[0], got[2][0], u16_at(got[2], 0x10)), ("return", 0xF, 0x91))
        self.assertEqual(log, [])
        self.assertEqual(got[2][0x12:], bytes([T.FILL]) * (T.OUT_LEN - 0x12))

    def test_gate_a_other_flag_or_state_passes_the_denial(self):
        self.assertEqual(outcome("a-flag-set-passes")[1], [("lookup", 1)])
        self.assertEqual(outcome("a-state-2-passes")[1], [("lookup", 1)])

    def test_gate_a_index_bound_is_exclusive(self):
        got, log = outcome("a-index-equal-limit")
        self.assertEqual((got[2][0], u16_at(got[2], 0x10), log), (0xF, 0xFA, []))
        self.assertEqual(outcome("a-index-below-limit")[0][2][0], 0xE)

    def test_gate_a_error_record_is_copied_whole(self):
        got, _ = outcome("a-error-copied")
        self.assertEqual(got[2][0x10:], T.record(0x91, bytes(range(0x6E))))
        self.assertEqual(got[2][0], 0xF)

    def test_amount_bound_is_exclusive(self):
        self.assertEqual(first_byte("b-bound-1"), 0xE)
        got, log = outcome("b-bound")
        self.assertEqual((got[2][0], u16_at(got[2], 0x10), struct.unpack_from("<Q", got[2], 0x18)[0], log), (0xF, 0x154, BOUND, []))
        self.assertEqual(struct.unpack_from("<Q", outcome("b-bound+1")[0][2], 0x18)[0], BOUND + 1)

    def test_slot_wrap_calls_first_then_checks_the_bound(self):
        got, log = outcome("c-bound")
        self.assertEqual(log, [("first", 3)])
        self.assertEqual((got[2][0], u16_at(got[2], 0x10)), (0xF, 0x154))
        got, log = outcome("c-first-error")
        self.assertEqual([entry[0] for entry in log], ["first"])
        self.assertEqual(got[2][0x10:], T.record(0x91, bytes(range(0x6E))))

    def test_slot_wrap_success_joins_both_records(self):
        got, log = outcome("c-both-ok")
        self.assertEqual([entry[0] for entry in log], ["first", "second"])
        self.assertEqual(got[2][0], 5)
        self.assertEqual(got[2][1:0x10], T.record(T.SUCCESS, bytes(0x6E))[:15])

    def test_transfer_log_event_values(self):
        got, log = outcome("d-logged")
        self.assertEqual(got[2][:2], struct.pack("<H", T.SUCCESS))
        self.assertEqual(got[2][2:], bytes([T.FILL]) * (T.OUT_LEN - 2))
        self.assertEqual([entry[0] for entry in log], ["check", "drop", "alloc", "record"])
        record = log[-1]
        self.assertEqual(record[1:3], (1, 1))
        self.assertEqual(record[3], (bytes(range(20)).hex(),))
        # 1234567 / 1e6 and 1e18 / 1e6 as IEEE doubles, written by hand
        self.assertEqual(struct.unpack("<d", struct.pack("<Q", record[6][1]))[0], 1.234567)
        self.assertEqual(struct.unpack("<d", struct.pack("<Q", record[6][3]))[0], 1e12)
        self.assertEqual((record[6][0], record[6][2]), (1 << 63, 77))

    def test_transfer_log_variants_that_do_not_log(self):
        self.assertEqual([entry[0] for entry in outcome("d-not-logged")[1]], ["check"])
        got, log = outcome("d-error")
        self.assertEqual(got[2][:0x70], T.record(0x98, bytes([1]) + bytes(range(0x6D))))
        self.assertEqual(len(log), 1)
        got, log = outcome("d-bound")
        self.assertEqual((u16_at(got[2], 0), log), (0x154, []))

    def test_transfer_log_failure_paths(self):
        got, log = outcome("d-unwrap-err")
        self.assertEqual(got[0], "panic")
        self.assertIn("unwrap()", got[1])
        self.assertIn("0x156", got[1])
        self.assertEqual([entry[0] for entry in log], ["check"])
        got, log = outcome("d-alloc-fail")
        self.assertEqual((got[:2], log[-1]), (("panic", "alloc-fail"), ("alloc-fail", 1, 0x14)))

    def test_flag_set(self):
        got, _ = outcome("e-off")
        self.assertEqual((got[2][0], u16_at(got[2], 0x10), got[3]), (0xF, 0x92, b"\x09"))
        got, log = outcome("e-two")
        self.assertEqual((got[2][0], got[3], log), (0xE, b"\x09", []))
        got, log = outcome("e-set")
        self.assertEqual((got[2][0], got[3], log), (0xE, b"\x01", [("enter",), ("leave",)]))

    def test_result_widen_drops_byte_seven(self):
        got, _ = outcome("f-ok")
        payload = T.record(T.SUCCESS, bytes(range(1, 0x6F)))
        self.assertEqual(got[2][0], 0xC)
        self.assertEqual(got[2][1:0x20], payload[:7] + payload[8:0x20])
        self.assertEqual(got[2][0x20:], bytes([T.FILL]) * (T.OUT_LEN - 0x20))
        self.assertEqual(outcome("f-error")[0][2][0x10:], T.record(0x91, bytes(range(0x6E))))

    def test_forwarders_pass_their_inputs_through(self):
        got, log = outcome("g-ok")
        self.assertEqual(log[0][1], bytes(range(0x18)).hex())
        self.assertEqual(log[0][2], bytes(range(0x18, 0x50)).hex())
        self.assertEqual((log[0][3], got[2][0]), (0x50, 0xE))
        got, log = outcome("h-ok")
        self.assertEqual(log[0][1], bytes(range(20)).hex())
        self.assertEqual(log[0][2:], (0, 0, 0, (T.SIDE, T.REQ, T.LOCATION_H)))
        self.assertEqual(outcome("h-error")[0][2][0], 0xF)


class ListForwarder(unittest.TestCase):
    def test_empty_list_uses_dangling_pointer_and_no_allocation(self):
        got, log = outcome("i-empty")
        self.assertEqual(log, [("list", 0, 8, 0, 5, "")])
        self.assertEqual(got[2][0], 1)

    def test_three_items_are_cloned_with_capacity_equal_to_length(self):
        got, log = outcome("i-three")
        self.assertEqual([entry[0] for entry in log], ["alloc", "copy", "list"])
        self.assertEqual(log[0], ("alloc", 48))
        self.assertEqual(log[2], ("list", 3, T.ALLOC, 3, 7, bytes(range(48)).hex()))
        self.assertEqual(got[2][0], 1)

    def test_error_record_is_copied(self):
        got, _ = outcome("i-error")
        self.assertEqual((got[2][0], got[2][0x10:]), (0xF, T.record(0x91, bytes(range(0x6E)))))

    def test_size_guard_uses_the_wrapped_byte_size(self):
        self.assertEqual(outcome("i-wrap-to-zero")[0][:2], ("panic", "layout:0:0x0"))
        self.assertEqual(outcome("i-over-limit")[0][:2], ("panic", "layout:0:0x8000000000000000"))
        self.assertEqual(outcome("i-at-limit")[0][:2], ("panic", "layout:8:0x7ffffffffffffff0"))
        self.assertEqual(outcome("i-at-limit")[1], [("alloc", 0x7FFFFFFFFFFFFFF0)])
        self.assertEqual(outcome("i-alloc-fail")[0][:2], ("panic", "layout:8:0x20"))


class PairForwarder(unittest.TestCase):
    """0x5436600: x is a niche encoded optional string (0x8000000000000000 and 0x8000000000000001 mean no value), y the second one."""

    def test_both_strings_are_cloned_in_order(self):
        got, log = outcome("j-both")
        self.assertEqual([entry[0] for entry in log], ["alloc", "copy", "alloc", "copy", "pair"])
        self.assertEqual((log[0], log[2]), (("alloc", 4), ("alloc", 3)))
        self.assertEqual(log[4][1:], (("vec", 4, 4, "00010203", 0), 9, ("vec", 3, 3, "646566", 0), bytes(range(17)).hex()))
        self.assertEqual(got[2][0], 4)
        self.assertEqual(got[2][1:0x10], struct.pack("<Q", 4) + struct.pack("<Q", T.ALLOC)[:7])
        self.assertEqual(got[2][0x10:], T.record(T.SUCCESS, bytes(0x6E)))

    def test_empty_strings_use_the_dangling_pointer_one(self):
        got, log = outcome("j-empty")
        self.assertEqual([entry[0] for entry in log], ["pair"])
        self.assertEqual(log[0][1], ("vec", 0, 0, "", 1))
        self.assertEqual(log[0][3], ("vec", 0, 0, "", 1))
        self.assertEqual(got[2][1:0x10], struct.pack("<Q", 0) + struct.pack("<Q", 1)[:7])
        self.assertEqual(got[2][0x10:], T.record(0x91, bytes(range(0x6E))))   # the callee record is copied without a tag test

    def test_niche_values_skip_the_clone(self):
        got, log = outcome("j-a-niche")
        self.assertEqual([entry[0] for entry in log], ["alloc", "copy", "pair"])
        self.assertEqual(log[2][1], ("niche", T.NICHE))
        self.assertEqual(got[2][1:0x10], struct.pack("<Q", T.NICHE) + struct.pack("<Q", T.CTX)[:7])
        got, log = outcome("j-all-niche")
        self.assertEqual([entry[0] for entry in log], ["pair"])
        self.assertEqual((log[0][1], log[0][3]), (("niche", T.NICHE + 1), ("unset",)))
        got, log = outcome("j-b-niche")
        self.assertEqual(log[-1][3], ("niche", T.NICHE))
        self.assertEqual([entry[0] for entry in log], ["alloc", "copy", "pair"])

    def test_allocation_failures_report_the_requested_size(self):
        self.assertEqual(outcome("j-fail-first")[0][:2], ("panic", "layout:1:0x2"))
        got, log = outcome("j-fail-second")
        self.assertEqual(got[:2], ("panic", "layout:1:0x2"))
        self.assertEqual([entry[0] for entry in log], ["alloc", "copy", "alloc"])


class RuleListChecks(unittest.TestCase):
    def test_no_mismatch_on_a_stream(self):
        shared = Shared.setup()
        cases = list(T.draw_stream(1600, shared.constants))
        stats, caught, rows = T.check_stream(shared.harness, cases, shared.constants, keep=100)
        self.assertEqual(stats["mismatches"], 0, stats["first_mismatch"])
        self.assertEqual(stats["cases"], len(cases))
        self.assertTrue(all(count for count, _ in caught.values()), caught)
        self.assertEqual(len(rows), (len(cases) + 99) // 100)
        self.assertEqual({sub for sub in T.SUBJECTS}, {case.subject for case in cases})

    def test_every_named_deviation_is_refused(self):
        shared = Shared.setup()
        cases = list(T.draw_stream(2000, shared.constants))
        _, caught, _ = T.check_stream(shared.harness, cases, shared.constants)
        self.assertGreaterEqual(len(caught), 12)
        for key, (count, first) in caught.items():
            self.assertGreater(count, 0, key)
            self.assertIsNotNone(first)

    def test_wrong_rule_lists_are_refused(self):
        shared = Shared.setup()
        k = shared.constants
        cases = [case for case in T.draw_stream(1200, k)]

        def refused(subject, wrong):
            for case in cases:
                if case.subject == subject and T.run_case(shared.harness, case) != wrong(case, k):
                    return True
            return False

        def wrong_b(case, k):
            return T.spec_b(case, dict(k, **{"limit_amount-wrap": BOUND - 1}))

        def wrong_d(case, k):
            return T.spec_d(case, dict(k, divisor=1e9))

        def wrong_f(case, k):
            got, log = T.spec_f(case, k)
            out = bytearray(got[2])
            if out[0] == 0xC:
                out[7] ^= 1
            return (got[0], got[1], bytes(out), got[3]), log

        def wrong_h(case, k):
            got, log = T.spec_h(case, k)
            return got, [("key", log[0][1], 0, 0, 0, (T.SIDE, T.REQ, 0))]

        self.assertTrue(refused(T.G_B, wrong_b))
        self.assertTrue(refused(T.G_D, wrong_d))
        self.assertTrue(refused(T.G_F, wrong_f))
        self.assertTrue(refused(T.G_H, wrong_h))

    def test_float_conversion_matches_idiom_for_large_clock_values(self):
        shared = Shared.setup()
        for clock in (0, 1, (1 << 53) + 1, (1 << 63), (1 << 64) - 1):
            case = T.Case(T.G_D, "clock", n=5, n2=1, clock=clock, rec=T.record(T.SUCCESS, bytes([1]) + bytes(0x6D)))
            got, log = T.run_case(shared.harness, case)
            seconds = struct.unpack("<d", struct.pack("<Q", log[-1][6][3]))[0]
            self.assertEqual(seconds, float(clock) / 1e6)


class ByteLevelControls(unittest.TestCase):
    def test_edited_instruction_changes_the_result(self):
        shared = Shared.setup()
        image = shared.image
        probe = shared.named["b-bound"]
        want = T.spec_b(probe, shared.constants)
        self.assertEqual(T.run_case(shared.harness, probe), want)
        reached = {}
        T.run_case(shared.harness, probe)
        # flip the jae after the bound compare into jb: the bound now admits the wrong side
        for row in T.decode_range(image, T.G_B, image.exact_fde(T.G_B)[1]):
            if row.op == "jcc" and row.target == 0x58C23E3:
                reached[row.va] = row
        self.assertEqual(len(reached), 1)
        row = next(iter(reached.values()))
        mutant = T.Harness(image, {row.va: row.data[0] ^ 1})
        self.assertNotEqual(T.run_case(mutant, probe), want)

    def test_mutants_do_not_leak_between_machines(self):
        shared = Shared.setup()
        image = shared.image
        probe = shared.named["e-set"]
        want = T.spec_e(probe, shared.constants)
        trapped = T.Harness(image, {T.G_E: 0xCC})
        self.assertEqual(T.run_case(trapped, probe)[0][0], "halt")
        self.assertEqual(T.run_case(shared.harness, probe), want)

    def test_removed_stub_is_reported_not_skipped(self):
        image = Shared.setup().image
        loose = T.Harness(image)
        del loose.machine.calls[T.CALL_F]
        with self.assertRaises(T.Halt):
            loose.run(Shared.setup().named["f-ok"])

    def test_wrong_stub_arguments_are_reported(self):
        image = Shared.setup().image
        wrong = T.Harness(image)
        case = Shared.setup().named["a-index-below-limit"]
        wrong.machine.calls[T.CALL_A] = lambda machine: machine.regs.__setitem__(T.RSI, 0) or wrong.on_a(machine)
        self.assertEqual(T.run_case(wrong, case)[0][0], "halt")

    def test_memory_outside_the_result_is_guarded(self):
        image = Shared.setup().image
        harness = T.Harness(image)
        case = Shared.setup().named["h-ok"]

        def scribble(machine):
            machine.memory.write(T.CTX + 0x40, 1, 0x55)
            harness.on_h(machine)

        harness.machine.calls[T.CALL_H] = scribble
        self.assertEqual(T.run_case(harness, case)[0][0], "halt")

    def test_structural_controls_are_all_detected(self):
        shared = Shared.setup()
        cases = list(T.draw_stream(1500, shared.constants))
        rows = T.structural_controls(shared.image, shared.constants, cases)
        self.assertGreaterEqual(len(rows), 20)
        self.assertEqual([name for name, detected, _ in rows if not detected], [])


class Regeneration(unittest.TestCase):
    def test_two_runs_are_byte_identical_and_measured(self):
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            for target in (first, second):
                self.assertEqual(T.main(["--out", target, "--cases", "1500"]), 0)
            names = sorted(path.name for path in pathlib.Path(first).iterdir())
            self.assertEqual(names, sorted(path.name for path in pathlib.Path(second).iterdir()))
            for name in names:
                self.assertEqual((pathlib.Path(first) / name).read_bytes(), (pathlib.Path(second) / name).read_bytes(), name)
            measure = json.loads((pathlib.Path(first) / "measure.json").read_text())
            self.assertEqual(measure["mismatches"], 0)
            self.assertEqual(measure["negative_detected"] + measure["equivalent"], measure["negative_controls"])
            self.assertGreater(measure["cases"], 1500)
            self.assertIn("equivalent-mutants.tsv", names)

    def test_output_has_no_server_paths(self):
        with tempfile.TemporaryDirectory() as target:
            T.main(["--out", target, "--cases", "400", "--no-mutants"])
            for path in pathlib.Path(target).iterdir():
                text = path.read_text()
                for name in ("ho" + "me", "m" + "nt", "s" + "rv", "ro" + "ot", "t" + "mp", "o" + "pt", "v" + "ar", "e" + "tc"):
                    self.assertNotIn("/" + name + "/", text, path.name)


if __name__ == "__main__":
    unittest.main()
