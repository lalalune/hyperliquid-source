"""Offline controls for the consensus timeout reconstruction.

These tests use synthetic byte arrays and do not require the target artifact.
The separately invoked generator performs target-bound differential cases.
"""
import itertools
import struct
import tempfile
import unittest
from pathlib import Path

from tools import node115_consensus_timeout_flow as model


class ByteImage:
    """The smallest read-only image required by the instruction evaluator."""

    def __init__(self, code):
        self.base = 0x1000000
        self.blob = code + bytes([0xcc]) * 32

    def offset(self, address):
        offset = address - self.base
        if not 0 <= offset < len(self.blob):
            raise model.EvidenceError("address outside synthetic image")
        return offset


class DecodeControls(unittest.TestCase):
    def run_code(self, code, arguments=None, memory=None):
        image = ByteImage(bytes.fromhex(code))
        machine = model.Machine(image)
        if memory is not None:
            machine.memory.write(model.HEAP_BASE, 8, memory)
        returned = machine.run(image.base, arguments or {})
        return machine, returned

    def test_unsigned_word_write_clears_upper_bits(self):
        machine, value = self.run_code("48 b8 ff ff ff ff ff ff ff ff b8 07 00 00 00 c3")
        self.assertEqual(value, 7)
        self.assertEqual(machine.regs[model.RAX], 7)

    def test_addition_sets_carry_without_signed_overflow(self):
        machine, value = self.run_code("48 c7 c0 ff ff ff ff 48 83 c0 01 c3")
        self.assertEqual(value, 0)
        self.assertTrue(machine.cf)
        self.assertFalse(machine.of)

    def test_addition_sets_signed_overflow(self):
        machine, value = self.run_code("48 b8 ff ff ff ff ff ff ff 7f 48 83 c0 01 c3")
        self.assertEqual(value, model.SENTINEL)
        self.assertTrue(machine.of)
        self.assertFalse(machine.cf)

    def test_byte_compare_exchange_succeeds(self):
        machine, result = self.run_code(
            "31 c0 b1 01 f0 0f b0 0f c3",
            {model.RDI: model.HEAP_BASE}, 0,
        )
        self.assertEqual(result, 0)
        self.assertEqual(machine.memory.read(model.HEAP_BASE, 1), 1)
        self.assertTrue(machine.zf)

    def test_byte_compare_exchange_returns_previous_value(self):
        machine, result = self.run_code(
            "31 c0 b1 01 f0 0f b0 0f c3",
            {model.RDI: model.HEAP_BASE}, 9,
        )
        self.assertEqual(result, 9)
        self.assertEqual(machine.memory.read(model.HEAP_BASE, 1), 9)
        self.assertFalse(machine.zf)

    def test_atomic_add_exchanges_the_original_value(self):
        machine, result = self.run_code(
            "b8 01 00 00 00 f0 48 0f c1 07 c3",
            {model.RDI: model.HEAP_BASE}, 41,
        )
        self.assertEqual(result, 41)
        self.assertEqual(machine.memory.read(model.HEAP_BASE, 8), 42)

    def test_segment_override_reads_the_selected_thread_view(self):
        image = ByteImage(bytes.fromhex("64 48 8b 04 25 00 00 00 00 c3"))
        machine = model.Machine(image)
        machine.memory.write(model.TLS_BASE, 8, 0x12345678)
        self.assertEqual(machine.run(image.base, {}), 0x12345678)

    def test_conditional_branch_is_sensitive_to_comparison(self):
        code = "83 ff 03 74 06 b8 07 00 00 00 c3 b8 09 00 00 00 c3"
        _, different = self.run_code(code, {model.RDI: 2})
        _, equal = self.run_code(code, {model.RDI: 3})
        self.assertEqual((different, equal), (7, 9))

    def test_signed_32_bit_float_conversion(self):
        image = ByteImage(bytes.fromhex("f2 0f 2a 07 c3"))
        machine = model.Machine(image)
        machine.memory.write(model.HEAP_BASE, 4, 0xffffffff)
        machine.run(image.base, {model.RDI: model.HEAP_BASE})
        self.assertEqual(model.to_float(machine.xmm[0] & model.MAX_U64), -1.0)

    def test_signed_64_bit_float_conversion(self):
        image = ByteImage(bytes.fromhex("f2 48 0f 2a 07 c3"))
        machine = model.Machine(image)
        machine.memory.write(model.HEAP_BASE, 8, model.MAX_U64)
        machine.run(image.base, {model.RDI: model.HEAP_BASE})
        self.assertEqual(model.to_float(machine.xmm[0] & model.MAX_U64), -1.0)

    def test_bad_opcode_is_not_assumed_to_be_a_nop(self):
        image = ByteImage(bytes.fromhex("0f 0f c3"))
        with self.assertRaises(model.EvidenceError):
            model.Machine(image).run(image.base, {})

    def test_out_of_range_read_is_rejected(self):
        image = ByteImage(bytes.fromhex("c3"))
        machine = model.Machine(image)
        with self.assertRaises(model.Halt):
            machine.memory.read(1, 1)

    def test_out_of_range_write_is_rejected(self):
        image = ByteImage(bytes.fromhex("c3"))
        machine = model.Machine(image)
        with self.assertRaises(model.Halt):
            machine.memory.write(1, 8, 0)

    def test_non_returning_loop_is_bounded(self):
        image = ByteImage(bytes.fromhex("eb fe"))
        machine = model.Machine(image)
        machine.step_limit = 10
        with self.assertRaises(model.Halt):
            machine.run(image.base, {})

    def test_missing_call_contract_is_rejected(self):
        image = ByteImage(bytes.fromhex("e8 00 00 00 00 c3"))
        with self.assertRaises(model.Halt):
            model.Machine(image).run(image.base, {})

    def test_hash_mismatch_is_rejected_without_an_elf(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory) / "fixture"
            fixture.write_bytes(b"invalid")
            with self.assertRaises(model.EvidenceError):
                model.load_image(fixture, model.SHA256)

    def test_invalid_elf_is_not_accepted_by_the_shared_parser(self):
        with self.assertRaises(ValueError):
            model.sections(b"invalid")

    def test_non_file_backed_region_cannot_be_selected(self):
        image = object.__new__(model.Image)
        image.mapped = [{"address": 0x1000, "size": 4, "offset": 0x20}]
        self.assertEqual(image.offset(0x1003), 0x23)
        with self.assertRaises(model.EvidenceError):
            image.offset(0x1004)

    def test_non_start_fde_is_rejected(self):
        image = object.__new__(model.Image)
        image.starts = [0x1000]
        image.fde_ends = {0x1000: 0x1010}
        self.assertEqual(image.exact_fde(0x1000), (0x1000, 0x1010))
        with self.assertRaises(model.EvidenceError):
            image.exact_fde(0x1001)
        with self.assertRaises(model.EvidenceError):
            image.fde(0x1010)

    def test_relocation_binding_rejects_missing_and_changed_targets(self):
        entries = [(slot, *value) for slot, value in model.SLOT_BINDINGS.items()]
        self.assertEqual(model.validate_bindings(entries), model.SLOT_BINDINGS)
        with self.assertRaises(model.EvidenceError):
            model.validate_bindings(entries[:-1])
        slot, kind, addend, symbol = entries[0]
        changed = [(slot, kind, addend ^ 1, symbol)] + entries[1:]
        with self.assertRaises(model.EvidenceError):
            model.validate_bindings(changed)
        with self.assertRaises(model.EvidenceError):
            model.validate_bindings(entries + [entries[0]])


class SelectorControls(unittest.TestCase):
    def test_first_timer_ready(self):
        self.assertEqual(
            model.independent_select(model.select_case()),
            (model.SENTINEL + 6, 0x1bf, (0, 1), (("poll", 0, "ready"),)),
        )

    def test_second_timer_ready_after_first_pending(self):
        result = model.independent_select(model.select_case(5, "pending", "ready"))
        self.assertEqual(result[0], model.SENTINEL + 7)
        self.assertEqual(result[2], (1, 0))
        self.assertEqual(result[3], (("poll", 0, "pending"), ("poll", 1, "ready")))

    def test_both_timers_pending(self):
        result = model.independent_select(model.select_case(5, "pending", "pending"))
        self.assertEqual(result[0], model.SENTINEL + 11)
        self.assertEqual(result[1], 0x19f)

    def test_unenabled_timer_is_pending_without_poll(self):
        result = model.independent_select(model.select_case(5, "off", "masked"))
        self.assertEqual(result[0], model.SENTINEL + 11)
        self.assertEqual(result[3], ())

    def test_non_boolean_enabled_byte_is_pending_without_poll(self):
        result = model.independent_select(model.select_case(5, "other", "masked"))
        self.assertEqual(result[0], model.SENTINEL + 11)
        self.assertEqual(result[2], (2, 1))
        self.assertEqual(result[3], ())

    def test_poll_result_uses_zero_versus_nonzero(self):
        ready = model.independent_select(model.select_case(5, "pending", "masked", poll_first=0))
        pending = model.independent_select(model.select_case(5, "pending", "masked", poll_first=255))
        self.assertEqual(ready[0], model.SENTINEL + 6)
        self.assertEqual(pending[0], model.SENTINEL + 11)

    def test_exhausted_selector_has_different_tag(self):
        result = model.independent_select(model.select_case(5, "masked", "masked"))
        self.assertEqual(result[0], model.SENTINEL + 10)
        self.assertEqual(result[3], ())

    def test_rotation_decides_which_ready_timer_wins(self):
        first = model.independent_select(model.select_case(5, "ready", "ready"))
        second = model.independent_select(model.select_case(6, "ready", "ready"))
        self.assertEqual(first[0], model.SENTINEL + 6)
        self.assertEqual(second[0], model.SENTINEL + 7)

    def test_all_valid_start_offsets(self):
        for start in range(9):
            with self.subTest(start=start):
                result = model.independent_select(model.select_case(start, "ready", "masked"))
                self.assertEqual(result[0], model.SENTINEL + 6)

    def test_invalid_start_and_mode_fail_closed(self):
        for args in ((-1, "ready", "masked"), (9, "ready", "masked"), (0, "wrong", "masked")):
            with self.subTest(args=args), self.assertRaises(ValueError):
                model.select_case(*args)


class PredicateControls(unittest.TestCase):
    def setUp(self):
        self.state = model.initial_state(model.default_case())

    def test_success_compares_all_twenty_bytes(self):
        self.assertEqual(model.independent_predicate(model.predicate_case(), self.state), (1, ()))
        for position in range(20):
            case = model.predicate_case(same=False, flip=position)
            with self.subTest(position=position):
                self.assertEqual(model.independent_predicate(case, self.state), (0, ()))

    def test_error_tag_cannot_become_a_match(self):
        for tag in range(256):
            if tag == 0x2e:
                continue
            with self.subTest(tag=tag):
                self.assertEqual(model.independent_predicate(model.predicate_case(tag), self.state)[0], 0)

    def test_error_cleanup_depends_on_tag_and_sizes(self):
        cases = (
            (0x10, 3, 7, (3, 7)),
            (0x10, 0, 7, (7,)),
            (0x10, 3, 0, (3,)),
            (0x20, 3, 7, (3,)),
            (0x13, 3, 7, (3,)),
            (0x11, 3, 7, ()),
        )
        for tag, first, second, expected in cases:
            case = model.predicate_case(tag, first_size=first, second_size=second)
            with self.subTest(tag=tag, first=first, second=second):
                sizes = tuple(size for _, size in model.independent_predicate(case, self.state)[1])
                self.assertEqual(sizes, expected)

    def test_bad_flip_index_rejected(self):
        with self.assertRaises(ValueError):
            model.predicate_case(flip=20)


class TimerArithmeticControls(unittest.TestCase):
    def test_nanosecond_boundary_and_carry(self):
        cases = (
            ((10, 0, 2, 0), (12, 0)),
            ((10, 999999998, 2, 1), (12, 999999999)),
            ((10, 999999999, 2, 1), (13, 0)),
            ((10, 999999999, 2, 2), (13, 1)),
        )
        for arguments, expected in cases:
            with self.subTest(arguments=arguments):
                self.assertEqual(model.timer_sum(*arguments), expected)

    def test_overflow_and_exact_double_second_are_rejected(self):
        cases = (
            ((1 << 63) - 1, 0, 1, 0),
            ((1 << 63) - 1, 999999999, 0, 1),
            (1, 1000000000, 0, 1000000000),
        )
        for arguments in cases:
            with self.subTest(arguments=arguments):
                self.assertIsNone(model.timer_sum(*arguments))

    def test_input_widths_are_checked(self):
        for arguments in ((-1, 0, 0, 0), (0, -1, 0, 0), (1 << 64, 0, 0, 0), (0, 1 << 32, 0, 0)):
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                model.timer_sum(*arguments)

    def test_raw_u32_addition_wraps_like_the_instruction(self):
        self.assertEqual(model.timer_sum(4, 0xffffffff, 0, 1), (4, 0))

    def test_negative_delta_sign_must_match_signed_overflow(self):
        self.assertIsNone(model.timer_sum(0, 0, model.MAX_U64, 0))
        self.assertEqual(model.timer_sum(model.SENTINEL, 0, model.MAX_U64, 0),
                         (model.SENTINEL - 1, 0))


class TimeoutControls(unittest.TestCase):
    def result(self, **values):
        return model.independent_timeout(model.default_case(**values))

    def test_saturating_counter(self):
        for count, expected in ((0, 1), (1, 2), (model.MAX_U64 - 1, model.MAX_U64), (model.MAX_U64, model.MAX_U64)):
            with self.subTest(count=count):
                _, state, _, _ = self.result(count=count, voted=1)
                self.assertEqual(model.qword(state, 0x8c8), expected)

    def test_vote_call_count_depends_on_both_inputs(self):
        cases = ((0, 0, 1), (0, 1, 0), (1, 0, 2), (1, 1, 1))
        for count, voted, expected in cases:
            with self.subTest(count=count, voted=voted):
                _, _, messages, _ = self.result(count=count, voted=voted)
                self.assertEqual(len(messages), expected)

    def test_optional_second_message_is_emitted_per_vote(self):
        _, _, messages, _ = self.result(count=1, voted=0, second=True)
        self.assertEqual([tag for tag, _ in messages],
                         [model.SENTINEL + 2, model.SENTINEL + 3] * 2)

    def test_empty_and_nonempty_tree_choose_different_contracts(self):
        empty = self.result(representation="tree_empty")[3]
        tree = self.result(representation="tree")[3]
        ring = self.result(representation="ring")[3]
        self.assertFalse(any(item[0].startswith("clone_") for item in empty))
        self.assertTrue(any(item[0] == "clone_tree" for item in tree))
        self.assertTrue(any(item[0] == "clone_ring" for item in ring))

    def test_nonempty_null_tree_panics_before_signing(self):
        status, _, messages, calls = self.result(representation="tree_bad")
        self.assertEqual(status, "panic")
        self.assertEqual(messages, ())
        self.assertEqual(calls[-1], ("panic",))
        self.assertFalse(any(call[0] == "sign" for call in calls))

    def test_growth_occurs_at_capacity_boundary(self):
        _, _, messages, calls = self.result(count=1, voted=0, second=True, capacity=1)
        self.assertEqual(len(messages), 4)
        self.assertEqual([call for call in calls if call[0] == "grow"],
                         [("grow", 1, 2), ("grow", 2, 4)])

    def test_timestamp_is_copied_to_the_state(self):
        _, state, _, _ = self.result(stamp=(17, 3600, 15))
        self.assertEqual(struct.unpack_from("<III", state, 0xb9c), (17, 3600, 15))

    def test_timer_failure_does_not_mark_timer_active(self):
        status, state, _, calls = self.result(clock=((1 << 63) - 1, 1),
                                               delta_seconds=0, delta_nanos=999999999)
        self.assertEqual(status, "panic")
        self.assertEqual(state[0xaa0], 0)
        self.assertEqual(calls[-1], ("panic",))
        self.assertFalse(any(call[0] == "reset" for call in calls))

    def test_elapsed_observations_are_consistent(self):
        _, _, _, calls = self.result(elapsed=(2, 500000000))
        observations = [call for call in calls if call[0] == "observe"]
        self.assertEqual(observations, [("observe", 11, model.to_bits(2.5)), ("observe", 18, model.to_bits(2.5))])

    def test_invalid_result_corruption_is_detected(self):
        result = self.result()
        bad_state = bytearray(result[1])
        bad_state[0x8c8] ^= 1
        corrupted = (result[0], bytes(bad_state), result[2], result[3])
        self.assertNotEqual(result, corrupted)

    def test_changed_message_byte_is_detected(self):
        result = self.result()
        tag, payload = result[2][0]
        altered = bytearray(payload)
        altered[-1] ^= 1
        corrupted = (result[0], result[1], ((tag, bytes(altered)),), result[3])
        self.assertNotEqual(result, corrupted)


class FlowControls(unittest.TestCase):
    def test_fresh_flow_starts_two_timers_for_local_match(self):
        case = model.default_case(fresh=True, lookup_match=True)
        result = model.independent_flow(case)
        resets = [event for event in result[4] if event[0] == "reset"]
        self.assertEqual(len(resets), 3)
        self.assertEqual(result[2][0xac0], 1)
        self.assertEqual(result[:2], (1, 3))

    def test_fresh_flow_starts_one_timer_without_local_match(self):
        case = model.default_case(fresh=True, lookup_match=False)
        result = model.independent_flow(case)
        resets = [event for event in result[4] if event[0] == "reset"]
        self.assertEqual(len(resets), 2)
        self.assertEqual(result[2][0xac0], 0)

    def test_closed_queue_discards_generated_items(self):
        case = model.default_case(closed=True)
        result = model.independent_flow(case)
        self.assertEqual(result[3], ())
        self.assertEqual(result[5][-1], ("closed", model.SENTINEL + 2))
        self.assertEqual(result[8], (0, 1, 0, 0, 0, 0, 2))

    def test_filter_discards_before_queue_access(self):
        case = model.default_case(keep=False)
        result = model.independent_flow(case)
        self.assertEqual(result[3], ())
        self.assertEqual(result[5], (("timer_poll", model.TIMER_AT),))
        self.assertIn(("drop", model.SENTINEL + 2), result[6])

    def test_filter_compacts_mixed_message_results_in_order(self):
        case = model.default_case(count=1, second=True, keep_pattern=(False, True), capacity=1)
        result = model.independent_flow(case)
        self.assertEqual([tag for tag, _ in result[3]], [model.SENTINEL + 3] * 2)
        self.assertEqual([entry[0] for entry in result[6]],
                         ["filter", "drop", "filter", "filter", "drop", "filter"])
        self.assertEqual(result[8], (2, 4, 0, 2, 3, 0, 2))

    def test_no_vote_does_not_emit_a_queue_item(self):
        case = model.default_case(count=0, voted=1)
        result = model.independent_flow(case)
        self.assertEqual(result[3], ())
        self.assertEqual(result[5], (("timer_poll", model.TIMER_AT),))

    def test_flow_rejects_panic_as_normal_return(self):
        case = model.default_case(clock=((1 << 63) - 1, 1), delta_seconds=0, delta_nanos=999999999)
        with self.assertRaises(ValueError):
            model.independent_flow(case)

    def test_case_sequences_are_deterministic_and_nonempty(self):
        for factory in (model.select_cases, model.predicate_cases, model.timer_cases, model.flow_cases):
            with self.subTest(factory=factory.__name__):
                self.assertEqual(list(itertools.islice(factory(), 3)), list(itertools.islice(factory(), 3)))
                self.assertGreater(len(list(itertools.islice(factory(), 3))), 0)


if __name__ == "__main__":
    unittest.main()
