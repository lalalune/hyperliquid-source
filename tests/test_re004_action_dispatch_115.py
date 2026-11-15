import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import re004_action_dispatch_115 as T  # noqa: E402

FOLDER = ROOT / "research" / "work-items" / "RE-004-action-dispatch-115"
NICHE, OK, H = T.NICHE, T.OK, T.H
U64 = T.U64


def rows(name):
    lines = (FOLDER / name).read_text().splitlines()
    return [line.split("\t") for line in lines[1:]]


def tagged(arm_tag, ln=5, cap=5, flag=0):
    """A bare action block: tag word, String (cap, ptr, len) and the flag byte."""
    block = bytearray(bytes([T.STACK_MARK]) * 0x100)
    block[0:8] = arm_tag.to_bytes(8, "little")
    block[8:32] = cap.to_bytes(8, "little") + T.STR.to_bytes(8, "little") + ln.to_bytes(8, "little")
    block[32] = flag
    return bytes(block)


def run(action, script, record=None, limit=0, string=b"abc:def"):
    case = {"arm": 0, "limit": limit, "script": script, "action": action, "string": string,
            "record": record if record is not None else bytes(T.REC_LEN)}
    return T.run_model(case)


def res(code, w1=None, w2=None, b8=None):
    raw = bytearray(bytes([0x11]) * 0x70)
    raw[0:2] = code.to_bytes(2, "little")
    if w1 is not None:
        raw[8:16] = w1.to_bytes(8, "little")
    if w2 is not None:
        raw[16:24] = w2.to_bytes(8, "little")
    if b8 is not None:
        raw[8] = b8
    return T.Res(raw)


class JumpTableIndex(unittest.TestCase):
    def test_niche_tags_select_arms(self):
        for arm in range(7):
            self.assertEqual(T.slot_index(NICHE + 13 + arm), arm)

    def test_dataful_and_low_niche_tags_use_arm_five(self):
        for tag in (0, 1, 1 << 40, NICHE - 1, NICHE, NICHE + 5, NICHE + 12, NICHE + 18):
            self.assertEqual(T.slot_index(tag), 5, hex(tag))

    def test_boundary_is_exact(self):
        self.assertEqual(T.slot_index(NICHE + 12), 5)
        self.assertEqual(T.slot_index(NICHE + 13), 0)
        self.assertEqual(T.slot_index(NICHE + 14), 1)


class AssetIdMapping(unittest.TestCase):
    def test_thresholds(self):
        table = {0: 0, 9999: 9999, 10000: 110000, 10001: 110001, 0x5F45A5F: 0x5F45A5F + 100000,
                 0x5F45A60: 0xFFFFFFFF, U64: 0xFFFFFFFF, 1 << 32: 0xFFFFFFFF}
        for index, want in table.items():
            self.assertEqual(T.asset_id(index), want, hex(index))

    def test_largest_valid_id_is_below_a_hundred_million(self):
        self.assertEqual(T.asset_id(0x5F45A5F), 99_999_999)

    def test_wrong_threshold_is_noticed(self):
        wrong = lambda i: i if i <= 9999 else (i + 100000 if i <= 0x5F45A60 else 0xFFFFFFFF)  # noqa: E731
        self.assertNotEqual(wrong(0x5F45A60), T.asset_id(0x5F45A60))


class VectorModel(unittest.TestCase):
    def build(self, factor, start, end, fail=False):
        heap = bytearray(bytes([T.STACK_MARK]) * T.USED)
        mem = T.Mem(heap)
        mem.put(T.REC + 0x50, factor.to_bytes(8, "little"))
        world = T.World({"alloc_fail": fail, "alloc_limit": 0x4000})
        return mem, world

    def test_ids_are_offset_by_ten_thousand_times_the_factor(self):
        mem, world = self.build(3, 2, 6)
        cap, ptr, items = T.vec_model(mem, world, T.REC, 2, 6)
        self.assertEqual((cap, items), (4, [30002, 30003, 30004, 30005]))
        self.assertEqual(world.log, [("alloc", 32)])

    def test_empty_range_allocates_nothing(self):
        for start, end in ((0, 0), (5, 5), (9, 2)):
            mem, world = self.build(7, start, end)
            self.assertEqual(T.vec_model(mem, world, T.REC, start, end), (0, 8, []))
            self.assertEqual(world.log, [])

    def test_multiplication_overflow_threshold(self):
        mem, world = self.build(1844674407370955, 0, 1)
        self.assertEqual(T.vec_model(mem, world, T.REC, 0, 1)[2], [18446744073709550000])
        mem, world = self.build(1844674407370956, 0, 1)
        with self.assertRaises(T.ModelPanic):
            T.vec_model(mem, world, T.REC, 0, 1)
        self.assertEqual(world.log[-1][0], "mul_ovf")

    def test_addition_overflow_is_reported_at_the_first_wrapping_item(self):
        mem, world = self.build(1844674407370955, 0, 2000)
        with self.assertRaises(T.ModelPanic):
            T.vec_model(mem, world, T.REC, 0, 2000)
        self.assertEqual(world.log[-1][0], "add_ovf")

    def test_capacity_overflow_and_allocation_failure(self):
        mem, world = self.build(1, 0, 1 << 61)
        with self.assertRaises(T.ModelPanic):
            T.vec_model(mem, world, T.REC, 0, 1 << 61)
        self.assertEqual(world.log, [("handle_error", 0, 0)])
        mem, world = self.build(1, 0, 3, fail=True)
        with self.assertRaises(T.ModelPanic):
            T.vec_model(mem, world, T.REC, 0, 3)
        self.assertEqual(world.log, [("alloc", 24), ("handle_error", 8, 24)])


class ArmModels(unittest.TestCase):
    def test_long_name_is_rejected_before_any_lookup(self):
        for arm_tag in (NICHE + 13, NICHE + 16):
            status, out, rec, log = run(tagged(arm_tag, ln=0x65), {})
            self.assertEqual(int.from_bytes(out[:2], "little"), 0x158)
            self.assertEqual(log, [("dealloc", T.STR, 5, 0)])

    def test_name_of_exactly_100_bytes_is_looked_up(self):
        script = {"find": [(0, 0)], "uni_lookup_a": [res(0x156)]}
        status, out, rec, log = run(tagged(NICHE + 13, ln=0x64), script)
        self.assertEqual(int.from_bytes(out[:2], "little"), 0x156)
        self.assertEqual([entry[0] for entry in log], ["find", "uni_lookup_a", "dealloc"])
        self.assertEqual(log[1][1:], (T.CTX + 0x1330, 1, 0))

    def test_arm_zero_forwards_the_mapped_asset_id(self):
        script = {"find": [(1, 3)], "uni_lookup_a": [res(OK, w1=77)], "asset_idx": [res(OK, w1=10000)],
                  "exec": [res(OK)]}
        status, out, rec, log = run(tagged(NICHE + 13, ln=7), script)
        event = log[3][2]
        self.assertEqual(event, (0x35).to_bytes(8, "little") + (110000).to_bytes(4, "little") + b"\x01")
        self.assertEqual(log[1][1:], (T.CTX + 0x1330, T.STR, 3))
        self.assertEqual(log[2][1:], (T.STR, 7, 77))

    def test_error_results_are_copied_whole(self):
        raw = res(0x1A3)
        script = {"find": [(0, 0)], "uni_lookup_a": [raw]}
        status, out, rec, log = run(tagged(NICHE + 13), script)
        self.assertEqual(out[:0x70], raw.raw)
        self.assertEqual(out[0x70:], bytes([T.STACK_MARK]) * 0x10)

    def test_index_bound_error_carries_the_index(self):
        action = bytearray(tagged(NICHE + 19))
        action[8:16] = (9).to_bytes(8, "little")
        status, out, rec, log = run(bytes(action), {}, limit=9)
        self.assertEqual(int.from_bytes(out[:2], "little"), 0xFA)
        self.assertEqual(int.from_bytes(out[8:16], "little"), 9)
        self.assertEqual(log, [])
        status, out, rec, log = run(bytes(action), {"indexed_apply": [res(OK)]}, limit=10)
        self.assertEqual(log[0][0], "indexed_apply")
        self.assertEqual(log[0][2], bytes(action[8:0x60]))

    def test_default_arm_hands_over_the_whole_block_and_drops_it(self):
        action = tagged(77, ln=1)
        for outcome in (res(OK), res(0x1A1)):
            status, out, rec, log = run(action, {"zero_addr_apply": [outcome]})
            self.assertEqual([entry[0] for entry in log], ["memcpy", "zero_addr_apply", "drop"])
            log = log[1:]
            self.assertEqual(log[0][2], bytes(20))
            self.assertEqual(log[1][1], action[:0xB0])

    def test_flag_set_writes_two_and_clear_writes_zero(self):
        record = bytearray(bytes([0xEE]) * T.REC_LEN)
        record[0x378:0x380] = (5).to_bytes(8, "little")
        record[0x10:0x18] = (0).to_bytes(8, "little")
        script = {"uni_lookup_b": [res(OK, w1=T.REC)]}
        status, out, rec, log = run(tagged(NICHE + 16, flag=1), script, record=bytes(record))
        self.assertEqual(rec[0x468], 2)
        status, out, rec, log = run(tagged(NICHE + 16, flag=0), script, record=bytes(record))
        self.assertEqual(rec[0x468], 0)

    def test_flag_set_registers_every_asset_of_the_record(self):
        record = bytearray(bytes([0]) * T.REC_LEN)
        record[0x10:0x18] = (3).to_bytes(8, "little")
        record[0x50:0x58] = (2).to_bytes(8, "little")
        script = {"uni_lookup_b": [res(OK, w1=T.REC)], "reg": [None]}
        status, out, rec, log = run(tagged(NICHE + 16, flag=1), script, record=bytes(record))
        regs = [entry[2] for entry in log if entry[0] == "reg"]
        self.assertEqual(regs, [20000, 20001, 20002])
        self.assertEqual([entry[0] for entry in log].count("dealloc"), 2)

    def test_missing_record_marker_gives_not_found(self):
        record = bytearray(bytes([0]) * T.REC_LEN)
        record[0x378:0x380] = NICHE.to_bytes(8, "little")
        status, out, rec, log = run(tagged(NICHE + 16, flag=1), {"uni_lookup_b": [res(OK, w1=T.REC)]},
                                    record=bytes(record))
        self.assertEqual(int.from_bytes(out[:2], "little"), 0x156)

    def test_arm_four_flag_truth_table(self):
        record = bytearray(bytes([0]) * T.REC_LEN)
        record[0x378:0x380] = (5).to_bytes(8, "little")
        record[0x408:0x410] = (NICHE + 1).to_bytes(8, "little")
        for flag, probe, calls in ((1, 2, True), (1, 0, False), (1, 1, False), (0, 2, False), (0, 0, True), (0, 3, True)):
            script = {"lookup_c": [res(OK, w1=T.REC, w2=123456)], "flag_probe": [res(OK, b8=probe)],
                      "ts_div": [999], "apply_flag": [res(OK)]}
            status, out, rec, log = run(tagged(NICHE + 17, flag=flag), script, record=bytes(record))
            names = [entry[0] for entry in log]
            self.assertEqual("apply_flag" in names, calls, (flag, probe))
            if calls:
                self.assertEqual(log[names.index("ts_div")][2], 12)
                self.assertEqual(log[names.index("apply_flag")][1:], (999, 123456, 1 if flag else 2))

    def test_quotient_uses_the_multiply_shift_form(self):
        for value in (0, 9999, 10000, 10001, 10000 * 1844674407370955, U64, U64 - 1):
            self.assertEqual((value * T.MAGIC10K >> 64) >> 11, value // 10000, value)
        wrong = T.MAGIC10K ^ 1
        self.assertNotEqual((10000 * 1844674407370955 * wrong >> 64) >> 11, 1844674407370955)

    def test_record_checks_precede_the_probe(self):
        record = bytearray(bytes([0]) * T.REC_LEN)
        record[0x378:0x380] = NICHE.to_bytes(8, "little")
        script = {"lookup_c": [res(OK, w1=T.REC, w2=1)]}
        self.assertEqual(int.from_bytes(run(tagged(NICHE + 17), script, record=bytes(record))[1][:2], "little"), 0x156)
        record[0x378:0x380] = (3).to_bytes(8, "little")
        record[0x408:0x410] = NICHE.to_bytes(8, "little")
        self.assertEqual(int.from_bytes(run(tagged(NICHE + 17), script, record=bytes(record))[1][:2], "little"), 0x1A1)

    def test_tag_outside_the_table_is_refused(self):
        with self.assertRaises(T.ToolError):
            run(tagged(NICHE + 20), {})


class DexSearch(unittest.TestCase):
    def world(self, names, niche=()):
        heap = bytearray(bytes([T.STACK_MARK]) * T.USED)
        mem = T.Mem(heap)
        uni = []
        for i, name in enumerate(names):
            record = bytearray(T.DEX_STRIDE)
            if i in niche:
                record[0x378:0x380] = NICHE.to_bytes(8, "little")
            uni.append((bytes(record), name))
        case = {"limit": 0, "string": b"", "action": bytes(0x100), "record": bytes(T.REC_LEN), "universe": uni}
        mem = T.Mem(T.build_heap(case))
        return mem, T.World({})

    def test_empty_name_selects_the_first_record(self):
        mem, world = self.world([b"a", b"b"])
        result = T.find_dex(mem, world, T.CTX + 0x1330, 1, 0)
        self.assertEqual((result.code, result.w1), (OK, T.UNI))

    def test_named_search_skips_marked_records(self):
        mem, world = self.world([b"abc", b"abc", b"xyz"], niche=(0,))
        result = T.find_dex(mem, world, T.CTX + 0x1330, T.STR, 3)
        self.assertEqual(result.code, 0x156)
        mem.put(T.STR, b"abc")
        result = T.find_dex(mem, world, T.CTX + 0x1330, T.STR, 3)
        self.assertEqual((result.code, result.w1), (OK, T.UNI + T.DEX_STRIDE))

    def test_length_mismatch_never_reaches_the_comparison(self):
        mem, world = self.world([b"abcd"])
        mem.put(T.STR, b"abcd")
        T.find_dex(mem, world, T.CTX + 0x1330, T.STR, 3)
        self.assertEqual(world.log, [])

    def test_indexing_is_bounds_checked(self):
        mem, world = self.world([b"a", b"b"])
        self.assertEqual(T.dex_at(mem, world, T.CTX + 0x1330, 1), T.UNI + T.DEX_STRIDE)
        with self.assertRaises(T.ModelPanic):
            T.dex_at(mem, world, T.CTX + 0x1330, 2)
        self.assertEqual(world.log, [("drop_err", 0x156), ("unwrap_failed", 0x2B, 0x156)])


class RecordedEvidence(unittest.TestCase):
    """The recorded machine digests must be reproduced by the pure model alone (no binary needed)."""

    def case_of(self, ident, index, edges):
        if index < len(edges):
            return edges[index]
        real = ident.startswith("r")
        arm, n = (int(part) for part in ident.lstrip("r").split("."))
        return T.make_real_case(arm, n - 100000) if real else T.make_case(arm, n)

    def test_model_reproduces_every_recorded_digest(self):
        edges = T.edge_cases()
        table = rows("cases.tsv")
        self.assertGreater(len(table), 2000)
        for index, row in enumerate(table):
            case = self.case_of(row[0], index, edges)
            result = T.run_model(case)
            self.assertEqual(T.digest_of(result), row[5], row[0])
            self.assertEqual(result[0].split("(")[0], row[2], row[0])
            self.assertEqual("%#x" % int.from_bytes(result[1][:2], "little"), row[3], row[0])

    def test_a_damaged_digest_would_be_noticed(self):
        edges = T.edge_cases()
        row = rows("cases.tsv")[40]
        result = T.run_model(self.case_of(row[0], 40, edges))
        damaged = row[5][:-1] + ("0" if row[5][-1] != "0" else "1")
        self.assertNotEqual(T.digest_of(result), damaged)

    def test_wrong_model_constants_change_recorded_digests(self):
        edges = T.edge_cases()
        table = rows("cases.tsv")
        original = T.asset_id
        try:
            T.asset_id = lambda i: i if i <= 9999 else (i + 100000 if i <= 0x5F45A60 else 0xFFFFFFFF)
            changed = sum(1 for index, row in enumerate(table[:29])
                          if T.digest_of(T.run_model(self.case_of(row[0], index, edges))) != row[5])
        finally:
            T.asset_id = original
        self.assertGreaterEqual(changed, 1)

    def test_vector_rows_are_reproduced(self):
        for row in rows("vec-cases.tsv"):
            n = int(row[0])
            status, result, log = T.vec_expected(T.vec_case(n))
            self.assertEqual(status.split("(")[0], row[4])
            self.assertEqual("-" if result is None else str(result[2]), row[5])

    def test_flow_table_covers_every_arm(self):
        arms = {row[0] for row in rows("flows.tsv")}
        self.assertEqual(arms, {str(i) for i in range(7)})


class Measurements(unittest.TestCase):
    def test_summary_agrees_with_the_tables(self):
        measure = json.loads((FOLDER / "measure.json").read_text())
        controls = rows("controls.tsv")
        equivalent = rows("equivalent-mutants.tsv")
        self.assertEqual(measure["negative_controls"], len(controls))
        self.assertEqual(measure["equivalent"], len(equivalent))
        detected = [row for row in controls if row[5] == "detected"]
        self.assertEqual(measure["negative_detected"], len(detected))
        self.assertEqual(len(detected) + len(equivalent), len(controls))
        self.assertEqual(measure["mismatches"], 0)
        self.assertEqual(measure["uncovered_outside_landing_pads"], 0)

    def test_every_missed_control_is_a_listed_equivalent(self):
        missed = {row[0] for row in rows("controls.tsv") if row[5] == "missed"}
        listed = {row[0] for row in rows("equivalent-mutants.tsv")}
        self.assertEqual(missed, listed)

    def test_jump_table_rows(self):
        table = rows("arms.tsv")
        self.assertEqual([row[2] for row in table[:7]], ["yes"] * 7)
        self.assertEqual([row[2] for row in table[7:]], ["no"] * 9)

    def test_slot_rows_name_every_callee(self):
        names = {row[0] for row in rows("slots.tsv")}
        for name in list(T.SLOTS) + list(T.CALLS):
            self.assertIn(name, names)


class ImageGuard(unittest.TestCase):
    def test_wrong_digest_is_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "blob"
            path.write_bytes(b"not an elf")
            with self.assertRaises(T.EvidenceError):
                T.load_image(path, T.SHA256)

    def test_address_outside_the_file_is_refused(self):
        class Fake:
            mapped = []
        with self.assertRaises(T.EvidenceError):
            T.Image.offset(Fake, 0x1000)


if __name__ == "__main__":
    unittest.main()
