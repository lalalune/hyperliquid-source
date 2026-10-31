"""Tests for the node #94 order placement packet: rules, real-byte runs and negative controls."""

import copy
import importlib.util
import json
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("order_place_route", ROOT / "tools" / "order_place_route.py")
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)
FOLDER = ROOT / "research" / "work-items" / "RE-006-order-place-route-94"


def shared_setup(cls):
    cls.image = tool.load_image()
    cls.harness = tool.Harness(cls.image)


class Base(unittest.TestCase):
    setUpClass = classmethod(shared_setup)

    def place(self, world, number=0):
        return self.harness.run(tool.Case("t: x", "place", world, number))

    def route(self, number=0, **changes):
        return self.harness.run(tool.Case("t: x", "route", tool.route_world(**changes), number))

    def wrap(self, world, number=0):
        return self.harness.run(tool.Case("t: x", "wrap", world, number))

    def names(self, answer):
        return [row[0] for row in answer["log"]]

    def test_rule_routes(self):
        self.assertEqual(tool.route_of(0, 0, 0, 1, 10007), "direct")
        self.assertEqual(tool.route_of(1, 0, 0, 1, 10007), "direct")
        self.assertEqual(tool.route_of(2, 0, 0, 1, 10007), "dex")
        self.assertEqual(tool.route_of(2, 0, 0, 1, 9999), "direct")
        self.assertEqual(tool.route_of(2, 0, 0, 0, 10007), "direct")
        self.assertEqual(tool.route_of(3, 0, 0, 0, 7), "collateral")
        self.assertEqual(tool.route_of(3, 0, 1, 0, 7), "direct")
        self.assertEqual(tool.route_of(4, 0, 1, 0, 7), "collateral")
        self.assertEqual(tool.route_of(4, 1, 0, 0, 7), "direct")

    def test_rule_words(self):
        self.assertEqual([tool.order_type(kind, market) for kind in (0, 1) for market in (0, 1)], [3, 2, 5, 4])
        self.assertEqual([tool.limit_type(3, 0), tool.limit_type(2, 3), tool.limit_type(0, 2), tool.limit_type(1, 0x103)], [9, 1, 0, 1])
        self.assertEqual(tool.wire_asset(9999), 9999)
        self.assertEqual(tool.wire_asset(10000), 110000)
        self.assertEqual(tool.wire_asset(99899999), 99999999)
        self.assertEqual(tool.wire_asset(99900000), 0xFFFFFFFF)
        self.assertEqual(tool.error_index(tool.NONE_WORD | 9), 9)
        self.assertEqual(tool.error_index(7), 2)

    def test_rule_bucket(self):
        now = tool.NOW
        self.assertEqual(tool.bucket_step(3, now, now, 1000, 4), (4, True))
        self.assertEqual(tool.bucket_step(4, now, now, 1000, 4), (5, False))
        self.assertEqual(tool.bucket_step(99, (now[0], now[1] - 1, now[2]), now, 1000, 1), (1, True))
        self.assertEqual(tool.bucket_step(tool.MAX64, now, now, 1000, 4), (tool.MAX64, False))

    def test_real_bytes_gate_needs_both_over(self):
        for number in (0, 2):
            self.assertEqual(self.route(number, mode=3, bucket_one=5, bucket_two=20)["out"], "too many")
            self.assertEqual(self.route(number, mode=3, bucket_one=5, bucket_two=1)["out"], "wrapper")
            self.assertEqual(self.route(number, mode=3, bucket_one=1, bucket_two=20)["out"], "wrapper")

    def test_real_bytes_rejected_call_still_counts(self):
        answer = self.route(mode=3, bucket_one=5, bucket_two=20)
        self.assertEqual(answer["bucket"][:2], [6, 21])
        self.assertEqual(answer["ops"], 50)
        self.assertEqual(answer["total"], 40)
        self.assertEqual(answer["freed"], [0x5300, 3 * 0x48])
        self.assertNotIn("wrap", self.names(answer))

    def test_real_bytes_second_router_has_no_gate(self):
        for number in (1, 3):
            answer = self.route(number, mode=3, bucket_one=90, bucket_two=90)
            self.assertEqual(answer["out"], "wrapper")
            self.assertNotIn("bucket", answer)
            self.assertEqual(answer["ops"], 51)

    def test_real_bytes_step_failure_is_dropped(self):
        answer = self.route(mode=2, before=0x141, after=0x162, request=tool.default_request(asset=10007))
        self.assertEqual(answer["out"], "wrapper")
        self.assertEqual(self.names(answer), ["mode row", "names", "step", "drop step", "wrap", "names", "step", "drop step"])

    def test_real_bytes_trigger_rests_in_field_u(self):
        world = tool.trigger_world(kind=1, market=1, third=5000, flag=1)
        for number in range(4):
            answer = self.place(world, number)
            self.assertEqual(answer["tree"][0][0], 9000)
            self.assertEqual(answer["tree"][0][5], 4)
            self.assertEqual(answer["tree"][0][-1], 0x101)
            self.assertEqual(answer["result"]["resting"], 1)
            self.assertEqual(answer["oid_after"], 9001)
            self.assertNotIn("insert", self.names(answer))

    def test_real_bytes_trigger_price_gate(self):
        self.assertIn("tree", self.place(tool.trigger_world(third=tool.MAX_TRIGGER)))
        for third in (tool.MAX_TRIGGER + 10, 5001):
            answer = self.place(tool.trigger_world(third=third))
            self.assertEqual(answer["error"], tool.NONE_WORD | tool.ERROR_TPSL)
            self.assertNotIn("tree", answer)
            self.assertEqual(answer["oid_after"], 9001)
            self.assertEqual(answer["log"][-1][-1], 0x18)

    def test_real_bytes_twap_error_writes_no_row(self):
        answer = self.place(tool.limit_world(group=tool.default_group(tag=3), insert={"error": tool.NONE_WORD | 2}))
        self.assertEqual(answer["rows_len"], 0)
        self.assertEqual(answer["oid_after"], 9000)
        self.assertEqual(self.names(answer), ["insert"])

    def test_real_bytes_limit_type_word(self):
        self.assertEqual(self.place(tool.limit_world(third=2))["log"][0][5], 0)
        self.assertEqual(self.place(tool.limit_world(third=3))["log"][0][5], 1)
        self.assertEqual(self.place(tool.limit_world(third=0, group=tool.default_group(tag=3)))["log"][0][5], 9)

    def test_real_bytes_spot_has_no_dex_bound(self):
        world = tool.limit_world(request=tool.default_request(kind=2, third=2, asset=30000))
        self.assertTrue(self.place(world, 0)["panic"])
        self.assertNotIn("panic", self.place(world, 2))

    def test_real_bytes_wrapper_status_shapes(self):
        base = {"request": tool.default_request(asset=10003), "group": tool.default_group(tag=1), "user": 5, "now": tool.NOW, "rows_count": 20000, "books": 40, "host": {"word": tool.NONE_WORD, "error": 5, "rows": 1}, "depth": 3}
        for number in range(4):
            answer = self.wrap(base, number)
            self.assertEqual((answer["tag"], answer["extra"], answer["first"], answer["depth"]), (tool.TAG_ERROR, 110003, 5, 3))
            self.assertEqual(answer["log"][-1], ["flush", 1, 1])

    def test_all_cases_match(self):
        failures = [line for line in (tool.compare_run(self.harness, case) for case in tool.all_cases()) if line]
        self.assertEqual(failures, [])

    def test_static_context_names(self):
        rows = {row["field"]: row["offset"] for row in tool.context_rows(self.image)}
        self.assertEqual(rows["next_oid"], "0x38")
        self.assertEqual(rows["time"], "0x60")
        self.assertEqual(rows["maybe_operate_with_abstraction_reentrancy_counter"], "0x58")
        self.assertEqual(rows["tx_index"], "0x0")

    def test_static_texts(self):
        tags = {row["tag"]: row["text"] for row in tool.tag_rows(self.image)}
        self.assertTrue(tags["0x170"].startswith("Too many abstraction operations."))
        errors = tool.error_rows(self.image)
        self.assertEqual(errors[9]["text"], "Invalid TP/SL price.")
        self.assertEqual(errors[9]["status_byte"], "0x18")

    def test_static_copies(self):
        rows = tool.copy_table(self.image)
        self.assertEqual(len(rows), len(tool.COPY_PAIRS))
        self.assertEqual(len(rows[0]["state_rows"]), 9)
        self.assertEqual(rows[0]["targets_that_differ"], [["0x4311140", "0x4314da0"]])

    def test_control_wrong_digest(self):
        with self.assertRaisesRegex(tool.EvidenceError, "SHA-256 mismatch"):
            tool.load_image(expected="0" * 64)

    def test_control_outside_fde_and_file(self):
        with self.assertRaisesRegex(tool.EvidenceError, "not an FDE start"):
            self.image.exact_fde(tool.GATE + 1)
        with self.assertRaisesRegex(tool.EvidenceError, "outside file-backed"):
            self.image.offset(self.image.named[".bss"]["address"] + 8)

    def tampered(self, va, value):
        changed = copy.copy(self.image)
        blob = bytearray(self.image.blob)
        blob[self.image.offset(va)] = value
        changed.blob = bytes(blob)
        return changed

    def test_control_status_table_byte(self):
        with self.assertRaisesRegex(tool.EvidenceError, "status table"):
            tool.error_rows(self.tampered(tool.STATUS_TABLE + 9, 0x7F))

    def test_control_copy_byte(self):
        with self.assertRaisesRegex(tool.EvidenceError, "copy row"):
            tool.copy_table(self.tampered(0x4309700 + 0x10, 0x90))

    def test_control_context_lea(self):
        with self.assertRaisesRegex(tool.EvidenceError, "field lea"):
            tool.context_rows(self.tampered(0x4C69736 + 1, 0x90))

    def test_control_branch_flip_is_caught(self):
        machine = self.harness.machine
        rows = tool.decode_range(self.image, *self.image.exact_fde(tool.GATE))
        row = next(one for one in rows if one.op == "jcc" and one.va > tool.GATE + 0x1A0)
        machine.patches = tool.mutate_patch(self.image, row.va, row.size - (2 if row.size == 2 else 5), "branch")
        machine.cache.pop(row.va, None)
        try:
            failed = [case for case in tool.gate_cases() if tool.compare_run(self.harness, case)]
        finally:
            machine.patches = {}
            machine.cache.pop(row.va, None)
        self.assertTrue(failed)

    def test_control_wrong_spec_is_caught(self):
        world = tool.trigger_world()
        case = tool.Case("t: x", "place", world, 0)
        wanted = tool.run_spec(case)
        wanted["oid_after"] += 1
        self.assertNotEqual(self.harness.run(case), wanted)

    def test_control_row_past_capacity_halts(self):
        machine = self.harness.machine
        rows = tool.decode_range(self.image, *self.image.exact_fde(0x430BE90))
        row = next(one for one in rows if one.va == 0x430C632)
        machine.patches = tool.mutate_patch(self.image, row.va, row.size - 2, "branch")
        machine.cache.pop(row.va, None)
        try:
            line = tool.compare_run(self.harness, tool.Case("t: x", "place", tool.trigger_world(third=5001, rows_cap=1, rows_len=1), 0))
        finally:
            machine.patches = {}
            machine.cache.pop(row.va, None)
        self.assertIn("row address", line)

    def test_evidence_files(self):
        document = json.loads((FOLDER / "evidence.json").read_text())
        self.assertEqual(document["mismatches"], 0)
        self.assertEqual(document["cases"]["total"], len(tool.all_cases()))
        self.assertEqual(document["target"]["sha256"], tool.SHA256)
        rows = [line.split("\t") for line in (FOLDER / "mutations.tsv").read_text().splitlines()[1:]]
        self.assertFalse([row for row in rows if row[3] != "killed" and (not row[5] or row[5].startswith("not explained"))])


if __name__ == "__main__":
    unittest.main()
