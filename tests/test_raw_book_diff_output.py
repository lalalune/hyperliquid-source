"""Tests for tools/raw_book_diff_output.py: the static pins, the specification on real bytes, and negative controls."""

import hashlib
import importlib.util
import json
import pathlib
import struct
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("raw_book_diff_output", ROOT / "tools" / "raw_book_diff_output.py")
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)
FOLDER = ROOT / "research" / "work-items" / "RE-006-raw-book-diff-output-94"


def load_shared(cls):
    cls.image = tool.load_image()
    cls.harness = tool.Harness(cls.image)
    cls.cases = tool.all_cases()


class Base(unittest.TestCase):
    setUpClass = classmethod(load_shared)

    def case(self, kind, label):
        rows = [case for case in self.cases if case.kind == kind and case.label == label]
        self.assertEqual(len(rows), 1, label)
        return rows[0]

    def poke(self, va, value):
        """Run with one byte of .text changed."""
        machine = self.harness.machine
        machine.patches = {va: value}
        machine.cache.pop(va - (va % 1), None)
        machine.cache.clear()

    def tearDown(self):
        self.harness.machine.patches = {}
        self.harness.machine.cache.clear()


class Input(unittest.TestCase):
    def test_wrong_digest_is_refused(self):
        with self.assertRaisesRegex(tool.EvidenceError, "sha256|SHA|digest"):
            tool.load_image(expected="0" * 64)

    def test_other_file_is_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "blob"
            path.write_bytes(b"not an elf")
            with self.assertRaises(tool.EvidenceError):
                tool.load_image(path=path)


class Static(Base):
    def test_twelve_writers_in_three_kinds(self):
        rows = tool.writer_rows(self.image)
        self.assertEqual(len(rows), 12)
        self.assertEqual(sorted({row["kind"] for row in rows}), ["new", "remove", "update"])
        self.assertEqual(sorted(sum(1 for row in rows if row["row_bytes"] == width) for width in (0x268, 0x278)), [6, 6])
        self.assertEqual(sum(1 for row in rows if row["scope"] != "mutated"), 2)

    def test_row_scan_finds_exactly_the_twelve(self):
        self.assertEqual(tool.row_scan(self.image), sorted(writer.start for writer in tool.WRITERS))

    def test_row_tag_patterns_miss_a_wrong_tag(self):
        writer = tool.WRITERS[4]
        tag, word = tool.row_tag_pattern(writer)
        wrong = tag[:5] + b"\x02" + tag[6:]
        begin, end = self.image.exact_fde(writer.start)
        data = tool.code(self.image, begin, end - begin)
        self.assertEqual(data.count(tag), 1)
        self.assertEqual(data.count(wrong), 0)

    def test_outside_address_has_no_fde_row(self):
        with self.assertRaises(tool.EvidenceError):
            self.image.exact_fde(0x47EF631)

    def test_sink_tables_send_kind_2_to_their_arms(self):
        rows = tool.sink_rows(self.image)
        self.assertEqual([row["arms"][0]["arm"] for row in rows], ["0x4854950", "0x4855361"])

    def test_flush_sites(self):
        rows = tool.flush_rows(self.image)
        self.assertEqual(rows["kind_2_arm"], "0x432a234")
        self.assertEqual(len(rows["sites"]), 3)

    def test_keys(self):
        rows = {row["key"]: row["record_offset"] for row in tool.key_rows(self.image)}
        self.assertEqual(rows["user"], "0x40")
        self.assertEqual(rows["px"], "0x38")
        self.assertEqual(rows["newSz"], "0x10")
        self.assertEqual(rows["events"], "0x0")

    def test_key_text_mismatch_raises(self):
        keep = tool.KEY_SITES
        tool.KEY_SITES = ((tool.RECORD_JSON, 0x47EF668, 0x40, "usex", 4),)
        try:
            with self.assertRaisesRegex(tool.EvidenceError, "key text"):
                tool.key_rows(self.image)
        finally:
            tool.KEY_SITES = keep

    def test_constructor_binds_the_name_to_the_object_offset(self):
        rows = tool.constructor_rows(self.image)
        self.assertEqual(len(rows), len(tool.CONSTRUCTOR_BYTES))

    def test_constructor_refuses_wrong_bytes(self):
        keep = tool.CONSTRUCTOR_BYTES
        tool.CONSTRUCTOR_BYTES = ((0x47F2B41, b"\xba\x41\x06\x00\x00", "wrong size"),)
        try:
            with self.assertRaisesRegex(tool.EvidenceError, "wrong size"):
                tool.constructor_rows(self.image)
        finally:
            tool.CONSTRUCTOR_BYTES = keep

    def test_float_template_has_ten_digits(self):
        self.assertEqual(tool.code(self.image, tool.FLOAT_TEMPLATE + 5, 2), b"\x0a\x00")

    def test_powers(self):
        rows = tool.powers_rows(self.image)
        self.assertEqual([row["value"] for row in rows[:4]], [1.0, 10.0, 100.0, 1000.0])

    def test_lea_target_refuses_other_bytes(self):
        with self.assertRaises(tool.EvidenceError):
            tool.lea_target(self.image, tool.RECORD_JSON)


class Spec(unittest.TestCase):
    def test_float_text(self):
        self.assertEqual(tool.float_text(1.5), "1.5")
        self.assertEqual(tool.float_text(2.0), "2.0")
        self.assertEqual(tool.float_text(100.0), "100.0")
        self.assertEqual(tool.float_text(0.0), "0.0")
        self.assertEqual(tool.float_text(-0.0), "0.0")
        self.assertEqual(tool.float_text(1e-11), "0.0")
        self.assertEqual(tool.float_text(0.1), "0.1")

    def test_spot_coin(self):
        base = tool.spot_world()
        self.assertEqual(tool.spot_coin(dict(base, asset=0)), "PURR/USDC")
        self.assertEqual(tool.spot_coin(base), "\x401")
        self.assertEqual(tool.spot_coin(dict(base, outcomes={2: (17, 1)})), "#171")
        self.assertEqual(tool.spot_coin(dict(base, outcomes={2: (17, 2)})), "\x401")

    def test_add_and_sub_saturate(self):
        self.assertEqual(tool.add_saturating(tool.MAX64, 1), (tool.MAX64, 1))
        self.assertEqual(tool.sub_saturating(1, 2), (0, 1))


class Runs(Base):
    def test_every_case_agrees(self):
        trouble = [tool.compare_run(self.harness, case) for case in self.cases]
        self.assertEqual([row for row in trouble if row], [])

    def test_case_kinds(self):
        self.assertEqual(sorted({case.kind for case in self.cases}), ["buffer", "file", "line", "sink", "writer"])

    def test_new_row_has_exact_words(self):
        got = self.harness.run(self.case("writer", "new 0x42e8710: plain rows 1 of 4"))
        row = got["rows"][0]
        self.assertEqual((row["word"], row["tag"], row["first"], row["asset"], row["side"]), (2, 0, 0x4D2, 7, 1))

    def test_update_same_size_writes_nothing(self):
        got = self.harness.run(self.case("writer", "update 0x49e4de0: same size rows 1 of 4"))
        self.assertEqual(got["rows"], [])
        self.assertEqual(got["total"], 900)

    def test_remove_vacant_key_writes_nothing(self):
        case = self.case("writer", "remove 0x232c6b0: vacant key rows 1 of 4")
        self.assertEqual(self.harness.run(case)["rows"], [])

    def test_sink_gate_word(self):
        self.assertEqual(self.harness.run(self.case("sink", "perp: gate off")), {"path": "off"})
        self.assertEqual(self.harness.run(self.case("sink", "perp: gate low bit"))["path"], "record")

    def test_spot_outcome_text(self):
        got = self.harness.run(self.case("sink", "spot: outcome token side 1"))
        self.assertEqual(got["record"]["coin"], "#171")

    def test_perp_decimals_limit(self):
        self.assertEqual(self.harness.run(self.case("sink", "perp: perp decimals 7"))["path"], "panic decimals")

    def test_stream_without_block_time_drops(self):
        got = self.harness.run(self.case("buffer", "stream: no block"))
        self.assertEqual(got, {"path": "no block", "free": 1})

    def test_stream_flag_adds_40_ms(self):
        got = self.harness.run(self.case("buffer", "stream: flag plus 40 ms"))
        self.assertEqual(got["local"][2], tool.CLOCK[2] + 40000000)

    def test_hourly_path_text(self):
        got = self.harness.run(self.case("file", "file: next hour"))
        self.assertEqual(got["log"][0], ["open", "base/node_raw_book_diffs/hourly/D2460100/H3"])

    def test_daily_path_text(self):
        got = self.harness.run(self.case("file", "file: daily next date"))
        self.assertEqual(got["log"][0], ["open", "base/node_raw_book_diffs/D2460101"])

    def test_hour_panic_limit(self):
        self.assertEqual(self.harness.run(self.case("file", "file: seconds at the hour limit"))["path"], "panic hour")

    def test_json_line_for_remove(self):
        line = self.harness.run(self.case("line", "file: remove"))
        self.assertTrue(line.endswith('"raw_book_diff":"remove"}\n'))
        self.assertEqual(json.loads(line)["coin"], "\x40107")

    def test_json_line_for_update(self):
        doc = json.loads(self.harness.run(self.case("line", "file: update")))
        self.assertEqual(doc["raw_book_diff"], {"update": {"origSz": "2.5", "newSz": "0.125"}})
        self.assertEqual(doc["side"], "B")

    def test_batch_line_keeps_order(self):
        doc = json.loads(self.harness.run(self.case("line", "batch: 3 records")))
        self.assertEqual(len(doc["events"]), 3)
        self.assertEqual(doc["block_number"], 999)

    def test_whole_number_keeps_one_zero(self):
        doc = json.loads(self.harness.run(self.case("line", "file: whole numbers")))
        self.assertEqual(doc["px"], "40000.0")
        self.assertEqual(doc["raw_book_diff"]["update"]["newSz"], "100.0")


class Controls(Base):
    def test_flipped_gate_is_caught(self):
        self.poke(0x4855363 + 6 + 1, 0x00)
        tool.mutate_patch  # the helper below is what the mutation pass uses
        self.harness.machine.patches = tool.mutate_patch(self.image, 0x485536A, 0, "branch")
        self.harness.machine.patches = {0x485536A + 1: tool.code(self.image, 0x485536A + 1, 1)[0] ^ 1}
        self.harness.machine.cache.clear()
        self.assertTrue(tool.compare_run(self.harness, self.case("sink", "perp: gate off")))

    def test_changed_row_tag_is_caught(self):
        at = tool.code(self.image, 0x49E4F7B, 9)
        self.assertEqual(at[:5], b"\x48\xc7\x44\x24\x10")
        self.harness.machine.patches = {0x49E4F7B + 5: 3}
        self.harness.machine.cache.clear()
        self.assertTrue(tool.compare_run(self.harness, self.case("writer", "update 0x49e4f20: smaller rows 1 of 4")))

    def test_wrong_expectation_is_caught(self):
        case = self.case("writer", "new 0x42e8710: plain rows 1 of 4")
        wrong = dict(case.world, total=case.world["total"] + 1)
        got = self.harness.run(case)
        self.assertNotEqual(got, tool.spec_writer(wrong))

    def test_changed_float_digits_are_caught(self):
        keep = tool.float_text
        tool.float_text = lambda value: ("%.9f" % value)
        try:
            self.assertTrue(tool.compare_run(self.harness, self.case("line", "file: rounding")))
        finally:
            tool.float_text = keep

    def test_stub_refuses_wrong_template(self):
        machine = self.harness.machine
        self.harness.fresh()
        machine.regs = [0] * 16
        machine.regs[tool.RSI] = 0x1234
        with self.assertRaisesRegex(tool.Halt, "format template"):
            self.harness.on_format(machine)

    def test_mutation_targets_cover_all_three_kinds(self):
        kinds = set()
        for _, _, rows in tool.mutated_groups(self.image)[:3]:
            kinds |= {kind for _, _, kind in tool.mutation_targets(self.image, rows)}
        self.assertTrue({"branch", "offset", "immediate"} <= kinds)


class Packet(unittest.TestCase):
    def test_manifest(self):
        lines = (FOLDER / "MANIFEST.sha256").read_text().splitlines()
        names = sorted(path.name for path in FOLDER.iterdir() if path.name != "MANIFEST.sha256")
        self.assertEqual(sorted(line.split("  ")[1] for line in lines), names)
        for line in lines:
            digest, name = line.split("  ")
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest)

    def test_evidence_numbers(self):
        doc = json.loads((FOLDER / "evidence.json").read_text())
        rows = [line.split("\t") for line in (FOLDER / "mutations.tsv").read_text().splitlines()[1:]]
        self.assertEqual(doc["mismatches"], 0)
        self.assertEqual(doc["cases"]["total"], len(tool.all_cases()))
        self.assertEqual(sum(1 for row in rows if row[3] == "killed"), doc["mutations"]["killed"])
        self.assertTrue(all(row[5] for row in rows if row[3] != "killed"))
        self.assertEqual(len((FOLDER / "row_writers.tsv").read_text().splitlines()), 13)

    def test_case_listing_matches(self):
        self.assertEqual(len((FOLDER / "cases.tsv").read_text().splitlines()) - 1, len(tool.all_cases()))


if __name__ == "__main__":
    unittest.main()
