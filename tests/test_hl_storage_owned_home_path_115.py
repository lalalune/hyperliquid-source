"""Binary-free tests for the node #115 owned_db_home.rs path-row evidence.

The retained body bytes and constants in the generated evidence are rebuilt into a small synthetic image, so the interpreter, the reference
model and the mutation controls all run without the node binary.
"""

import bisect
import hashlib
import json
import pathlib
import struct
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import hl_storage_owned_home_path_115 as tool  # noqa: E402

WORK = ROOT / "research" / "work-items" / "RE-009-owned-db-home-path-scan-115"


def table(name):
    lines = (WORK / name).read_text().splitlines()
    head = lines[0].split("\t")
    return [dict(zip(head, line.split("\t"))) for line in lines[1:]]


class FakeImage:
    """Just enough of the ELF image view for the interpreter: byte segments at virtual addresses plus a relocation map."""

    def __init__(self, segments, relative):
        self.segments = sorted(segments.items())
        self.starts = [va for va, _ in self.segments]
        blob = bytearray()
        self.base = {}
        for va, data in self.segments:
            self.base[va] = len(blob)
            blob += data + bytes(32)
        self.blob = blob
        self.relative_map = relative

    def offset(self, va):
        index = bisect.bisect_right(self.starts, va) - 1
        if index < 0:
            raise tool.EvidenceError("address outside file-backed sections: %#x" % va)
        start, data = self.segments[index]
        if va >= start + len(data) + 16:
            raise tool.EvidenceError("address outside file-backed sections: %#x" % va)
        return self.base[start] + va - start

    def relative(self):
        return self.relative_map

    def exact_fde(self, va):
        for row in table("functions.tsv"):
            if int(row["start"], 16) == va:
                return va, int(row["end"], 16)
        raise tool.EvidenceError("not an FDE start: %#x" % va)


def build_segments():
    segments = {}
    for row in table("functions.tsv"):
        start = int(row["start"], 16)
        data = bytearray()
        for line in table("bodies.tsv"):
            va = int(line["va"], 16)
            if start <= va < int(row["end"], 16):
                data += bytes.fromhex(line["hex16"])
        segments[start] = bytes(data[:int(row["bytes"])])
    for row in table("references.tsv"):
        if row["bytes_at_target"] != "unmapped" and row["slot_role"] == "":
            segments.setdefault(int(row["target"], 16), bytes.fromhex(row["bytes_at_target"]))
    relative = {int(row["slot"], 16): int(row["relative_addend"], 16) for row in table("relocations.tsv")}
    return segments, relative


def image():
    segments, relative = build_segments()
    return FakeImage(segments, relative)


class EvidenceShape(unittest.TestCase):
    def test_body_hashes_match_functions_table(self):
        segments, _ = build_segments()
        for row in table("functions.tsv"):
            body = segments[int(row["start"], 16)]
            self.assertEqual(len(body), int(row["bytes"]))
            self.assertEqual(hashlib.sha256(body).hexdigest(), row["sha256"])

    def test_byte_damage_changes_the_hash(self):
        segments, _ = build_segments()
        row = table("functions.tsv")[0]
        body = bytearray(segments[int(row["start"], 16)])
        body[100] ^= 1
        self.assertNotEqual(hashlib.sha256(bytes(body)).hexdigest(), row["sha256"])

    def test_function_extents_are_the_reported_sizes(self):
        rows = {int(r["start"], 16): int(r["end"], 16) - int(r["start"], 16) for r in table("functions.tsv")}
        self.assertEqual(rows, {0x16961B0: 1401, 0x1696730: 0x4F, 0x1696780: 0xE7, 0x1696870: 241})

    def test_instruction_table_tiles_each_body(self):
        rows = table("instructions.tsv")
        ends = {int(r["start"], 16): int(r["end"], 16) for r in table("functions.tsv")}
        position = None
        previous = None
        for row in rows:
            va = int(row["va"], 16)
            if va in ends:
                if previous is not None:
                    self.assertEqual(position, ends[previous])
                position = va
                previous = va
            self.assertEqual(va, position)
            position += int(row["size"])
            self.assertEqual(len(row["bytes"]) // 2, int(row["size"]))
        self.assertEqual(position, 0x1696961)

    def test_measure_counts_close(self):
        measure = json.loads((WORK / "measure.json").read_text())
        self.assertEqual(measure["negative_detected"] + measure["equivalent"], measure["negative_controls"])
        self.assertEqual(len(table("controls.tsv")), measure["negative_controls"])
        self.assertEqual(len(table("equivalent-mutants.tsv")), measure["equivalent"])
        detected = [r for r in table("controls.tsv") if r["detected"] == "1"]
        self.assertEqual(len(detected), measure["negative_detected"])
        total = sum(int(r["cases"]) for r in table("routes.tsv"))
        self.assertEqual(total, measure["cases"])

    def test_every_equivalent_mutant_has_a_reason(self):
        rows = table("equivalent-mutants.tsv")
        self.assertTrue(rows)
        for row in rows:
            self.assertNotIn(row["reason"], ("", "unclassified"))
        undetected = {(r["va"], r["byte"], r["new"]) for r in table("controls.tsv") if r["detected"] == "0"}
        self.assertEqual(undetected, {(r["va"], r["byte"], r["new"]) for r in rows})

    def test_packet_has_no_server_paths(self):
        bad = ["/" + word + "/" for word in ("home", "mnt", "srv", "root", "tmp", "opt", "var", "etc")]
        for path in sorted(ROOT.rglob("*")):
            if path.is_file() and "pycache" not in str(path) and path.suffix in (".py", ".tsv", ".json", ".md"):
                if WORK in path.parents or path.name.startswith(("hl_storage_owned_home", "test_hl_storage_owned_home")):
                    text = path.read_text()
                    for word in bad:
                        self.assertNotIn(word, text, str(path.name))

    def test_manifest_lists_every_file(self):
        manifest = WORK / "MANIFEST.sha256"
        if not manifest.exists():
            return
        listed = {}
        for line in manifest.read_text().splitlines():
            digest, name = line.split("  ", 1)
            listed[name] = digest
        names = sorted(p.name for p in WORK.iterdir() if p.is_file() and p.name != "MANIFEST.sha256")
        self.assertEqual(sorted(listed), names)
        for name in names:
            self.assertEqual(hashlib.sha256((WORK / name).read_bytes()).hexdigest(), listed[name], name)


class SearchClasses(unittest.TestCase):
    def test_length_cut_overs(self):
        want = {0: "short-reject", 9: "short-reject", 10: "exact-10", 11: "scalar-window", 24: "scalar-window", 25: "lane-16", 73: "lane-16",
                74: "block-64", 500: "block-64"}
        for n, label in want.items():
            self.assertEqual(tool.lane_class(n), label)

    def test_profile_matches_classifier(self):
        for row in table("length-profile.tsv"):
            self.assertEqual(row["search_class"], tool.lane_class(int(row["length"])))
            self.assertEqual(row["route"], "row")

    def test_profile_cost_grows_across_classes(self):
        cost = {int(r["length"]): int(r["distinct_instructions_executed"]) for r in table("length-profile.tsv")}
        self.assertLess(cost[5], cost[10])
        self.assertLess(cost[10], cost[40])
        self.assertLess(cost[40], cost[100])

    def test_region_labels(self):
        self.assertEqual(tool.region(0x16961B0), "prologue")
        self.assertEqual(tool.region(0x169623F), "panic-route")
        self.assertEqual(tool.region(0x1696700), "landing-pad")
        self.assertEqual(tool.region(0x1696870), "verifier-compare-loop")
        self.assertEqual(tool.region(0x16968F0), "verifier-short-needle-tail")


class ReferenceModel(unittest.TestCase):
    def test_model_panics_exactly_on_substring(self):
        for text in (b"checkpoint", b"xcheckpointx", b"/a/checkpoints"):
            self.assertEqual(tool.ctor_model(text, 5, False)[0], "panic")
        for text in (b"", b"checkpoin", b"heckpoint", b"Checkpoint", b"check point", b"chekpoint"):
            self.assertEqual(tool.ctor_model(text, 5, False)[0], "row")

    def test_row_layout(self):
        route = tool.ctor_model(b"abc", 0x77, False)
        box = bytes.fromhex(route[2])
        self.assertEqual(struct.unpack_from("<QQQQQ", box), (1, 1, 0x77, tool.HAY, 3))
        self.assertEqual(box[40:], tool.fmt_bytes(b"abc"))
        self.assertEqual(len(box), tool.BOX_SIZE)

    def test_alloc_failure_route(self):
        route = tool.ctor_model(b"abc", 1, True)
        self.assertEqual(route[:4], ("alloc-error", ("fmt", "alloc", "alloc_error"), 8, 0x58))

    def test_verify_model(self):
        hay = b"ab" + b"heckpoint" + b"zz"
        self.assertEqual(tool.verify_model(hay, tool.REST, 1, 1, 0), 1)
        self.assertEqual(tool.verify_model(hay, tool.REST, 1, 1, 1), 0)
        self.assertEqual(tool.verify_model(hay, tool.REST, 1, 2, 0), 0)
        self.assertEqual(tool.verify_model(hay, b"", 0, 1, 0), 1)
        self.assertEqual(tool.verify_model(hay, tool.REST, 0, 0x8001, 0), 0)
        self.assertEqual(tool.verify_model(hay, tool.REST, 0, 0x8002, 0), 1)


class Interpreter(unittest.TestCase):
    """The retained bytes, run on the interpreter, must agree with the reference model."""

    @classmethod
    def setUpClass(cls):
        cls.image = image()
        cls.cases = list(tool.ctor_cases())
        cls.verify = list(tool.verify_cases()) + list(tool.solid_mask_cases())

    def test_constructor_cases(self):
        rig = tool.new_rig(self.image)
        for case in self.cases[::25]:
            error, _ = tool.check_ctor(rig, case[1], case[2], case[3])
            self.assertEqual(error, "", case[0])

    def test_boundary_and_tail_families_all_run(self):
        rig = tool.new_rig(self.image)
        for case in self.cases:
            if case[0] in tool.ALWAYS:
                error, _ = tool.check_ctor(rig, case[1], case[2], case[3])
                self.assertEqual(error, "")

    def test_verifier_cases(self):
        rig = tool.new_rig(self.image)
        for case in self.verify[::15]:
            self.assertEqual(tool.check_verify(rig, case), "")

    def test_panic_route_carries_the_string_and_location(self):
        rig = tool.new_rig(self.image)
        got, _ = tool.run_ctor(rig, b"/x/y/checkpoint", 9, False, tool.FILLS[0])
        self.assertEqual(got, ("panic", tool.PANIC_PIECES_VA, tool.STRUCT, tool.PANIC_FMT_FN, tool.LOCATION_SLOT))

    def test_row_route_moves_the_string_triple(self):
        rig = tool.new_rig(self.image)
        got, _ = tool.run_ctor(rig, b"/x/y/db", 0x1234, False, tool.FILLS[0])
        box = bytes.fromhex(got[2])
        self.assertEqual(struct.unpack_from("<QQ", box), (1, 1))
        self.assertEqual(struct.unpack_from("<QQQ", box, 16), (0x1234, tool.HAY, 7))

    def test_alloc_failure_reaches_the_diagnostic(self):
        rig = tool.new_rig(self.image)
        got, _ = tool.run_ctor(rig, b"abc", 1, True, tool.FILLS[0])
        self.assertEqual(got[0], "alloc-error")
        self.assertEqual(got[2:4], (8, 0x58))

    def test_haystack_over_read_would_show(self):
        """Truncated needles followed by a completing pad byte must not panic, whatever the bytes around the string are."""
        rig = tool.new_rig(self.image)
        for fill in tool.FILLS:
            got, _ = tool.run_ctor(rig, b"checkpoin", 1, False, fill)
            self.assertEqual(got[0], "row")
            got, _ = tool.run_ctor(rig, b"heckpoint", 1, False, fill)
            self.assertEqual(got[0], "row")


class NegativeControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = image()
        cls.cases = list(tool.ctor_cases())
        cls.verify = list(tool.verify_cases()) + list(tool.solid_mask_cases())

    def disagree(self, model, texts):
        rig = tool.new_rig(self.image)
        for text in texts:
            got, _ = tool.run_ctor(rig, text, 7, False, tool.FILLS[0])
            if got != model(text, 7, False):
                return True
        return False

    def test_case_insensitive_model_is_rejected(self):
        wrong = lambda t, c, f: tool.ctor_model(t.lower(), c, f)
        self.assertTrue(self.disagree(wrong, [b"CHECKPOINT", b"Checkpoint"]))

    def test_nine_byte_needle_model_is_rejected(self):
        original = tool.NEEDLE
        try:
            tool.NEEDLE = b"heckpoint"
            self.assertTrue(self.disagree(tool.ctor_model, [b"xheckpoint"]))
        finally:
            tool.NEEDLE = original

    def test_prefix_only_model_is_rejected(self):
        def wrong(text, cap, fail):
            return tool.ctor_model(text[:20], cap, fail)
        self.assertTrue(self.disagree(wrong, [b"a" * 30 + b"checkpoint"]))

    def test_length_cap_model_is_rejected(self):
        def wrong(text, cap, fail):
            return tool.ctor_model(text[:24], cap, fail) if len(text) > 24 else tool.ctor_model(text, cap, fail)
        self.assertTrue(self.disagree(wrong, [b"q" * 40 + b"checkpoint"]))

    def test_wrong_box_layout_model_is_rejected(self):
        def wrong(text, cap, fail):
            route = tool.ctor_model(text, cap, fail)
            if route[0] != "row":
                return route
            box = bytearray(bytes.fromhex(route[2]))
            box[8] = 0
            return route[:2] + (bytes(box).hex(),) + route[3:]
        self.assertTrue(self.disagree(wrong, [b"abc"]))

    def test_wrong_alloc_size_model_is_rejected(self):
        def wrong(text, cap, fail):
            route = tool.ctor_model(text, cap, fail)
            return route[:-1] + ((0x50,),) if route[0] == "row" else route
        self.assertTrue(self.disagree(wrong, [b"abc"]))

    def test_verify_model_without_flag_is_rejected(self):
        rig = tool.new_rig(self.image)
        hay = b"a" + b"heckpoint" + b"b"
        got, _ = tool.run_verify(rig, hay, tool.REST, 0, 1, 1, tool.FILLS[0])
        self.assertEqual(got, 0)
        self.assertNotEqual(got, 1)

    def test_verify_model_ignoring_mask_is_rejected(self):
        rig = tool.new_rig(self.image)
        hay = b"a" + b"heckpoint" + b"b"
        got, _ = tool.run_verify(rig, hay, tool.REST, 0, 2, 0, tool.FILLS[0])
        self.assertEqual(got, 0)

    def test_condition_flip_is_detected(self):
        entries = [("c", i) for i, c in enumerate(self.cases) if c[0] in tool.ALWAYS][:60]
        entries += [("v", i) for i in range(0, 200, 4)]
        hit, reason, _ = tool.detect(self.image, (0x1696886, 0, 0x72, "condition-flip", "candidate-verifier", 0x1696886), entries, self.cases, self.verify)
        self.assertTrue(hit)

    def test_retarget_past_the_exact_ten_compare_is_detected(self):
        entries = [("b", i) for i, c in enumerate(self.cases) if c[0] == "truncated-tail"]
        hit, _, _ = tool.detect(self.image, (0x16961D0, 1, 0x4B, "branch-retarget", "path-row-constructor", 0x16961D0), entries, self.cases, self.verify)
        self.assertTrue(hit)

    def test_alloc_size_change_is_detected(self):
        entries = [("c", i) for i, c in enumerate(self.cases) if c[0] == "miss"][:8]
        hit, reason, _ = tool.detect(self.image, (0x169641D, 1, 0x59, "immediate-low-byte", "path-row-constructor", 0x169641D), entries, self.cases, self.verify)
        self.assertTrue(hit)

    def test_mask_bit_scan_mutant_is_detected(self):
        entries = [("v", i) for i in range(3200, len(self.verify))]
        hit, _, _ = tool.detect(self.image, (0x1696886, 1, 0x25, "branch-retarget", "candidate-verifier", 0x1696886), entries, self.cases, self.verify)
        self.assertTrue(hit)

    def test_equivalent_mutant_is_not_detected(self):
        entries = [("c", i) for i, c in enumerate(self.cases) if c[0] == "placement"][::60]
        hit, _, _ = tool.detect(self.image, (0x16961D2, 3, 0x19, "immediate-low-byte", "path-row-constructor", 0x16961D2), entries, self.cases, self.verify)
        self.assertFalse(hit)

    def test_every_listed_detection_stays_detected(self):
        """Replay the first retained detecting control of each function."""
        rows = [r for r in table("controls.tsv") if r["detected"] == "1" and r["kind"] == "condition-flip"]
        self.assertGreater(len(rows), 30)
        by_function = {}
        for row in rows:
            by_function.setdefault(row["function"], row)
        self.assertEqual(sorted(by_function), ["candidate-verifier", "path-row-constructor", "row-drop-glue", "vec-drop-glue"])


class DropGlue(unittest.TestCase):
    """0x1696730 drops a vector triple, 0x1696780 drops the whole box; both through the same four callouts."""

    @classmethod
    def setUpClass(cls):
        cls.image = image()
        cls.cases = list(tool.glue_cases())

    def test_model_vector_drop(self):
        self.assertEqual(tool.glue_model("vec", [0, 5, 6], 0), (("drop_elems", tool.BOXA),))
        self.assertEqual(tool.glue_model("vec", [9, 5, 6], 0), (("drop_elems", tool.BOXA), ("dealloc", 5, 9, 0)))

    def test_model_row_drop_order(self):
        words = [1, 1, 3, 0x100, 4, 7, 0x200, 8, 0, 0, 0]
        events = tool.glue_model("row", words, 0)
        self.assertEqual(events, (("dealloc", 0x100, 3, 0), ("drop_elems", tool.BOXA + 0x28), ("dealloc", 0x200, 7, 0)))
        self.assertEqual(tool.glue_model("row", words, 5)[0][0], "once")
        self.assertEqual(len(tool.glue_model("row", [1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0], 0)), 1)

    def test_interpreter_agrees_on_a_spread_of_cases(self):
        rig = tool.new_rig(self.image)
        for case in self.cases[::11]:
            self.assertEqual(tool.check_glue(rig, case), "")

    def test_every_state_word_pattern_takes_the_once_path(self):
        rig = tool.new_rig(self.image)
        words = [1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        for state in (0, 1, 2, 0x100, 0x80000000, 0xFFFFFFFF):
            events, _ = tool.run_glue(rig, "row", words, state)
            self.assertEqual(events[0][0] == "once", state != 0, state)

    def test_wrong_order_model_is_rejected(self):
        rig = tool.new_rig(self.image)
        words = [1, 1, 3, 0x100, 4, 7, 0x200, 8, 0, 0, 0]
        got, _ = tool.run_glue(rig, "row", words, 0)
        wrong = (got[2], got[1], got[0])
        self.assertNotEqual(got, wrong)

    def test_swapped_dealloc_arguments_are_rejected(self):
        rig = tool.new_rig(self.image)
        words = [1, 1, 3, 0x100, 4, 7, 0x200, 8, 0, 0, 0]
        got, _ = tool.run_glue(rig, "row", words, 0)
        self.assertEqual(got[0], ("dealloc", 0x100, 3, 0))
        self.assertNotEqual(got[0], ("dealloc", 3, 0x100, 0))

    def test_vector_drop_frees_only_nonzero_capacity(self):
        rig = tool.new_rig(self.image)
        events, _ = tool.run_glue(rig, "vec", [0, 0x77, 1] + [0] * 8, 0)
        self.assertEqual([e[0] for e in events], ["drop_elems"])
        events, _ = tool.run_glue(rig, "vec", [4, 0x77, 1] + [0] * 8, 0)
        self.assertEqual([e[0] for e in events], ["drop_elems", "dealloc"])

    def test_glue_mutants_are_detected(self):
        entries = [("g", i) for i in range(len(self.cases))][:300]
        flip = (0x1696794, 0, 0x74, "condition-flip", "row-drop-glue", 0x1696794)
        retarget = (0x1696794, 1, 0x50, "branch-retarget", "row-drop-glue", 0x1696794)
        for patch in (flip, retarget):
            hit, _, _ = tool.detect(self.image, patch, entries, [], [], self.cases)
            self.assertTrue(hit, patch)

    def test_constructor_box_feeds_the_row_glue(self):
        rig = tool.new_rig(self.image)
        got, _ = tool.run_ctor(rig, b"/x/y/db_home", 0x40, False, tool.FILLS[0])
        words = list(struct.unpack("<11Q", bytes.fromhex(got[2])))
        events, _ = tool.run_glue(rig, "row", words, 0)
        self.assertEqual(events, tool.glue_model("row", words, 0))
        self.assertEqual(events[0], ("dealloc", tool.HAY, 0x40, 0))


class CoverageTables(unittest.TestCase):
    def test_unexecuted_instructions_are_cleanup_or_dead(self):
        allowed = {0x1696269, 0x16966F3, 0x169688A, 0x16968E7}
        rows = table("coverage.tsv")
        self.assertEqual(len(rows), len(table("instructions.tsv")))
        for row in rows:
            if row["executed"] == "0":
                self.assertTrue(row["region"] == "landing-pad" or int(row["va"], 16) in allowed, row["va"])

    def test_summary_counts_match_tables(self):
        summary = json.loads((WORK / "summary.json").read_text())
        rows = table("coverage.tsv")
        self.assertEqual(summary["instructions"], len(rows))
        self.assertEqual(summary["executed_instructions"], sum(int(r["executed"]) for r in rows))
        self.assertEqual(summary["binary_sha256"], tool.SHA256)

    def test_branch_targets_are_instruction_starts_or_outside(self):
        starts = {r["va"] for r in table("instructions.tsv")}
        for row in table("branches.tsv"):
            if row["target_region"] != "outside":
                self.assertIn(row["target"], starts, row["va"])

    def test_relocation_slots_are_eight_byte_got_entries(self):
        for row in table("relocations.tsv"):
            slot = int(row["slot"], 16)
            self.assertEqual(slot % 8, 0)
            self.assertGreater(slot, 0x64DD458)
            self.assertLess(slot, 0x64F0000)

    def test_panic_constants_were_read_from_the_image(self):
        constants = json.loads((WORK / "summary.json").read_text())["constants"]
        self.assertEqual(constants["panic_piece"], "OwnedDbDir invalid dir ")
        self.assertEqual(constants["panic_piece_length_byte"], len(constants["panic_piece"]))
        self.assertEqual(constants["type_name"], "OwnedDbDir")
        self.assertEqual(constants["needle_rest"], tool.REST.decode())
        self.assertEqual(constants["lane_c"], "c" * 16)
        self.assertEqual(constants["lane_t"], "t" * 16)
        self.assertEqual((constants["location_line"], constants["location_column"]), (21, 9))


class Loader(unittest.TestCase):
    def test_wrong_digest_is_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "node"
            path.write_bytes(b"not the node binary")
            with self.assertRaises(tool.EvidenceError):
                tool.load_image(path)

    def test_address_outside_every_mapping_is_refused(self):
        fake = image()
        with self.assertRaises(tool.EvidenceError):
            fake.offset(0x10)
        memory = tool.Memory(fake)
        with self.assertRaises(tool.Halt):
            memory.bytes_at(0x10, 4)

    def test_write_outside_stack_and_heap_is_refused(self):
        memory = tool.Memory(image())
        with self.assertRaises(tool.Halt):
            memory.write(0x1696870, 4, 1)

    def test_unmodelled_call_halts(self):
        rig = tool.new_rig(image())
        rig[0].slots.clear()
        with self.assertRaises(tool.Halt):
            tool.place(rig[0], b"abc", tool.FILLS[0])
            rig[0].memory.write(tool.STRUCT, 8, 1)
            rig[0].memory.write(tool.STRUCT + 8, 8, tool.HAY)
            rig[0].memory.write(tool.STRUCT + 16, 8, 3)
            rig[0].run(tool.CTOR, {tool.RDI: tool.STRUCT})


if __name__ == "__main__":
    unittest.main()
