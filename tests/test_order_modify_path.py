"""Tests for tools/order_modify_path.py: the node #94 modify path, run from ELF bytes with stubbed edges."""

import hashlib
import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import order_modify_path as tool  # noqa: E402

FOLDER = ROOT / "research" / "work-items" / "RE-006-order-modify-path-94"


def load_shared(cls):
    cls.image = tool.load_image()
    cls.harness = tool.Harness(cls.image)
    cls.cases = tool.all_cases()
    cls.by_label = {case.label: case for case in cls.cases}
    cls.static = tool.analyse(cls.image, full=False)


class Base(unittest.TestCase):
    setUpClass = classmethod(load_shared)

    def run_case(self, label):
        return self.harness.run(self.by_label[label])

    def names(self, label):
        return [row[0] for row in self.run_case(label)["log"]]

    def with_patch(self, patches):
        machine = self.harness.machine
        machine.patches = dict(patches)
        machine.cache = {}
        self.addCleanup(self.clear)

    def clear(self):
        self.harness.machine.patches = {}
        self.harness.machine.cache = {}


class Identity(Base):
    def test_binary_digest(self):
        self.assertEqual(hashlib.sha256(bytes(self.image.blob)).hexdigest(), tool.SHA256)

    def test_wrong_digest_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(expected="0" * 64)

    def test_every_function_is_an_exact_fde(self):
        for row in self.static["functions"]:
            self.assertEqual(self.image.exact_fde(int(row["start"], 16))[1], int(row["end"], 16))

    def test_address_inside_a_function_refused(self):
        with self.assertRaises(tool.EvidenceError):
            self.image.exact_fde(0x271C491)

    def test_address_out_of_range_refused(self):
        with self.assertRaises(tool.EvidenceError):
            self.image.offset(0x7FFFFFFFFFFF)


class Agreement(Base):
    def test_no_mismatch_in_any_case(self):
        self.assertEqual(self.static["first_mismatch"], "")
        self.assertEqual(self.static["mismatches"], 0)
        self.assertGreater(len(self.cases), 400)

    def test_every_outcome_class_is_reached(self):
        wanted = {"status 0x38", "status 0x39", "status 0x3a", "status 0x186", "status 0xf9", "status 0x60", "panic 0x56e9b28", "panic 0x56bb478", "panic 0x5742338"}
        self.assertLessEqual(wanted, set(self.static["outcomes"]))

    def test_all_three_bodies_run(self):
        for row in self.static["functions"]:
            if " body" in row["role"]:
                self.assertGreater(row["instructions_stepped"], row["instructions"] * 3 // 4, row["role"])


class Path(Base):
    def test_check_runs_before_the_lookup(self):
        names = self.names("first: perp client id found")
        self.assertLess(names.index("check"), names.index("lookup"))

    def test_failed_check_leaves_old_order_and_skips_hook(self):
        found = self.run_case("first: perp check error")
        self.assertEqual(found["result"]["tag"], 0x55)
        self.assertEqual([row[0] for row in found["log"]], ["resolve", "check"])
        self.assertIn(501, found["orders"])

    def test_client_id_key_reaches_the_map(self):
        found = self.run_case("second: spot client id found")
        self.assertEqual(found["result"]["tag"], tool.TAG_OK)
        self.assertIn(900, found["orders"])
        self.assertNotIn(501, found["orders"])

    def test_map_miss_is_status_38_with_hook(self):
        found = self.run_case("third: perp client id unknown")
        self.assertEqual(found["result"], {"tag": 0x38})
        self.assertEqual(found["log"][-1], ["hook", 1])

    def test_key_byte_3_differs_between_copies(self):
        self.assertIn("lookup", self.names("first: perp rare key byte 3"))
        self.assertNotIn("lookup", self.names("second: perp rare key byte 3"))

    def test_kind_2_rejects_only_with_a_parent(self):
        self.assertEqual(self.run_case("first: perp parent and kind 2")["result"], {"tag": 0x39})
        self.assertEqual(self.run_case("first: perp parent and kind 1")["result"]["tag"], tool.TAG_OK)
        self.assertEqual(self.run_case("first: perp no parent and kind 2")["result"]["tag"], tool.TAG_OK)

    def test_order_of_a_replacement(self):
        names = self.names("first: perp plain replace")
        self.assertEqual(names, ["resolve", "check", "remove", "flush", "insert", "names", "done", "tail", "hook"])

    def test_reason_is_two(self):
        found = self.run_case("first: perp plain replace")
        self.assertEqual(found["log"][2], ["remove", "perp", ["perp", 2, 1], 501, 2])

    def test_all_links_move(self):
        for copy in ("first", "second", "third"):
            found = self.run_case(copy + ": perp parent, peer and kids")
            orders = found["orders"]
            self.assertEqual(orders[900], [400, 502, [601, 602]], copy)
            self.assertEqual(orders[400][2], [501, 900], copy)
            self.assertEqual(orders[502][1], 900, copy)
            self.assertEqual(orders[601][0], 900, copy)

    def test_gone_kid_is_dropped(self):
        self.assertEqual(self.run_case("first: spot middle kid gone")["orders"][900][2], [601, 603, 604])

    def test_gone_parent_still_named(self):
        self.assertEqual(self.run_case("second: perp parent gone")["orders"][900][0], 400)

    def test_gone_peer_not_named(self):
        self.assertIsNone(self.run_case("first: perp peer gone")["orders"][900][1])

    def test_no_rest_changes_no_link(self):
        found = self.run_case("first: perp replace does not rest, kids stay")
        self.assertEqual(found["orders"][601][0], 501)
        self.assertEqual(found["orders"][502][1], 501)

    def test_failure_cancels_kids_and_leaves_old_order_gone(self):
        found = self.run_case("second: spot insert failed with kids and rows")
        self.assertEqual([row[3] for row in found["log"] if row[0] == "child"], [601, 602, 603])
        self.assertEqual(found["log"][-2], ["flush", "spot", None, 3])
        self.assertNotIn(501, found["orders"])

    def test_text_error_becomes_3a(self):
        found = self.run_case("third: perp insert text error")
        self.assertEqual(found["result"], {"tag": 0x3A, "text": tool.text_words()})

    def test_neighbour_of_text_error_passes(self):
        self.assertEqual(self.run_case("first: perp insert neighbour of the text error")["result"]["tag"], 0xC5)

    def test_insert_context_carries_the_old_value(self):
        row = [row for row in self.run_case("first: spot extra bytes pass to the insert")["log"] if row[0] == "insert"][0]
        self.assertEqual(row[2:], [1, tool.ramp(32, 0xD1).hex()])

    def test_wrapper_clears_a_stale_client_id_tag(self):
        found = self.run_case("first: single tag 2 counts as none")
        self.assertEqual(bytes.fromhex(found["log"][0][2])[0x24], 0)

    def test_batch_keeps_entry_order(self):
        found = self.run_case("second: batch two")
        self.assertEqual(found["count"], 2)
        self.assertEqual(found["rows"][1], tool.body_output(1, tool.TAG_OK + 1).hex())


class Controls(Base):
    """A real instruction change must show as a mismatch."""

    def flipped(self, site, offset, mask, label):
        data = tool.code(self.image, site, 16)
        self.with_patch({site + offset: data[offset] ^ mask})
        return tool.compare_run(self.harness, self.by_label[label])

    def test_old_order_missing_branch(self):
        self.assertTrue(self.flipped(0x271CAE3, 0, 1, "first: perp old oid absent"))

    def test_byte_b_compare(self):
        self.assertTrue(self.flipped(0x271CBD2, 0, 1, "first: perp byte b differs"))

    def test_kind_immediate(self):
        self.assertTrue(self.flipped(0x271CBE2, 7, 1, "first: perp parent and kind 2"))

    def test_reason_immediate(self):
        self.assertTrue(self.flipped(0x271CC9B, 2, 1, "first: perp plain replace"))

    def test_text_error_word(self):
        self.assertTrue(self.flipped(0x271D71C, 5, 1, "first: perp insert text error"))

    def test_rest_bit_test(self):
        self.assertTrue(self.flipped(0x271CE68, 1, 1, "first: perp parent, peer and kids"))

    def test_harness_sees_a_wrong_specification(self):
        case = self.by_label["first: perp parent, peer and kids"]
        wanted = tool.spec_run(case)
        wanted["orders"][900][1] = 503
        self.assertNotEqual(self.harness.run(case), wanted)

    def test_leak_is_visible(self):
        """Patching the free of the kid list to a skip must show as a leak or a difference."""
        self.assertTrue(self.flipped(0x271D9A5, 0, 1, "first: perp replace does not rest, kids stay"))


class Static(Base):
    def test_status_texts(self):
        tags = {row["tag"]: row["text"] for row in self.static["tags"]}
        self.assertEqual(tags["0x38"], "Cannot modify canceled or filled order")
        self.assertEqual(tags["0x39"], "Attempted to modify to invalid new order")
        self.assertEqual(tags["0x3a"], "Error placing new order during modify: <String>")
        self.assertEqual(tags["0xf9"], "Spot disabled")

    def test_template_address_is_checked(self):
        with self.assertRaises(tool.EvidenceError):
            tool.arm_template(self.image, tool.TAG_TEXTS, tool.TAG_REPLACE, 0x22)

    def test_locations(self):
        rows = {row["location"]: (row["file"], row["line"]) for row in self.static["locations"]}
        self.assertEqual(rows["0x56e9b28"], ("l1/src/dex_registry/perp_dex.rs", 30))
        self.assertEqual(rows["0x56bb478"], ("l1/src/books.rs", 19))

    def test_second_and_third_differ_only_in_state_rows(self):
        by_pair = {(row["first"], row["second"]): row for row in self.static["copies"]}
        self.assertEqual(len(by_pair[("0x4d1c1c0", "0x4d1dff0")]["state_rows"]), 10)
        self.assertEqual(by_pair[("0x25182c0", "0x2517c10")]["state_rows"], [])

    def test_first_copy_has_another_size(self):
        row = self.static["pairs_of_other_size"][0]
        self.assertEqual((row["first_size"], row["second_size"]), (6987, 7715))

    def test_slot_targets(self):
        for slot, target in tool.SLOT_NAMES.items():
            self.assertEqual(tool.image_slot(self.image, slot), target)

    def test_slot_refused_when_absent(self):
        with self.assertRaises(tool.EvidenceError):
            tool.image_slot(self.image, 0x10)

    def test_callers_of_the_first_body(self):
        sites = [row for row in self.static["_sites"] if row[0] == 0x271C490]
        self.assertEqual([row[3] for row in sites], [0x22BE760, 0x24BE320])

    def test_two_lookup_sites_per_body(self):
        for copy in tool.COPIES:
            self.assertEqual(len([row for row in self.static["_sites"] if row[0] == tool.SLOT_LOOKUP and row[3] == copy.body]), 2)

    def test_render_is_stable(self):
        self.assertEqual(tool.render(self.static), tool.render(self.static))


class Evidence(unittest.TestCase):
    def test_manifest_lists_every_file(self):
        names = {path.name for path in FOLDER.iterdir()} - {"MANIFEST.sha256"}
        rows = dict(reversed(line.split("  ")) for line in (FOLDER / "MANIFEST.sha256").read_text().splitlines())
        self.assertEqual(set(rows), names)
        for name, digest in rows.items():
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest)

    def test_saved_evidence_agrees(self):
        doc = json.loads((FOLDER / "evidence.json").read_text())
        self.assertEqual(doc["mismatches"], 0)
        self.assertEqual(doc["target"]["sha256"], tool.SHA256)
        self.assertGreater(doc["mutations"]["killed"], 800)

    def test_every_open_mutant_has_a_reason(self):
        rows = [line.split("\t") for line in (FOLDER / "mutations.tsv").read_text().splitlines()[1:]]
        self.assertTrue(rows)
        for row in rows:
            if row[3] != "killed":
                self.assertTrue(row[5] and row[5] != "pending", row)

    def test_write_outputs_writes_ascii(self):
        with tempfile.TemporaryDirectory() as folder:
            tool.write_outputs(folder, {"a.txt": "x\n"})
            self.assertEqual(pathlib.Path(folder, "a.txt").read_bytes(), b"x\n")


if __name__ == "__main__":
    unittest.main()
