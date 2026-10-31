"""Tests for tools/cancel_item_path.py: the node #94 cancel path, run from ELF bytes with stubbed edges."""

import hashlib
import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import cancel_item_path as tool  # noqa: E402

FOLDER = ROOT / "research" / "work-items" / "RE-006-cancel-item-path-94"


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
            self.image.exact_fde(0x275A381)

    def test_address_out_of_range_refused(self):
        with self.assertRaises(tool.EvidenceError):
            self.image.offset(0x7FFFFFFFFFFF)


class Agreement(Base):
    def test_no_mismatch_in_any_case(self):
        self.assertEqual(self.static["first_mismatch"], "")
        self.assertEqual(self.static["mismatches"], 0)
        self.assertGreater(len(self.cases), 400)

    def test_every_outcome_class_is_reached(self):
        wanted = {"core list too long", "core panic books", "core panic clearinghouses", "core panic perp_dex", "item status 0xc5", "item status 0x186", "lookup found", "lookup none"}
        self.assertLessEqual(wanted, set(self.static["outcomes"]))

    def test_all_three_copies_run(self):
        for row in self.static["functions"]:
            if "core" in row["role"] or "item" in row["role"] or "spot arm" in row["role"]:
                self.assertGreater(row["instructions_stepped"], 40, row["role"])


class Path(Base):
    def test_absent_oid_still_rows_and_flushes(self):
        found = self.run_case("first: oid absent, dex 0")
        names = [row[0] for row in found["log"]]
        self.assertLess(names.index("perp"), names.index("grow"))
        self.assertLess(names.index("grow"), names.index("flush"))
        self.assertLess(names.index("flush"), names.index("hook"))
        self.assertEqual(found["results"], [{"tag": 0xC5, "asset": 2}])
        self.assertEqual(found["done"], 7)

    def test_removed_oid_counts(self):
        found = self.run_case("first: oid present, dex 0")
        self.assertEqual(found["results"], [{"tag": 0x186}])
        self.assertEqual(found["done"], 8)
        self.assertEqual(found["count"], 41)

    def test_reason_is_two(self):
        found = self.run_case("first: oid present, dex 0")
        self.assertIn(["perp", ["perp", 0, 2], 501, 2], found["log"])

    def test_unknown_client_id_skips_the_removal(self):
        found = self.run_case("first: client id unknown")
        names = [row[0] for row in found["log"]]
        self.assertNotIn("perp", names)
        self.assertIn("flush", names)
        self.assertEqual(found["results"][0]["tag"], 0xC5)

    def test_spot_closed_stops_before_the_book(self):
        found = self.run_case("first: spot closed")
        names = [row[0] for row in found["log"]]
        self.assertEqual(found["results"], [{"tag": 0xF9}])
        for absent in ("spot", "flush", "hook"):
            self.assertNotIn(absent, names)
        self.assertEqual(found["done"], 7)

    def test_resolver_error_bytes_pass_through(self):
        found = self.run_case("first: resolver error")
        self.assertEqual(found["results"][0]["tag"], 0x141)
        self.assertEqual(found["results"][0]["payload"], tool.ramp(0x5E, 9).hex())

    def test_panic_after_the_flush_when_the_second_bound_fails(self):
        found = self.run_case("first: rare absent, dex at the second limit")
        self.assertEqual(found["panic"], "clearinghouses")
        self.assertEqual(found["log"][-1][0], "flush")

    def test_wire_edges(self):
        self.assertEqual([tool.wire_asset(value) for value in (0, 9999, 10000, 99899999, 99900000)], [0, 9999, 110000, 99999999, 0xFFFFFFFF])
        last = self.run_case("first: wire exact 99899999 absent")
        over = self.run_case("first: wire exact 99900000 absent")
        self.assertEqual(last["result"]["asset"], 99999999)
        self.assertEqual(over["result"]["asset"], 0xFFFFFFFF)

    def test_gate_mask(self):
        self.assertEqual([value for value in range(16) if tool.timed_by_gate(0, value) is None], [0, 2, 3, 4, 12, 14])
        self.assertIsNone(tool.timed_by_gate(2, 1))
        self.assertTrue(tool.timed_by_gate(0, 15))

    def test_sip_matches_the_real_hash(self):
        """A hit in the real probe needs our hash to agree with the real bytes."""
        self.assertTrue(self.run_case("first: lookup user found")["found"])
        self.assertEqual(self.run_case("first: lookup user found")["oid"], 0x1234567890)

    def test_lookup_finds_nothing_when_our_hash_is_wrong(self):
        """Negative control of the line above: a wrong control byte from the Python hash must make the real probe miss."""
        case = self.by_label["first: lookup user found"]
        real = tool.sip13
        self.addCleanup(setattr, tool, "sip13", real)
        tool.sip13 = lambda k0, k1, data: real(k0, k1, data) ^ (0x55 << 57)
        self.assertFalse(self.harness.run(case)["found"])


class Controls(Base):
    """A real instruction change must show as a mismatch."""

    def flipped(self, site, offset, mask, label):
        data = tool.code(self.image, site, 16)
        self.with_patch({site + offset: data[offset] ^ mask})
        return tool.compare_run(self.harness, self.by_label[label])

    def test_status_branch(self):
        self.assertIn("differs", self.flipped(0x275A778, 0, 1, "first: oid absent, dex 0"))

    def test_second_bound_branch(self):
        self.assertTrue(self.flipped(0x275A781, 1, 1, "first: rare absent, dex at the second limit"))

    def test_reason_immediate(self):
        self.assertTrue(self.flipped(0x275A6C9, 2, 1, "first: oid present, dex 0"))

    def test_spot_off_branch(self):
        self.assertTrue(self.flipped(0x275A460, 1, 1, "first: spot closed"))

    def test_map_offset(self):
        self.assertTrue(self.flipped(0x275A617, 3, 8, "first: client id found"))

    def test_row_word(self):
        self.assertTrue(self.flipped(0x275A6E3, 8, 1, "first: oid present, dex 0"))

    def test_wire_limit(self):
        self.assertTrue(self.flipped(0x275A7B8, 3, 1, "first: wire exact 99899999 absent"))

    def test_hook_flag(self):
        self.assertTrue(self.flipped(0x275A7F8, 1, 1, "first: oid absent, dex 0"))

    def test_lookup_items_test(self):
        self.assertTrue(self.flipped(0x342A528, 5, 1, "first: lookup rare inner map empty with a tempting row"))

    def test_harness_sees_a_wrong_specification(self):
        case = self.by_label["first: oid present, dex 0"]
        wanted = tool.spec_run(case)
        wanted["done"] += 1
        self.assertNotEqual(self.harness.run(case), wanted)


class Static(Base):
    def test_status_texts(self):
        tags = {row["tag"]: row["text"] for row in self.static["tags"]}
        self.assertEqual(tags["0xf9"], "Spot disabled")
        self.assertEqual(tags["0x143"], "Invalid input length")
        self.assertTrue(tags["0xc5"].startswith("Order was never placed, already canceled, or filled."))

    def test_template_has_two_arguments(self):
        self.assertEqual(bytes.fromhex(self.static["not_found"]["template_bytes"]), b"\xc0\x07 asset=\xc0\x00")

    def test_locations(self):
        rows = {row["location"]: (row["file"], row["line"]) for row in self.static["locations"]}
        self.assertEqual(rows["0x56e9b28"], ("l1/src/dex_registry/perp_dex.rs", 30))
        self.assertEqual(rows["0x56e9ae0"], ("l1/src/dex_registry/clearinghouses.rs", 11))
        self.assertEqual(rows["0x56bb478"], ("l1/src/books.rs", 19))

    def test_copy_rows_only_change_state_fields(self):
        by_pair = {(row["first"], row["second"]): row for row in self.static["copies"]}
        self.assertEqual(by_pair[("0x24bbcf0", "0x4447770")]["state_rows"], [])
        self.assertEqual(len(by_pair[("0x4d85940", "0x4d85290")]["state_rows"]), 10)

    def test_slot_targets(self):
        for slot, target in tool.SLOT_NAMES.items():
            self.assertEqual(tool.image_slot(self.image, slot), target)

    def test_slot_refused_when_absent(self):
        with self.assertRaises(tool.EvidenceError):
            tool.image_slot(self.image, 0x10)

    def test_one_closure_per_item(self):
        sites = [row for row in self.static["_sites"] if row[0] == 0x275A380]
        self.assertEqual([row[3] for row in sites], [0x24BBCF0])

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
        self.assertGreater(doc["mutations"]["killed"], 600)

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
