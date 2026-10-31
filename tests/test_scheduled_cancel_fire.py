"""Tests for tools/scheduled_cancel_fire.py: scheduled cancel firing path of node #94."""

import hashlib
import json
import pathlib
import struct
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import scheduled_cancel_fire as tool  # noqa: E402

FOLDER = ROOT / "research" / "work-items" / "RE-006-scheduled-cancel-fire-94"
SHARED = {}
Case, Entry, user_id = tool.Case, tool.Entry, tool.user_id


def shared():
    if not SHARED:
        SHARED["image"] = tool.load_image()
        SHARED["harnesses"] = [tool.Harness(SHARED["image"], copy) for copy in tool.COPIES]
    return SHARED


def run(case, copy=0):
    return shared()["harnesses"][copy].run(case)


def fire(entries, **fields):
    return run(Case("t", "fire", entries=entries, **fields))


def fired(result):
    return [event[1] for event in result["events"] if event[0] == "select"]


def setUpModule():
    shared()


class IdentityTests(unittest.TestCase):
    def test_wrong_hash_is_refused(self):
        with self.assertRaisesRegex(tool.EvidenceError, "SHA-256 mismatch"):
            tool.load_image(expected="0" * 64)

    def test_hash_constant(self):
        self.assertEqual(tool.SHA256, "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f")

    def test_function_extents(self):
        image = shared()["image"]
        self.assertEqual(image.exact_fde(0x2702760), (0x2702760, 0x2702D59))
        self.assertEqual(image.exact_fde(0x270F1C0), (0x270F1C0, 0x270F6E5))
        self.assertEqual(image.exact_fde(0x4D005D0), (0x4D005D0, 0x4D00AF5))
        self.assertEqual(image.exact_fde(0x4D000A0), (0x4D000A0, 0x4D005C5))
        self.assertEqual(image.exact_fde(0x4CEF8F0), (0x4CEF8F0, 0x4CEFEE9))
        self.assertEqual(image.exact_fde(0x4CEF2F0), (0x4CEF2F0, 0x4CEF8E9))
        self.assertEqual(image.exact_fde(0x26E3EF0), (0x26E3EF0, 0x26E4231))
        self.assertEqual(image.exact_fde(0x26E4240), (0x26E4240, 0x26E4611))

    def test_inside_a_function_is_refused(self):
        with self.assertRaisesRegex(tool.EvidenceError, "not an FDE start"):
            shared()["image"].exact_fde(0x2702761)

    def test_nobits_never_resolves(self):
        image = shared()["image"]
        bss = image.named[".bss"]
        with self.assertRaisesRegex(tool.EvidenceError, "outside file-backed"):
            image.offset(bss["address"] + 8)

    def test_reason_names(self):
        rows = tool.status_names(shared()["image"])
        self.assertEqual({row["value"]: row["text"] for row in rows}, {0xD: "liquidatedCanceled", 0xF: "scheduledCancel", 0x10: "internalCancel"})

    def test_a_wrong_status_table_is_refused(self):
        saved = tool.STATUS_TABLE
        tool.STATUS_TABLE = 0x7038E0 + 0x1000
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.status_names(shared()["image"])
        finally:
            tool.STATUS_TABLE = saved

    def test_vote_case(self):
        rows = tool.read_vote(shared()["image"])
        self.assertEqual(rows[0]["case"], 27)

    def test_copies_have_one_shape(self):
        rows = tool.copy_diff(shared()["image"])
        self.assertEqual([row["shape_differences"] for row in rows], [0] * 6)
        third = [row for row in rows if row["function"] == "fire" and row["copy"] == "third"][0]
        self.assertEqual(third["field_map"], {"0x39a8": "0x4428", "0x39b0": "0x4430", "0x39b8": "0x4438"})

    def test_pins_hold(self):
        self.assertEqual(len(tool.read_pins(shared()["image"])), 4)

    def test_pin_count_is_enforced(self):
        saved = tool.pin_rows
        tool.pin_rows = lambda: [(0x2702760, "absent", b"\xde\xad\xbe\xef\x01", 1)]
        try:
            with self.assertRaisesRegex(tool.EvidenceError, "sites"):
                tool.read_pins(shared()["image"])
        finally:
            tool.pin_rows = saved

    def test_sites(self):
        image = shared()["image"]
        sites = tool.direct_sites(image, [copy["select"] for copy in tool.COPIES] + [copy["fire"] for copy in tool.COPIES])
        SHARED["sites"] = sites
        rows = tool.read_sites(image, sites)
        self.assertEqual([(row["reason"], row["flag"]) for row in rows], [(0xF, 0), (0xD, 0), (0x10, 1)] * 3)
        self.assertEqual([row["host"] for row in tool.read_routes(image, sites)], ["0x22297c0", "0x470e9a0", "0x47162d0"])

    def test_a_wrong_reason_site_is_refused(self):
        image = shared()["image"]
        sites = SHARED.get("sites") or tool.direct_sites(image, [copy["select"] for copy in tool.COPIES])
        saved = tool.COPIES
        tool.COPIES = (dict(tool.COPIES[0], fire_site=tool.COPIES[0]["liq_site"]),)
        try:
            with self.assertRaisesRegex(tool.EvidenceError, "arguments"):
                tool.read_sites(image, sites)
        finally:
            tool.COPIES = saved

    def test_a_wrong_host_is_refused(self):
        image = shared()["image"]
        sites = {tool.COPIES[0]["fire"]: [(0x2229DB1, 0xE8)]}
        saved = tool.COPIES
        tool.COPIES = tool.COPIES[:1]
        try:
            with self.assertRaisesRegex(tool.EvidenceError, "host of"):
                tool.read_routes(image, sites)
        finally:
            tool.COPIES = saved


class FireTests(unittest.TestCase):
    def test_all_cases_match_on_every_copy(self):
        for harness in shared()["harnesses"]:
            for case in tool.all_cases():
                if harness.copy is not tool.FIRST and case.kind not in ("fire", "select"):
                    continue
                self.assertIsNone(tool.compare_run(harness, case))

    def test_deadline_equal_to_now_fires(self):
        self.assertEqual(len(fired(fire([Entry(user_id(2), 0, 20000, 3600, 5000)]))), 1)

    def test_deadline_one_nano_later_waits(self):
        self.assertEqual(fired(fire([Entry(user_id(2), 0, 20000, 3600, 5001)])), [])

    def test_seconds_outrank_nanos(self):
        self.assertEqual(fired(fire([Entry(user_id(2), 0, 20000, 3601, 0)])), [])
        self.assertEqual(len(fired(fire([Entry(user_id(2), 0, 20000, 3599, 0x90000000)]))), 1)

    def test_date_is_signed(self):
        self.assertEqual(len(fired(fire([Entry(user_id(2), 0, 0xFFFF0000)]))), 1)

    def test_firing_counts_and_disarms(self):
        result = fire([Entry(user_id(2), 3, 19000, 5, 6)])
        self.assertEqual(result["entries"], [(user_id(2).hex(), 4, 0, 5, 6)])

    def test_count_saturates(self):
        result = fire([Entry(user_id(2), tool.MASK[8], 19000)])
        self.assertEqual(result["entries"][0][1], tool.MASK[8])

    def test_firing_passes_reason_and_no_flag(self):
        event = [row for row in fire([Entry(user_id(2), 0, 19000)])["events"] if row[0] == "select"][0]
        self.assertEqual(event[2:], (2, 0xF, 0))

    def test_users_fire_in_key_order(self):
        result = fire([Entry(user_id(5), 0, 19000), Entry(user_id(3), 0, 19000), Entry(user_id(4), 0, 19000)])
        self.assertEqual(fired(result), [user_id(3).hex(), user_id(4).hex(), user_id(5).hex()])

    def test_no_day_reset_on_same_date(self):
        result = fire([Entry(user_id(2), 4)])
        self.assertEqual(result["entries"], [(user_id(2).hex(), 4, 0, 0, 0)])

    def test_day_reset_zeroes_counts_and_drops_disarmed(self):
        result = fire([Entry(user_id(2), 4), Entry(user_id(3), 5, 20001), Entry(user_id(4), 6, 19000)], prev=19999)
        self.assertEqual(result["entries"], [(user_id(3).hex(), 0, 20001, 0, 0)])
        self.assertEqual(result["length"], 1)

    def test_entry_fired_on_the_reset_block_is_removed(self):
        result = fire([Entry(user_id(2), 9, 19000)], prev=19999)
        self.assertEqual(len(fired(result)), 1)
        self.assertEqual(result["entries"], [])

    def test_day_reset_compares_signed(self):
        self.assertEqual(fire([Entry(user_id(2), 4)], prev=0xFFFF0000)["entries"], [])
        self.assertEqual(fire([Entry(user_id(2), 4)], now=(0xFFFF0000, 0, 0), prev=20000)["entries"][0][1], 4)

    def test_third_copy_reads_its_own_map(self):
        case = Case("t", "fire", entries=[Entry(user_id(2), 0, 19000)])
        self.assertEqual(len(fired(run(case, 2))), 1)


class SelectTests(unittest.TestCase):
    def test_all_walks_dexes_then_spot(self):
        kinds = [event[0] for event in run(Case("t", "select", selector=2, dexes=[1, 0], collections=2))["events"]]
        self.assertEqual(kinds, ["alloc", "drop", "perp", "flush dex", "drop", "perp", "flush dex", "free", "spot", "flush spot"])

    def test_perp_one_splits_the_asset(self):
        event = [row for row in run(Case("t", "select", selector=0, asset=10005))["events"] if row[0] == "perp"][0]
        self.assertEqual(event[:4], ("perp", 1, 10005, 1))

    def test_dex_past_end_panics(self):
        result = run(Case("t", "select", selector=0, asset=20000, collections=2))
        self.assertEqual(result["stop"], ("unwrap", tool.ERROR_WORD, tool.LOC_SELECT))

    def test_spot_keeps_the_raw_asset(self):
        event = run(Case("t", "select", selector=1, asset=20000))["events"][0]
        self.assertEqual(event[:3], ("spot", 1, 20000))


class ClosureTests(unittest.TestCase):
    def test_perp_local_is_the_remainder(self):
        result = run(Case("t", "closure perp", selector=1, books=3, asset=10001))
        self.assertEqual(result["events"], [("sweep", 1, 0xF)])

    def test_spot_index_is_not_reduced(self):
        result = run(Case("t", "closure spot", selector=1, books=3, asset=10001))
        self.assertEqual(result["stop"], ("panic", tool.LOC_BOOK_INDEX))

    def test_no_flag_leaves_twaps(self):
        me = user_id(1)
        result = run(Case("t", "closure perp", selector=0, books=1, flag=0, users={me: [5]}, ids=[5]))
        self.assertEqual(result["events"], [("sweep", 0, 0xF)])

    def test_twap_row_is_terminated(self):
        me = user_id(1)
        case = Case("t", "closure perp", selector=0, books=1, flag=1, users={me: [100]}, ids=[100], rows={100: 5})
        kinds = [event[0] for event in run(case)["events"]]
        self.assertEqual(kinds, ["sweep", "collect", "take", "user out", "drain step", "drop", "make", "row", "list free"])

    def test_row_dex_past_metadata_panics(self):
        me = user_id(1)
        case = Case("t", "closure perp", selector=0, books=1, flag=1, users={me: [100]}, ids=[100], rows={100: 20001}, metas=2)
        self.assertEqual(run(case)["stop"], ("unwrap", tool.ERROR_WORD, tool.LOC_PERP_ROW))


class SweepTests(unittest.TestCase):
    SLAB = [(0, 0, 900), (2, 0, 111), (0, 1, 800), (4, 0, 100)]

    def removed(self, **fields):
        result = run(Case("t", fields.pop("kind", "sweep perp"), slab=self.SLAB, **fields))
        return [event[1] for event in result["events"] if event[0] == "remove"], result

    def test_perp_merges_and_sorts(self):
        keys, result = self.removed(first=[0, 1, 2, 3], second=[50, 900])
        self.assertEqual(keys, [50, 100, 800, 900])
        self.assertEqual([event[0] for event in result["events"]][-2:], ["map out", "entry drop"])

    def test_spot_without_flag_skips_flagged_and_second_tree(self):
        keys, result = self.removed(kind="sweep spot", chain=False, first=[0, 1, 2, 3], second=[50])
        self.assertEqual(keys, [100, 900])
        self.assertNotIn("map out", [event[0] for event in result["events"]])

    def test_absent_user_does_nothing(self):
        self.assertEqual(self.removed(absent=True, others=[2])[1]["events"], [])

    def test_none_from_the_map_skips_the_drop(self):
        result = self.removed(first=[0], claimed_none=True)[1]
        self.assertNotIn("entry drop", [event[0] for event in result["events"]])


class ControlTests(unittest.TestCase):
    def flip(self, patches, case, copy=0):
        harness = shared()["harnesses"][copy]
        machine = harness.machine
        machine.patches = patches
        for va in patches:
            for back in range(16):
                machine.cache.pop(va - back, None)
        try:
            return tool.compare_run(harness, case)
        finally:
            machine.patches = {}
            for va in patches:
                for back in range(16):
                    machine.cache.pop(va - back, None)

    def test_due_flip_is_seen(self):
        image = shared()["image"]
        at = image.offset(0x2702AA0)
        self.assertEqual(bytes(image.blob[at:at + 2]), b"\x0f\x8f")
        case = Case("t", "fire", entries=[Entry(user_id(2), 0, 19000)])
        self.assertIn("differs", self.flip({0x2702AA1: 0x8E}, case))

    def test_day_flip_is_seen(self):
        image = shared()["image"]
        at = image.offset(0x2702BEB)
        self.assertEqual(bytes(image.blob[at:at + 2]), b"\x0f\x8d")
        case = Case("t", "fire", prev=19999, entries=[Entry(user_id(2), 4)])
        self.assertIn("differs", self.flip({0x2702BEC: 0x8C}, case))

    def test_reason_immediate_flip_is_seen(self):
        image = shared()["image"]
        at = image.offset(0x2702B46)
        self.assertEqual(bytes(image.blob[at:at + 3]), b"\x41\xb8\x0f")
        self.assertIn("differs", self.flip({0x2702B48: 0x0D}, Case("t", "fire", entries=[Entry(user_id(2), 0, 19000)])))

    def test_retain_write_flip_is_seen(self):
        image = shared()["image"]
        self.assertEqual(bytes(image.blob[image.offset(0x27E8B57):image.offset(0x27E8B57) + 2]), b"\x0f\x84")
        case = Case("t", "fire", prev=19999, entries=[Entry(user_id(2), 4), Entry(user_id(3), 4, 20001)])
        self.assertIn("differs", self.flip({0x27E8B58: 0x85}, case))


class EvidenceTests(unittest.TestCase):
    def test_static_files_regenerate(self):
        """Static sections agree with the stored evidence; the mutation pass is left to the tool run."""
        evidence = tool.analyse(shared()["image"], full=False)
        stored = json.loads((FOLDER / "evidence.json").read_text())
        for key in ("functions", "routes", "selector_sites", "vote_arm", "status_names", "copy_diff", "locations", "worked_example", "pins", "outcomes"):
            self.assertEqual(json.loads(json.dumps(evidence[key])), stored[key], key)
        self.assertEqual(evidence["mismatches"], 0)
        self.assertEqual(stored["mismatches"], 0)

    def test_stored_tallies_match_rows(self):
        stored = json.loads((FOLDER / "evidence.json").read_text())
        rows = (FOLDER / "mutations.tsv").read_text().splitlines()[1:]
        for key in ("killed", "survived", "unreached"):
            self.assertEqual(stored["mutations"][key], sum(1 for row in rows if row.split("\t")[3] == key))

    def test_every_survivor_has_a_reason(self):
        rows = (FOLDER / "mutations.tsv").read_text().splitlines()[1:]
        for row in rows:
            fields = row.split("\t")
            if fields[3] != "killed":
                self.assertTrue(fields[5], row)

    def test_manifest_matches(self):
        for line in (FOLDER / "MANIFEST.sha256").read_text().splitlines():
            digest, name = line.split("  ")
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest)

    def test_outputs_are_ascii(self):
        with tempfile.TemporaryDirectory() as folder:
            tool.write_outputs(folder, {"a.txt": "ascii\n"})
            self.assertEqual(pathlib.Path(folder, "a.txt").read_bytes(), b"ascii\n")
            with self.assertRaises(UnicodeEncodeError):
                tool.write_outputs(folder, {"b.txt": "☃"})


if __name__ == "__main__":
    unittest.main()
