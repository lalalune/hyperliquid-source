import hashlib
import json
import pathlib
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import freeze_user_orders as tool  # noqa: E402

FOLDER = ROOT / "research" / "work-items" / "RE-006-freeze-user-orders-94"


def build(cls):
    cls.image = tool.load_image()
    cls.harness = tool.Harness(cls.image)
    cls.doc = tool.analyse(cls.image, full=False)


class Base(unittest.TestCase):
    setUpClass = classmethod(build)

    def run_case(self, case, copy=tool.FIRST):
        self.harness.copy = copy
        self.harness.machine.patches = {}
        return self.harness.run(case)

    def mutant(self, va, at, kind, case, copy=tool.FIRST):
        """compare_run of one patched byte: None means the spec cannot tell."""
        machine = self.harness.machine
        self.harness.copy = copy
        machine.patches = tool.mutate_patch(self.image, va, at, kind)
        machine.cache.clear()
        try:
            return tool.compare_run(self.harness, case)
        finally:
            machine.patches = {}
            machine.cache.clear()


class Identity(Base):
    def test_wrong_digest_refused(self):
        with self.assertRaisesRegex(tool.EvidenceError, "SHA-256 mismatch"):
            tool.load_image(expected="0" * 64)

    def test_wrong_bytes_refused(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "work" if (ROOT / "work").is_dir() else None) as folder:
            path = pathlib.Path(folder) / "copy"
            path.write_bytes(b"\x7fELF")
            with self.assertRaisesRegex(tool.EvidenceError, "SHA-256 mismatch"):
                tool.load_image(path)

    def test_address_outside_every_fde(self):
        with self.assertRaisesRegex(tool.EvidenceError, "outside every FDE"):
            self.image.fde(0x10)

    def test_not_a_function_start(self):
        with self.assertRaisesRegex(tool.EvidenceError, "not an FDE start"):
            self.image.exact_fde(tool.PREDICATE + 1)

    def test_nobits_never_resolves(self):
        bss = self.image.named[".bss"]
        with self.assertRaisesRegex(tool.EvidenceError, "outside file-backed"):
            self.image.offset(bss["address"] + 8)

    def test_function_extents(self):
        rows = {row["start"]: row for row in self.doc["functions"]}
        self.assertEqual(rows["0x274b550"]["end"], "0x274b7dd")
        self.assertEqual(rows["0x4d69da0"]["end"], "0x4d6a068")
        self.assertEqual(rows["0x4d6a070"]["end"], "0x4d6a338")
        self.assertEqual(rows["0x375f1c0"]["end"], "0x375f3cd")
        self.assertEqual(rows["0x42f4680"]["size"], rows["0x42f4bf0"]["size"])


class Handler(Base):
    def test_all_copies_agree_with_the_spec(self):
        for case in tool.handler_cases():
            for copy in tool.copies_of(case):
                self.harness.copy = copy
                self.assertIsNone(tool.compare_run(self.harness, case), (case.label, copy["name"]))

    def test_order_per_spot(self):
        run = self.run_case(tool.Case("t", "handler", spots=(4, 6)))
        names = [event[0] for event in run["events"]]
        self.assertEqual(names, ["insert", "alloc", "copy", "sweep", "twap", "flush", "sweep", "twap", "flush", "free"])

    def test_cap_edge(self):
        below = self.run_case(tool.Case("t", "handler", frozen=999))
        at = self.run_case(tool.Case("t", "handler", frozen=1000))
        self.assertEqual(below["status"], (tool.STATUS_OK,))
        self.assertEqual(at["status"], (tool.STATUS_TEXT,) + tool.MSG_CAP)
        self.assertEqual(at["events"], [])

    def test_cap_does_not_stop_unfreeze(self):
        run = self.run_case(tool.Case("t", "handler", frozen=5000, freeze=0))
        self.assertEqual(run["events"], [("remove", 3)])

    def test_privilege_off_stops_both_directions(self):
        for freeze in (0, 1):
            run = self.run_case(tool.Case("t", "handler", tag=0, freeze=freeze))
            self.assertEqual(run["status"], (tool.STATUS_TEXT,) + tool.MSG_REVOKED)
            self.assertEqual(run["events"], [])

    def test_walk_reads_the_clone(self):
        run = self.run_case(tool.Case("t", "handler", spots=(1, 2, 3), reorder=True))
        self.assertEqual([event[1] for event in run["events"] if event[0] == "sweep"], [1, 2, 3])

    def test_cap_immediate_is_seen(self):
        case = tool.Case("t", "handler", frozen=999)
        rows = tool.decode_range(self.image, *self.image.exact_fde(tool.FIRST["entry"]))
        row = [row for row in rows if row.imm_at is not None and row.op == "cmp" and row.size == 8][0]
        self.assertIsNotNone(self.mutant(row.va, row.imm_at + 1, "immediate", case))

    def test_reason_immediate_is_seen(self):
        at = bytes(self.image.blob[self.image.offset(0x274B6DE):self.image.offset(0x274B6DE) + 6])
        self.assertEqual(at, bytes.fromhex("41b910000000"))
        self.assertIsNotNone(self.mutant(0x274B6DE, 2, "immediate", tool.Case("t", "handler", spots=(1,))))

    def test_spec_would_notice_a_wrong_status(self):
        case = tool.Case("t", "handler", spots=())
        self.assertEqual(self.run_case(case)["status"], tool.spec_run(case, tool.FIRST)["status"])
        self.assertNotEqual(self.run_case(tool.Case("t", "handler", tag=0))["status"], tool.spec_run(case, tool.FIRST)["status"])


class Twap(Base):
    def test_both_copies(self):
        for case in tool.twap_cases():
            for copy in tool.TWAP_COPIES:
                self.harness.copy = copy
                self.assertIsNone(tool.compare_run(self.harness, case), (case.label, copy["name"]))

    def test_keeps_other_spots(self):
        run = self.run_case(tool.Case("t", "twap", rows=((100, 7), (101, 8), (102, 7))), tool.COPIES[1])
        self.assertEqual([event[1] for event in run["events"] if event[0] == "row"], [100, 102])

    def test_user_leaves_only_when_empty(self):
        run = self.run_case(tool.Case("t", "twap", rows=((100, 7), (101, 8))), tool.COPIES[1])
        self.assertNotIn(("user out",), run["events"])
        run = self.run_case(tool.Case("t", "twap", rows=((100, 7), (101, 7))), tool.COPIES[1])
        self.assertIn(("user out",), run["events"])

    def test_row_bytes_are_checked(self):
        machine = self.harness.machine
        self.harness.copy = tool.COPIES[1]
        va = 0x42F4B25
        self.assertEqual(bytes(self.image.blob[self.image.offset(va):self.image.offset(va) + 12])[-4:], struct.pack("<I", tool.ROW_TAG))
        self.assertIsNotNone(self.mutant(va, 8, "immediate", tool.Case("t", "twap", rows=((100, 7),)), tool.COPIES[1]))
        self.assertEqual(machine.patches, {})


class Predicate(Base):
    def test_table(self):
        for case in tool.predicate_cases():
            self.harness.copy = tool.FIRST
            self.assertIsNone(tool.compare_run(self.harness, case), case.label)

    def test_base_or_quote(self):
        rows = ((1, 0),)
        for sets, value in (({}, 0), ({1: (1,)}, 1), ({0: (1,)}, 1), ({2: (1,)}, 0)):
            self.assertEqual(self.run_case(tool.Case("t", "predicate", spot_rows=rows, frozen_sets=sets))["value"], value)

    def test_privilege_word_hides_the_set(self):
        case = tool.Case("t", "predicate", spot_rows=((1, 0),), frozen_sets={1: (1,)}, tag_map={1: 0})
        self.assertEqual(self.run_case(case)["value"], 0)

    def test_quote_jump_is_seen(self):
        va = 0x375F2F0
        data = bytes(self.image.blob[self.image.offset(va):self.image.offset(va) + 2])
        self.assertEqual(data, b"\x0f\x85")
        self.assertIsNotNone(self.mutant(va, 1, "branch", tool.Case("t", "predicate", spot_rows=((1, 0),), frozen_sets={0: (1,)})))


class Accessor(Base):
    def test_table(self):
        for case in tool.accessor_cases():
            self.harness.copy = tool.FIRST
            self.assertIsNone(tool.compare_run(self.harness, case), case.label)

    def test_four_arms_only(self):
        rows = self.doc["action_table"]["rows"]
        self.assertEqual(len(rows), 5)
        self.assertEqual(rows[0]["indices"], "84 rows")
        self.assertEqual(sorted(self.doc["action_table"]["selected"]), ["12", "14", "2", "35"])

    def test_filter_edges(self):
        for asset, kept in ((9999, False), (10000, True), (109999, True), (110000, False), (99999999, False), (100000000, True), (0, False)):
            self.assertEqual(tool.keeps_asset(asset), kept)
            value = self.run_case(tool.Case("t", "accessor", action=tool.ACTION_BASE_TAG + 12, one=asset))["value"]
            self.assertEqual(value, [asset] if kept else None)


class Register(Base):
    def test_table(self):
        for case in tool.register_cases():
            self.harness.copy = tool.FIRST
            self.assertIsNone(tool.compare_run(self.harness, case), case.label)

    def test_list_is_base_only(self):
        run = self.run_case(tool.Case("t", "register", base=2, quote=0, quotes=((0, 0),), existing=((1, 0),), base_list=(), quote_list=(0,), tokens=6))
        self.assertEqual(run["base_list"], [1])
        self.assertEqual(run["quote_list"], [0])


class Gate(Base):
    def test_table(self):
        for case in tool.gate_cases():
            self.harness.copy = tool.FIRST
            self.assertIsNone(tool.compare_run(self.harness, case), case.label)

    def test_three_hosts(self):
        gate = self.doc["gate"]
        self.assertEqual(gate["predicate_sites"], 3)
        self.assertEqual([row["host"] for row in gate["rows"]], ["0x2208580", "0x444b430", "0x444c310"])
        self.assertEqual({row["status_word"] for row in gate["rows"]}, {"0x158"})
        self.assertEqual({row["resolver_sites_in_host"] for row in gate["rows"]}, {1})

    def test_status_text(self):
        rows = {row["tag"]: row["value"] for row in self.doc["status_text"]}
        self.assertEqual(rows["0x158"], "User actions frozen for token")
        self.assertEqual(rows["0x15a"], "User is not frozen for token")

    def test_action_fields(self):
        self.assertEqual([row["past_end_status"] for row in self.doc["action_fields"]], ["0xea"] * 3)

    def test_display_arm_shape_is_checked(self):
        with self.assertRaisesRegex(tool.EvidenceError, "display arm"):
            tool.read_display(self.image, (0x0,))


class Evidence(Base):
    def test_cap_text_keeps_braces(self):
        rows = {row["at"]: row for row in self.doc["messages"]}
        self.assertEqual(rows["0x5998cd"]["value"], "number of frozen users capped at {MAX_N_FROZEN_USERS}")
        self.assertEqual(rows["0x5998cd"]["length"], 53)

    def test_copy_differences(self):
        field = [row for row in self.doc["copy_diff"][0]["rows"] if row["class"] == "field"]
        self.assertEqual(len(field), 3)
        self.assertEqual(self.doc["copy_diff"][1]["rows"], [])
        self.assertEqual({row["class"] for row in self.doc["copy_diff"][2]["rows"]}, {"call target"})
        self.assertEqual(len([row for row in self.doc["copy_diff"][0]["rows"] if row["class"] == "call target"]), 3)

    def test_no_mismatch(self):
        self.assertEqual(self.doc["mismatches"], 0)

    def test_committed_files(self):
        committed = json.loads((FOLDER / "evidence.json").read_text())
        for key in ("functions", "gate", "action_table", "status_text", "messages", "copy_diff", "locations", "worked_example", "cases", "outcomes", "fields", "reference_claims"):
            self.assertEqual(committed[key], json.loads(json.dumps(self.doc[key])), key)
        lines = (FOLDER / "mutations.tsv").read_text().splitlines()[1:]
        tally = {key: sum(1 for line in lines if line.split("\t")[3] == key) for key in ("killed", "survived", "unreached")}
        self.assertEqual(tally, committed["mutations"])
        self.assertFalse([line for line in lines if line.split("\t")[3] != "killed" and not line.split("\t")[5]])

    def test_manifest(self):
        rows = (FOLDER / "MANIFEST.sha256").read_text().splitlines()
        names = sorted(path.name for path in FOLDER.iterdir() if path.name != "MANIFEST.sha256")
        self.assertEqual([row.split("  ")[1] for row in rows], names)
        for row in rows:
            digest, name = row.split("  ")
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest)

    def test_no_external_tool(self):
        source = (ROOT / "tools" / "freeze_user_orders.py").read_text()
        self.assertNotIn("subprocess", source)
        self.assertNotIn("objdump", source.replace("No objdump", ""))


if __name__ == "__main__":
    unittest.main()
