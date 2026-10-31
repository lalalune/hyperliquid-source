"""Tests for tools/order_status_output.py: the static pins, the specification on real bytes, and negative controls."""

import hashlib
import importlib.util
import json
import pathlib
import struct
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("order_status_output", ROOT / "tools" / "order_status_output.py")
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)
FOLDER = ROOT / "research" / "work-items" / "RE-006-order-status-output-94"


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
    def test_row_sites(self):
        rows = tool.row_sites(self.image)
        self.assertEqual(len(rows), 52)
        self.assertEqual(len({row["host"] for row in rows}), 25)
        self.assertEqual(sum(1 for row in rows if row["inner"] == 2), 22)
        self.assertEqual(sum(1 for row in rows if row["inner"] == 4), 30)

    def test_row_site_status_values(self):
        rows = [row for row in tool.row_sites(self.image) if row["inner"] == 2]
        self.assertEqual(sorted(row["name"] for row in rows if row["name"]), ["filled"] * 4 + ["triggered"] * 3)
        self.assertEqual(sum(1 for row in rows if row["status"] == "register"), 15)
        self.assertNotIn("not in window", {row["status"] for row in rows})

    def test_stack_store_refuses_other_forms(self):
        self.assertIsNone(tool.stack_store(b"\x48\xc7\x45\x10\x03\x00\x00\x00", 0))
        self.assertIsNone(tool.stack_store(b"\x48\x89\x04\x24\x03\x00\x00\x00", 0))
        self.assertEqual(tool.stack_store(b"\x48\xc7\x44\x24\x10\x03\x00\x00\x00", 0), (0x10, 5))
        self.assertEqual(tool.stack_store(b"\x48\xc7\x04\x24\x03\x00\x00\x00", 0), (0, 4))

    def test_status_table(self):
        rows = tool.status_rows(self.image)
        self.assertEqual(len(rows), 36)
        names = {row[0]: row[3] for row in rows}
        self.assertEqual((names[0], names[1], names[2], names[3]), ("open", "filled", "canceled", "triggered"))
        self.assertEqual(names[0x23], "haltedRejected")

    def test_status_arm_refuses_a_wrong_address(self):
        with self.assertRaisesRegex(tool.EvidenceError, "no lea"):
            tool.status_arm(self.image, tool.STATUS_FIELD, 0)

    def test_buffers(self):
        rows = {row["name"]: row["object_offset"] for row in tool.buffer_rows(self.image)}
        self.assertEqual(rows["node_order_statuses"], "0x740")
        self.assertEqual(rows["node_twap_statuses"], "0x678")
        self.assertEqual(rows["node_raw_book_diffs"], "0x5b0")
        self.assertEqual(rows["node_fills"], "0x4e8")

    def test_gate_of_order_statuses(self):
        rows = {row["name"]: row for row in tool.buffer_rows(self.image)}
        self.assertEqual(rows["node_order_statuses"]["gate_jump"], "0x47f1db8")
        self.assertIn("closed with it", rows["node_twap_statuses"]["gate_jump"])

    def test_config_rows(self):
        rows = tool.config_rows(self.image)
        self.assertEqual(len(rows), len(tool.CONFIG_BYTES))

    def test_require_refuses_other_bytes(self):
        with self.assertRaisesRegex(tool.EvidenceError, "differ"):
            tool.require(self.image, tool.BOTH_CLOSED[0], b"\x90" * 8, "control")

    def test_sinks(self):
        rows = tool.sink_rows(self.image)
        self.assertEqual(len(rows), 4)
        self.assertEqual({row["handler"] for row in rows if row["row_kind"] == 3}, {"0x47f1100"})
        self.assertEqual({row["handler"] for row in rows if row["row_kind"] == 4}, {"0x47f0d10"})
        self.assertEqual(sorted(row["jump_site"] for row in rows), ["0x485483f", "0x4854a5a", "0x485524f", "0x4855457"])

    def test_keys(self):
        rows = tool.key_rows(self.image)
        self.assertEqual(len(rows), len(tool.KEY_SITES))
        self.assertEqual([row["key"] for row in rows[:6]], ["time", "user", "hash", "builder", "status", "order"])

    def test_wrong_key_text_is_refused(self):
        original = tool.KEY_SITES
        tool.KEY_SITES = ((tool.STATUS_JSON, 0x47EF50A, 0xD0, "tick", 4),)
        try:
            with self.assertRaisesRegex(tool.EvidenceError, "key text"):
                tool.key_rows(self.image)
        finally:
            tool.KEY_SITES = original

    def test_no_lea_is_refused(self):
        with self.assertRaisesRegex(tool.EvidenceError, "no rip lea"):
            tool.lea_target(self.image, tool.STATUS_HANDLER)

    def test_outside_address_has_no_fde_row(self):
        with self.assertRaises(tool.EvidenceError):
            tool.Image.exact_fde(self.image, tool.STATUS_HANDLER + 1)

    def test_drains(self):
        rows = tool.drain_rows(self.image)
        self.assertEqual(rows[1]["target"], "0x47052b0")
        self.assertEqual(rows[3]["target"], "0x47046b0")

    def test_copies_share_one_shape(self):
        for rows in (tool.copy_shapes(self.image, [pair[0] for pair in tool.ROTATIONS.values()]), tool.copy_shapes(self.image, [pair[1] for pair in tool.ROTATIONS.values()])):
            self.assertEqual(len(rows), 5)
            self.assertTrue(all(row["same_instruction_shape"] for row in rows))

    def test_shape_tells_a_different_function(self):
        rows = tool.copy_shapes(self.image, [tool.STATUS_HANDLER, tool.TWAP_HANDLER])
        self.assertFalse(rows[0]["same_instruction_shape"])


class Runs(Base):
    def test_every_case_matches(self):
        bad = [row for row in (tool.compare_run(self.harness, case) for case in self.cases) if row]
        self.assertEqual(bad, [])

    def test_every_kind_is_present(self):
        self.assertEqual({case.kind for case in self.cases}, {"sink", "handler", "buffer", "twap", "block", "file", "line"})

    def test_pending_row_moves_fields_up_and_clears_the_hash(self):
        out = self.harness.run(self.case("handler", "pending: second row"))
        self.assertEqual(out["vector"], [4, 2])
        self.assertEqual(out["pushed"]["hash_flag"], 0)
        self.assertEqual(out["log"], [])

    def test_flush_stops_at_word_2(self):
        out = self.harness.run(self.case("handler", "flush: row with word 2 stops the walk"))
        self.assertEqual([row[0] for row in out["log"]], ["buffer", "left", "left", "free"])
        self.assertEqual(out["vector"], [0, 0])

    def test_closed_drop_offsets(self):
        self.assertEqual(self.harness.run(self.case("handler", "pending: word 2 closed"))["log"], [["drop", 0x30]])
        self.assertEqual(self.harness.run(self.case("handler", "direct: word 0 closed"))["log"], [["drop", 0x28]])
        self.assertEqual(self.harness.run(self.case("handler", "flush: word 4 closed"))["log"], [])

    def test_word_3_is_direct(self):
        self.assertEqual(tool.inner_kind(3), "direct")
        self.assertEqual(self.harness.run(self.case("handler", "direct: word 3 gate word 1"))["log"][0][0], "buffer")

    def test_buffer_paths(self):
        self.assertEqual(self.harness.run(self.case("buffer", "file: plain"))["path"], "file")
        self.assertEqual(self.harness.run(self.case("buffer", "stream: no block"))["path"], "no block")
        self.assertEqual(self.harness.run(self.case("buffer", "vector: full"))["length"], 5)

    def test_forty_milliseconds(self):
        out = self.harness.run(self.case("buffer", "stream: flag plus 40 ms"))
        self.assertEqual(out["local"], [2460002, tool.CLOCK[1], tool.CLOCK[2] + 40000000])

    def test_twap_niche_is_not_freed(self):
        self.assertEqual(self.harness.run(self.case("twap", "closed: niche 2"))["log"], [["free", 16]])
        self.assertEqual(self.harness.run(self.case("twap", "closed: first word past the niche"))["log"], [["free", tool.CLOSED + 3], ["free", 16]])

    def test_twap_order_of_frees(self):
        self.assertEqual(self.harness.run(self.case("twap", "closed: second text"))["log"], [["free", 24], ["free", 16]])
        self.assertEqual(self.harness.run(self.case("twap", "file: second text"))["log"], [["free", 16], ["free", 24]])

    def test_block_drain(self):
        out = self.harness.run(self.case("block", "status: two rows"))
        self.assertEqual([row[0] for row in out["log"]], ["batch", "drop", "drop", "free"])
        self.assertTrue(out["reset"])
        self.assertEqual(self.harness.run(self.case("block", "status: no vector"))["log"], [])

    def test_block_flush_needs_the_low_byte(self):
        self.assertEqual(self.harness.run(self.case("block", "twap: flush argument"))["log"][-1], ["flush"])
        self.assertNotEqual(self.harness.run(self.case("block", "twap: flush argument high bits only"))["log"][-1], ["flush"])

    def test_paths(self):
        out = self.harness.run(self.case("file", "status file: next hour"))
        self.assertEqual(out["log"][0], ["open", "base/node_order_statuses/hourly/D2460100/H3"])

    def test_line_keys_in_order(self):
        line = self.harness.run(self.case("line", "file: both"))
        self.assertLess(line.index('"user"'), line.index('"hash"'))
        self.assertLess(line.index('"hash"'), line.index('"builder"'))
        self.assertLess(line.index('"builder"'), line.index('"status"'))
        self.assertLess(line.index('"status"'), line.index('"order"'))
        self.assertTrue(line.endswith('"}\n') or line.endswith('}\n'))

    def test_null_fields(self):
        line = self.harness.run(self.case("line", "file: plain"))
        self.assertIn('"hash":null,"builder":null,', line)

    def test_every_status_byte_prints_its_name(self):
        for row in tool.status_rows(self.image):
            line = self.harness.run(self.case("line", "file: status byte %d" % row[0]))
            self.assertIn('"status":"%s"' % row[3], line)


class Controls(Base):
    def assertBreaks(self, kind, label, va, value):
        case = self.case(kind, label)
        self.assertIsNone(tool.compare_run(self.harness, case))
        self.poke(va, value)
        self.assertIsNotNone(tool.compare_run(self.harness, case))

    def test_inner_word_compare(self):
        self.assertBreaks("handler", "flush: row with word 2 stops the walk", 0x47F140B, 3)

    def test_row_stride(self):
        self.assertBreaks("handler", "flush: three", 0x47F13D1, 0x19)

    def test_time_shift(self):
        self.assertBreaks("buffer", "stream: flag plus 40 ms", 0x47EDAA0, 0)

    def test_status_byte_offset(self):
        self.assertBreaks("handler", "pending: first row", 0x47F130D, 0xF9)

    def test_twap_gate(self):
        self.assertBreaks("twap", "closed: plain" if False else "closed: second text", 0x47F0D32, 0x79)

    def test_hour_limit(self):
        self.assertBreaks("file", "status file: seconds at the hour limit", 0x4703AE9 - 5, 0x91)

    def test_block_vector_reset(self):
        self.assertBreaks("block", "status: two rows", 0x4857FAA, 0)

    def test_status_table_byte(self):
        self.assertBreaks("line", "file: plain", tool.ROTATIONS["status file"][1] + 0x14, 0xCC)

    def test_a_spec_change_is_seen(self):
        case = self.case("handler", "direct: builder word")
        expected = tool.spec_run(case)
        expected["log"][0][1] ^= 1
        self.assertNotEqual(self.harness.run(case), expected)


class Packet(unittest.TestCase):
    def test_manifest(self):
        for line in (FOLDER / "MANIFEST.sha256").read_text().splitlines():
            digest, name = line.split("  ")
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest)

    def test_manifest_covers_the_folder(self):
        listed = {line.split("  ")[1] for line in (FOLDER / "MANIFEST.sha256").read_text().splitlines()}
        self.assertEqual(listed, {path.name for path in FOLDER.iterdir() if path.name != "MANIFEST.sha256"})

    def test_regeneration_is_byte_identical(self):
        image = tool.load_image()
        files = tool.render(tool.analyse(image))
        for name, text in files.items():
            self.assertEqual((FOLDER / name).read_text(encoding="ascii"), text, name)

    def test_every_open_row_has_a_reason(self):
        lines = (FOLDER / "mutations.tsv").read_text(encoding="ascii").splitlines()[1:]
        rows = [line.split("\t") for line in lines]
        self.assertTrue(rows)
        self.assertEqual([row for row in rows if row[3] != "killed" and not row[5]], [])
        self.assertNotIn("no reason recorded", {row[5] for row in rows})

    def test_evidence_counts(self):
        doc = json.loads((FOLDER / "evidence.json").read_text())
        self.assertEqual(doc["mismatches"], 0)
        self.assertEqual(doc["target"]["sha256"], tool.SHA256)
        self.assertEqual(doc["row_site_census"]["sites"], 52)
        self.assertEqual(doc["status_names"], 36)


if __name__ == "__main__":
    unittest.main()
