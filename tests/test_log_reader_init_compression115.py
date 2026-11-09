"""Tests for the node #115 log::Reader::InitCompression model.

Replays all 2,400 cases in cases.tsv through the tool's replay_case,
then checks the model's key behaviours directly: the type install
with the flag stored first, the kind-7-only Create gate (a type-0
record still allocates the buffer but installs a null product), the
0x8000-byte buffer swap (old buffer deleted, old uncompressor
leaked), the re-entry behaviour, and the live engine check (a real
DCtx resets with directive 1).
"""

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import log_reader_init_compression115 as m

PACKET = (Path(__file__).resolve().parents[1] / "research" / "work-items"
          / "re-002-node115-rocksdb-log-reader-init-compression-115")


def _read_cases():
    rows = []
    with open(PACKET / "cases.tsv") as fh:
        header = fh.readline().rstrip("\n").split("\t")
        for line in fh:
            rows.append(dict(zip(header, line.rstrip("\n").split("\t"))))
    return rows


class ReplayTests(unittest.TestCase):
    def test_case_count(self):
        rows = _read_cases()
        self.assertEqual(len(rows), 2400)
        groups = {}
        for r in rows:
            groups[r["group"]] = groups.get(r["group"], 0) + 1
        self.assertEqual(groups, {"type_install": 600, "create_buffer": 600,
                                  "reentry": 600, "bindings": 600})

    def test_all_cases_replay(self):
        bad = []
        for r in _read_cases():
            ok, detail = m.replay_case(r)
            if not ok:
                bad.append((r["id"], detail))
        self.assertEqual(bad, [], f"{len(bad)} cases failed: {bad[:5]}")


class TypeInstallTests(unittest.TestCase):
    def _run(self, **kw):
        p = {"type": 7, "old_uncompress": 0, "old_buffer": 0}
        p.update(kw)
        return m._run_scenario(p)

    def test_type_sweeps_all_256_bytes(self):
        seen = set()
        for r in _read_cases():
            if r["group"] == "type_install":
                seen.add(json.loads(r["param"])["type"])
        self.assertEqual(seen, set(range(256)))

    def test_flag_set_and_type_stored_in_binary_order(self):
        out = self._run(type=7)
        self.assertEqual(out["type_after"], 7)
        self.assertTrue(out["record_read_after"])
        kinds = [k for k, _ in out["events"]]
        # The binary stores the flag (0x5f01e90) before the type
        # (0x5f01e99); upstream lists them the other way round.
        self.assertLess(kinds.index("set_record_read"),
                        kinds.index("set_compression_type"))
        self.assertEqual(out["events"][0], ["read_type", 7])

    def test_no_kNoCompression_gate(self):
        # Unlike the writer twin, there is no early return for type 0:
        # the flag is set and the buffer is allocated, but the Create
        # gate returns null so uncompress_ stays null.
        out = self._run(type=0)
        self.assertTrue(out["record_read_after"])
        self.assertEqual(out["type_after"], 0)
        self.assertEqual(out["uncompress_after"], 0)
        self.assertNotEqual(out["buffer_after"], 0)
        self.assertEqual(out["buffer_size"], 0x8000)

    def test_create_gate_kind_7_only(self):
        for ctype in (1, 2, 3, 4, 5, 6, 0x40, 0xFF):
            out = self._run(type=ctype)
            self.assertEqual(out["uncompress_after"], 0,
                             f"type {ctype} should install null")
            # ... but the buffer is still allocated.
            self.assertNotEqual(out["buffer_after"], 0)
            self.assertEqual(out["buffer_size"], 0x8000)
        out = self._run(type=7)
        self.assertNotEqual(out["uncompress_after"], 0)

    def test_buffer_always_kBlockSize(self):
        for ctype in (0, 1, 7, 0x40, 0xFF):
            self.assertEqual(self._run(type=ctype)["buffer_size"], 0x8000)

    def test_old_buffer_freed_old_uncompress_leaked(self):
        out = self._run(type=7, old_buffer=42, old_uncompress=77)
        self.assertEqual(out["freed_buffers"], [42])
        self.assertEqual(out["leaked_uncompress"], [77])
        kinds = [k for k, _ in out["events"]]
        self.assertIn("leak_old_uncompress", kinds)
        self.assertIn("delete_old_buffer", kinds)
        # The fresh buffer is stored before the old one is freed.
        self.assertLess(kinds.index("install_buffer"),
                        kinds.index("delete_old_buffer"))

    def test_fresh_reader_installs_cleanly(self):
        out = self._run(type=7)
        self.assertEqual(out["freed_buffers"], [])
        self.assertEqual(out["leaked_uncompress"], [])
        kinds = [k for k, _ in out["events"]]
        self.assertNotIn("leak_old_uncompress", kinds)
        self.assertNotIn("delete_old_buffer", kinds)


class ReentryTests(unittest.TestCase):
    def test_second_call_leaks_first_product_and_frees_first_buffer(self):
        p = {"type": 7, "second_type": 7,
             "old_uncompress": 0, "old_buffer": 0}
        out = m._run_scenario(p)
        first_product = out["first"]["uncompress_after"]
        first_buffer = out["first"]["buffer_after"]
        self.assertNotEqual(first_product, 0)
        self.assertNotEqual(first_buffer, 0)
        self.assertEqual(out["leaked_uncompress"], [first_product])
        self.assertEqual(out["freed_buffers"], [first_buffer])
        # The second call installs a fresh product and buffer.
        self.assertNotEqual(out["uncompress_after"], 0)
        self.assertNotEqual(out["buffer_after"], first_buffer)

    def test_reentry_to_non_zstd_nulls_product_but_keeps_flag(self):
        p = {"type": 7, "second_type": 1,
             "old_uncompress": 0, "old_buffer": 0}
        out = m._run_scenario(p)
        self.assertEqual(out["uncompress_after"], 0)
        self.assertEqual(out["type_after"], 1)
        self.assertTrue(out["record_read_after"])
        self.assertEqual(len(out["leaked_uncompress"]), 1)
        self.assertEqual(len(out["freed_buffers"]), 1)

    def test_reentry_events_cover_both_calls(self):
        p = {"type": 7, "second_type": 7,
             "old_uncompress": 0, "old_buffer": 0}
        out = m._run_scenario(p)
        self.assertEqual(out["first"]["events"][0], ["read_type", 7])
        self.assertEqual(out["second"]["events"][0], ["read_type", 7])


class BindingsTests(unittest.TestCase):
    def test_functions_tsv_matches_binary_and_census(self):
        rows = list(open(PACKET / "functions.tsv"))[1:]
        self.assertEqual(len(rows), 1)
        data = m._read_binary()
        for row in rows:
            cols = row.rstrip("\n").split("\t")
            start, end = int(cols[1], 16), int(cols[2], 16)
            body = data[m._va_to_off(start):m._va_to_off(end)]
            import hashlib
            self.assertEqual(hashlib.sha256(body).hexdigest(), cols[4])

    def test_caller_census(self):
        census = json.load(open(PACKET / "census.json"))
        self.assertEqual(census["validated_sites"], 3)
        self.assertEqual(census["targets"]["0x5f01e80"]["calls"], 3)
        self.assertEqual(census["targets"]["0x5f01e80"]["jumps"], 0)
        self.assertEqual(census["targets"]["0x5f01e80"]["lea_refs"], 0)
        sites = [l.split("\t") for l in
                 open(PACKET / "callers.tsv").read().splitlines()[1:]]
        by_site = {row[3]: row for row in sites}
        self.assertEqual(by_site["0x5f023c4"][4], "0x5f01f10")
        self.assertEqual(by_site["0x5f0286b"][4], "0x5f01f10")
        self.assertEqual(by_site["0x5f033ac"][4], "0x5f02f20")

    def test_reader_layout_pins_the_four_fields(self):
        layout = {n: (o, s) for n, o, s in m.READER_LAYOUT}
        self.assertEqual(layout["compression_type_"], (0x72, 1))
        self.assertEqual(layout["compression_type_record_read_"], (0x73, 1))
        self.assertEqual(layout["uncompress_"], (0x78, 8))
        self.assertEqual(layout["uncompressed_buffer_"], (0x80, 8))
        self.assertEqual(layout["size"], (0x00, 0xF0))

    def test_live_engine_check(self):
        created, reset_ret = m.live_engine_check()
        self.assertTrue(created)
        self.assertEqual(reset_ret, 0)


if __name__ == "__main__":
    unittest.main()
