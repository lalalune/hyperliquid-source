"""Tests for the node #115 SequentialFileReader::Read model.

Replays all 2,400 generated cases (2,396 rows in cases.tsv -- the 4
direct-path full-block rows over the cap live only in cases.json)
through the tool's replay_case, then checks the model's key
behaviours directly: the paranoid scratch bump, the n == 0 fast
path, the buffered loop (rate-limiter gating, short/error breaks,
the sret move dropping subcode/scope), the direct path (alignment
math, the memcpy tail, the double offset advance with listeners),
the file selection, multi-call sequences (offset_ discipline), and
the live engine check (real file round trip + the empty-literal
byte + the bump in the event trace).
"""

import hashlib
import json
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import sequential_file_reader_read115 as m

PACKET = (Path(__file__).resolve().parents[1] / "research" / "work-items"
          / "re-002-node115-rocksdb-sequential-file-reader-read-115")
BIN = Path(__file__).resolve().parents[1] / "work" / "hl-node-115.bin"
CENSUS = (Path(__file__).resolve().parents[1] / "research" / "work-items"
          / "RE-002-node115-vendor-census" / "census.json")


def _read_cases():
    rows = []
    with open(PACKET / "cases.tsv") as fh:
        header = fh.readline().rstrip("\n").split("\t")
        for line in fh:
            rows.append(dict(zip(header, line.rstrip("\n").split("\t"))))
    return rows


def _run(**kw):
    p = {"n": 100, "use_direct_io": False, "priority": m.IO_TOTAL}
    p.update(kw)
    return m._run_scenario(p)


def _call(out, i=0):
    return out["calls_out"][i]


def _events(out, kind):
    return [v for k, v in out["events"] if k == kind]


class ReplayTests(unittest.TestCase):
    def test_case_counts(self):
        rows = _read_cases()
        self.assertEqual(len(rows), 2396)
        groups = {}
        for r in rows:
            groups[r["group"]] = groups.get(r["group"], 0) + 1
        self.assertEqual(groups, {"buffered_path": 600,
                                  "direct_path": 596,
                                  "sequences": 600, "bindings": 600})
        cases = json.load(open(PACKET / "cases.json"))
        self.assertEqual(len(cases), 2400)
        gen = m.generate_cases()
        self.assertEqual(len(gen), 2400)
        self.assertEqual([c["id"] for c in gen],
                         [c["id"] for c in cases])

    def test_all_cases_replay(self):
        bad = []
        for r in _read_cases():
            ok, detail = m.replay_case(r)
            if not ok:
                bad.append((r["id"], detail))
        self.assertEqual(bad, [], f"{len(bad)} cases failed: {bad[:5]}")

    def test_generated_cases_replay(self):
        bad = []
        for c in m.generate_cases():
            row = {"group": c["group"], "scenario": c["scenario"],
                   "param": c["param"], "expected": c["expected"]}
            ok, detail = m.replay_case(row)
            if not ok:
                bad.append((c["id"], detail))
        self.assertEqual(bad, [], f"{len(bad)} cases failed: {bad[:5]}")


class BufferedPathTests(unittest.TestCase):
    def test_full_read_returns_ok_and_result(self):
        out = _run(read_script=m._ok_script([100], 1))
        call = _call(out)
        self.assertEqual(call["return_status"]["code"], 0)
        self.assertEqual(call["result"], {"data": "scratch", "size": 100})
        self.assertEqual(call["offset_after"], 0)
        self.assertEqual(out["iostats_bytes_read"], 100)

    def test_scratch_bump_runs_before_the_read(self):
        out = _run(scratch_hex="41",
                   read_script=m._ok_script([100], 3))
        bumps = _events(out, "scratch_bump")
        self.assertEqual(len(bumps), 1)
        self.assertEqual(bumps[0]["scratch0"], 0x42)
        # The read overwrites the bumped byte with the file's first
        # byte, so the final scratch starts with the file data.
        self.assertEqual(bytes.fromhex(_call(out)["scratch_after"])[:1],
                         m._bytes(1, 3)[:1])

    def test_no_bump_when_n_is_zero_or_scratch_null(self):
        out = _run(n=0, scratch_hex="41", read_script=[])
        self.assertEqual(_events(out, "scratch_bump"), [])
        out = _run(scratch_null=True,
                   read_script=m._ok_script([100], 2))
        self.assertEqual(_events(out, "scratch_bump"), [])
        self.assertEqual(_call(out)["result"],
                         {"data": None, "size": 100})

    def test_n_zero_reads_nothing(self):
        out = _run(n=0, read_script=[{"ok": False, "bytes": "",
                                       "state": "ff"}])
        kinds = [k for k, _ in out["events"]]
        self.assertNotIn("file_read", kinds)
        self.assertNotIn("request_token", kinds)
        self.assertEqual(_call(out)["result"],
                         {"data": "scratch", "size": 0})
        self.assertEqual(_call(out)["return_status"]["code"], 0)

    def test_short_read_breaks_with_bytes_so_far(self):
        out = _run(read_script=m._ok_script([50], 4))
        self.assertEqual(_call(out)["result"],
                         {"data": "scratch", "size": 50})
        self.assertEqual(_events(out, "loop_break")[0]["reason"],
                         "short_read")

    def test_error_read_keeps_bytes_and_returns_status(self):
        out = _run(read_script=[{"ok": False,
                                 "bytes": m._bytes(40, 5).hex(),
                                 "state": "deadbeef",
                                 "status": {"code": 2, "subcode": 3,
                                            "severity": 1,
                                            "retryable": 1,
                                            "data_loss": 0,
                                            "scope": 2}}])
        call = _call(out)
        self.assertEqual(call["return_status"]["code"], 2)
        # The sret move drops subcode (+2) and scope (+6).
        self.assertEqual(call["return_status"]["subcode"], 0)
        self.assertIsNone(call["return_status"]["scope"])
        self.assertEqual(call["return_status"]["severity"], 1)
        self.assertEqual(call["return_status"]["state"], "deadbeef")
        self.assertEqual(call["result"], {"data": "scratch", "size": 40})
        self.assertEqual(_events(out, "loop_break")[0]["reason"],
                         "status_not_ok")

    def test_multi_chunk_read_loops_until_n(self):
        # A limiter caps `allowed` below n, so each chunk returns
        # exactly `allowed` bytes and the loop continues.
        out = _run(n=300, priority=m.IO_LOW,
                   rate_limiter=[100, 100, 100],
                   read_script=m._ok_script([100, 100, 100], 6))
        self.assertEqual(_call(out)["result"],
                         {"data": "scratch", "size": 300})
        self.assertEqual(len(_events(out, "file_read")), 3)

    def test_second_chunk_status_state_frees_the_first(self):
        out = _run(n=200, priority=m.IO_LOW,
                   rate_limiter=[100, 100],
                   read_script=[{"ok": True,
                                 "bytes": m._bytes(100, 12).hex(),
                                 "state": "11111111"},
                                {"ok": True,
                                 "bytes": m._bytes(100, 13).hex(),
                                 "state": "22222222"}])
        self.assertEqual(_call(out)["return_status"]["state"],
                         "22222222")
        self.assertIn(["prev_status_state_freed", True],
                      out["events"])

    def test_rate_limiter_caps_each_chunk(self):
        out = _run(n=300, priority=m.IO_LOW,
                   rate_limiter=[100, 100, 100],
                   read_script=m._ok_script([100, 100, 100], 14))
        tokens = _events(out, "request_token")
        self.assertEqual([t["bytes"] for t in tokens],
                         [300, 200, 100])
        self.assertEqual([t["allowed"] for t in tokens],
                         [100, 100, 100])

    def test_io_total_bypasses_the_limiter(self):
        out = _run(n=300, priority=m.IO_TOTAL, rate_limiter=[1, 1, 1],
                   read_script=m._ok_script([300], 16))
        kinds = [k for k, _ in out["events"]]
        self.assertNotIn("request_token", kinds)
        self.assertEqual(_events(out, "rate_bypass")[0]["reason"],
                         "priority_is_io_total")

    def test_offset_never_moves_without_listeners(self):
        out = _run(n=200, offset=5000, listeners=[],
                   read_script=m._ok_script([100, 100], 21))
        self.assertEqual(out["offset_after"], 5000)

    def test_offset_advances_per_chunk_with_listeners(self):
        out = _run(n=200, offset=5000, listeners=[True],
                   priority=m.IO_LOW, rate_limiter=[100, 100],
                   read_script=m._ok_script([100, 100], 22))
        self.assertEqual(out["offset_after"], 5200)
        self.assertEqual(len(out["listener_calls"][0]), 2)
        self.assertEqual(out["listener_calls"][0][0]["offset"], 5000)
        self.assertEqual(out["listener_calls"][0][1]["offset"], 5100)

    def test_base_noop_listener_is_skipped(self):
        out = _run(n=100, listeners=[False],
                   read_script=m._ok_script([100], 24))
        self.assertEqual(out["listener_calls"][0], [])
        self.assertEqual(len(_events(out, "notify_skip_base")), 1)

    def test_tracer_selection(self):
        for tracer, selected in ((None, "raw"),
                                 ({"tracing_enabled": False}, "raw"),
                                 ({"tracing_enabled": True}, "wrapper")):
            out = _run(io_tracer=tracer,
                       read_script=m._ok_script([100], 18))
            self.assertEqual(
                _events(out, "file_select")[0]["selected"], selected)


class DirectPathTests(unittest.TestCase):
    def _direct(self, **kw):
        p = {"n": 100, "use_direct_io": True, "alignment": 4096,
             "priority": m.IO_TOTAL,
             "positioned_script": m._ok_script([4096], 31)}
        p.update(kw)
        return _run(**p)

    def test_full_window_read_returns_n(self):
        out = self._direct(n=4096, offset=0)
        self.assertEqual(_call(out)["result"],
                         {"data": "scratch", "size": 4096})
        self.assertEqual(_call(out)["offset_after"], 4096)
        self.assertEqual(out["iostats_bytes_read"], 4096)

    def test_alignment_math(self):
        out = self._direct(n=100, offset=4097)
        math = _events(out, "align_math")[0]
        self.assertEqual(math["aligned_offset"], 4096)
        self.assertEqual(math["offset_advance"], 1)
        self.assertEqual(math["size"], 4096)
        self.assertEqual(math["capacity"], 4096)
        self.assertEqual(math["raw_alloc"], 8192)
        self.assertEqual(_call(out)["result"],
                         {"data": "scratch", "size": 100})

    def test_offset_advances_by_n_up_front(self):
        out = self._direct(n=4096, offset=10000, listeners=[])
        self.assertEqual(_events(out, "offset_advance")[0]["by"], 4096)
        # No listeners: no further advance.
        self.assertEqual(out["offset_after"], 14096)

    def test_offset_double_advance_with_listeners(self):
        out = self._direct(n=4096, offset=10000, listeners=[True])
        # n up front + tmp.size() per PositionedRead.
        self.assertEqual(out["offset_after"], 10000 + 4096 + 4096)

    def test_short_read_still_memcpys_what_was_read(self):
        out = self._direct(n=4096, offset=0,
                           positioned_script=m._ok_script([100], 38))
        self.assertEqual(_call(out)["result"],
                         {"data": "scratch", "size": 100})
        self.assertEqual(_events(out, "memcpy")[0]["bytes"], 100)

    def test_short_read_below_offset_advance_copies_nothing(self):
        out = self._direct(n=4096, offset=4095,
                           positioned_script=m._ok_script([100], 40))
        self.assertEqual(_call(out)["result"],
                         {"data": "scratch", "size": 0})
        self.assertEqual(_events(out, "memcpy"), [])

    def test_error_read_copies_nothing_but_advances_offset(self):
        out = self._direct(n=4096, offset=4096,
                           positioned_script=[{"ok": False,
                                              "bytes": m._bytes(100, 41).hex(),
                                              "state": "dead",
                                              "status": {"code": 1,
                                                         "severity": 1}}])
        call = _call(out)
        self.assertEqual(call["return_status"]["code"], 1)
        self.assertEqual(call["result"], {"data": "scratch", "size": 0})
        self.assertEqual(call["offset_after"], 4096 + 4096)
        self.assertEqual(_events(out, "memcpy"), [])

    def test_n_zero_allocates_nothing_and_reads_nothing(self):
        out = self._direct(n=0, offset=4096,
                           positioned_script=[{"ok": False, "bytes": "",
                                              "state": "ff"}])
        kinds = [k for k, _ in out["events"]]
        self.assertNotIn("positioned_read", kinds)
        self.assertEqual(_call(out)["result"],
                         {"data": "scratch", "size": 0})
        self.assertEqual(_call(out)["offset_after"], 4096)


class SequenceTests(unittest.TestCase):
    def test_buffered_reads_accumulate_offset_only_with_listeners(self):
        for listeners, expected in (([], 0), ([True], 300)):
            out = _run(n=100, calls=3, offset=0, listeners=listeners,
                       read_script=m._ok_script([100, 100, 100], 60))
            self.assertEqual(out["offset_after"], expected)

    def test_error_then_success_has_no_sticky_state(self):
        out = _run(n=100, calls=2,
                   read_script=[{"ok": False,
                                 "bytes": m._bytes(10, 62).hex(),
                                 "state": "aa",
                                 "status": {"code": 1}},
                                {"ok": True,
                                 "bytes": m._bytes(100, 63).hex(),
                                 "state": None}])
        self.assertEqual(
            [c["return_status"]["code"] for c in out["calls_out"]],
            [1, 0])
        self.assertEqual(out["calls_out"][1]["result"]["size"], 100)

    def test_direct_reads_accumulate_offset_by_n_per_call(self):
        out = _run(n=100, calls=3, use_direct_io=True,
                   alignment=4096, offset=0, listeners=[],
                   positioned_script=m._ok_script([4096, 4096, 4096], 64))
        self.assertEqual(out["offset_after"], 300)


class BindingsTests(unittest.TestCase):
    def test_functions_tsv_matches_binary_and_census(self):
        rows = list(open(PACKET / "functions.tsv"))[1:]
        self.assertEqual(len(rows), 2)
        data = BIN.read_bytes()
        by_start = {r["start"]: r
                    for r in json.load(open(CENSUS))["records"]}
        for row in rows:
            cols = row.rstrip("\n").split("\t")
            start, end = int(cols[1], 16), int(cols[2], 16)
            body = data[m._vaddr_to_offset(start):m._vaddr_to_offset(end)]
            self.assertEqual(hashlib.sha256(body).hexdigest(), cols[4])
            if cols[0].endswith("(.cold)"):
                self.assertEqual(cols[4],
                                 "a9bc64e39b97b3441ad2400bda9e561fcd87f31e613fa5dee3badce60863e867")
                self.assertEqual(cols[5],
                                 "3a799780cc7fa290d6ca4836f9a7a2a746bb33228f2f79d0b858293c2bd863e8")
            else:
                self.assertEqual(cols[4],
                                 "95a9f1f1e426f0f8fac5cb1cc8076c5cada53ace93a9f59506ddbe9b9027c3ea")
                self.assertEqual(cols[5], "")
                self.assertEqual(cols[8], "none")
                self.assertIsNone(by_start.get(start))

    def test_caller_census(self):
        census = json.load(open(PACKET / "census.json"))
        self.assertEqual(census["validated_sites"], 5)
        self.assertEqual(census["targets"]["0x6048e00"]["calls"], 5)
        self.assertEqual(census["targets"]["0x6048e00"]["jumps"], 0)
        self.assertEqual(census["targets"]["0x6048e00"]["lea_refs"], 0)
        sites = [l.split("\t") for l in
                 open(PACKET / "callers.tsv").read().splitlines()[1:]]
        by_site = {row[3]: row for row in sites}
        self.assertEqual(by_site["0x5f01997"][4], "0x5f018d0")
        self.assertEqual(by_site["0x5f02a87"][4], "0x5f02980")
        self.assertEqual(by_site["0x603b843"][4], "0x603ae70")
        self.assertEqual(by_site["0x60d4dc7"][4], "0x60d4cf0")

    def test_reader_layout_pins_the_observed_fields(self):
        layout = {n: (o, s) for n, o, s in m.READER_LAYOUT}
        self.assertEqual(layout["file_name_"], (0x00, 32))
        self.assertEqual(layout["file_"], (0x20, 96))
        self.assertEqual(layout["file_.io_tracer_"], (0x20, 16))
        self.assertEqual(layout["file_.fs_tracer_"], (0x30, 80))
        self.assertEqual(layout["file_.fs_tracer_.target_"], (0x38, 8))
        self.assertEqual(layout["offset_"], (0x80, 8))
        self.assertEqual(layout["listeners_"], (0x88, 24))
        self.assertEqual(layout["rate_limiter_"], (0xA0, 8))
        self.assertEqual(layout["size"], (0x00, 0xA8))

    def test_cold_reloc_targets_pin_the_engine_callees(self):
        data = BIN.read_bytes()
        by_start = {r["start"]: r
                    for r in json.load(open(CENSUS))["records"]}
        rec = by_start[0x6048D68]
        targets = {}
        for rel in rec["relocations"]:
            o, w = rel["offset"], rel["width"]
            site = 0x6048D68 + o
            disp = struct.unpack_from("<i", data,
                                      m._vaddr_to_offset(site))[0]
            targets[o] = site + w + disp
        self.assertEqual(targets[10], 0x63F0DC0)    # PLT _ZdaPv
        self.assertEqual(targets[47], 0x63F0A50)    # PLT _Unwind_Resume
        self.assertEqual(targets[68], 0x63F0D70)    # PLT __stack_chk_fail
        self.assertEqual(targets[105], 0x5D36110)   # _Hashtable dtor
        self.assertEqual(targets[116], 0x5D36110)   # _Hashtable dtor
        self.assertEqual(rec["target_body_sha256"],
                         "a9bc64e39b97b3441ad2400bda9e561fcd87f31e613fa5dee3badce60863e867")

    def test_main_fde_bytes_pin_the_model(self):
        data = BIN.read_bytes()
        base = m._vaddr_to_offset(0x6048E00)
        # endbr64 prologue, first byte 0xf3.
        self.assertEqual(data[base], 0xF3)
        # The scratch bump: add BYTE PTR [rax],0x1 at 0x6049784.
        bump = m._vaddr_to_offset(0x6049784)
        self.assertEqual(data[bump:bump + 3], bytes([0x80, 0x00, 0x01]))
        # The IOOptions merged immediate 0x400000000 at 0x6049012.
        imm = m._vaddr_to_offset(0x6049012)
        self.assertEqual(data[imm:imm + 10], bytes.fromhex("48ba0000000004000000"))
        # The empty-string literal 0x4376fd is 0x00.
        self.assertEqual(data[m._vaddr_to_offset(0x4376FD)], 0x00)
        # The last instruction jumps into the .cold pads.
        tail = data[m._vaddr_to_offset(0x60497F8):
                    m._vaddr_to_offset(0x60497FD)]
        self.assertEqual(tail, bytes.fromhex("e9e5f5ffff"))

    def test_live_engine_check(self):
        result = m.live_engine_check()
        self.assertTrue(result["buffered_ok"])
        self.assertTrue(result["direct_ok"])
        self.assertTrue(result["scratch_bump_observed"])
        self.assertEqual(result["empty_literal_byte_0x4376fd"], "0x00")


if __name__ == "__main__":
    unittest.main()
