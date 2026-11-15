"""Tests for the node #115 rocksdb::SequentialFileReader::
NewReadaheadSequentialFile model.

Replays all 2,400 cases in cases.tsv through the tool, then checks
the model's key behaviours directly: the gate (alignment >=
readahead_size takes the move path, returning the same file and
nulling the input; equality moves; readahead 0 moves), the wrap
path (the second alignment call supplies the layout; readahead_size_
is Roundup(readahead, alignment); the buffer is new char[capacity +
alignment] with bufstart_ aligned; the object is 0x80 bytes with
the vtable 0x64d1d80), the rounding (Roundup and AlignUp tables,
including non-powers of two), the .cold cleanup record (the LSDA's
three call-site entries and the two landing pads), the caller
census (four calls, from RecoverLogFiles, MaybeInitLogReader, the
readahead ctor and Parse; 0 jumps, 0 LEA refs), the FDE body and
source hashes, the vtable slots, and the live engine check (real
files wrapped by the model).
"""

import hashlib
import json
import re
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import sequential_file_reader_new_readahead115 as m

PACKET = (Path(__file__).resolve().parents[1] / "research" / "work-items"
          / "re-002-node115-sequential-file-reader-new-readahead-115")
BIN = Path(__file__).resolve().parents[1] / "artifacts" / "node" / "115" / "hl-node"
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
CENSUS = (Path(__file__).resolve().parents[1] / "research" / "work-items"
          / "RE-002-node115-vendor-census" / "census.json")


def _read_cases():
    rows = []
    with open(PACKET / "cases.tsv") as fh:
        header = fh.readline().rstrip("\n").split("\t")
        for line in fh:
            rows.append(dict(zip(header, line.rstrip("\n").split("\t"))))
    return rows


def _va2off(va):
    out = subprocess.check_output(["readelf", "-lW", str(BIN)]).decode()
    for line in out.splitlines():
        p = line.split()
        if p and p[0] == "LOAD":
            v, o, f = int(p[2], 16), int(p[1], 16), int(p[4], 16)
            if v <= va < v + f:
                return o + (va - v)
    raise ValueError(hex(va))


class ReplayTests(unittest.TestCase):
    def test_case_count(self):
        rows = _read_cases()
        self.assertEqual(len(rows), 2400)
        groups = {}
        for r in rows:
            groups[r["group"]] = groups.get(r["group"], 0) + 1
        self.assertEqual(groups, {"gate": 600, "rounding": 600,
                                  "layout": 600, "bindings": 600})

    def test_replay_all(self):
        for row in _read_cases():
            inputs = json.loads(row["inputs_json"])
            expected = json.loads(row["expected_json"])
            self.assertEqual(m.run_case(inputs), expected, row["case_id"])

    def test_case_ids_unique(self):
        rows = _read_cases()
        self.assertEqual(len({r["case_id"] for r in rows}), 2400)

    def test_wrapped_invariants(self):
        for row in _read_cases():
            expected = json.loads(row["expected_json"])
            if not expected.get("wrapped"):
                continue
            obj = expected["object"]
            a = obj["alignment_"]
            self.assertEqual(obj["readahead_size_"] % a, 0,
                             row["case_id"])
            self.assertEqual(obj["buffer_capacity_"],
                             obj["readahead_size_"], row["case_id"])
            self.assertEqual(obj["buffer_buf_size"],
                             obj["buffer_capacity_"] + a, row["case_id"])
            # bufstart_ is a true multiple of the alignment only
            # when the alignment is a power of two (the upstream
            # contract); otherwise the binary's mask formula is
            # reproduced exactly.
            base = int(expected["alloc_base"], 16)
            if a & (a - 1) == 0:
                self.assertEqual(int(obj["buffer_bufstart"], 16) % a, 0,
                                 row["case_id"])
                self.assertGreaterEqual(
                    obj["buffer_bufstart_offset"], 0, row["case_id"])
            else:
                self.assertEqual(int(obj["buffer_bufstart"], 16),
                                 (base + a - 1) & -a, row["case_id"])
            self.assertLess(obj["buffer_bufstart_offset"], a,
                            row["case_id"])
            self.assertEqual(obj["buffer_cursize_"], 0, row["case_id"])
            self.assertEqual(obj["buffer_offset_"], 0, row["case_id"])
            self.assertEqual(obj["read_offset_"], 0, row["case_id"])
            self.assertEqual(obj["size"], 0x80, row["case_id"])
            self.assertEqual(obj["vtable"], "0x64d1d80", row["case_id"])
            self.assertEqual(expected["alignment_calls"], 2,
                             row["case_id"])

    def test_move_invariants(self):
        for row in _read_cases():
            expected = json.loads(row["expected_json"])
            if expected.get("wrapped") is not False:
                continue
            self.assertGreaterEqual(
                expected["alignment_gate"],
                expected["readahead_size"], row["case_id"])
            self.assertTrue(expected["input_null_after"], row["case_id"])
            self.assertEqual(expected["alignment_calls"], 1,
                             row["case_id"])

    def test_error_rows_are_zero_alignment(self):
        for row in _read_cases():
            expected = json.loads(row["expected_json"])
            if "error" not in expected:
                continue
            self.assertEqual(expected["error"], "ZeroDivisionError")
            inputs = json.loads(row["inputs_json"])
            self.assertEqual(inputs["alignment"], 0, row["case_id"])
            self.assertGreater(inputs["readahead_size"], 0,
                               row["case_id"])


class GateTests(unittest.TestCase):
    def _run(self, alignment, readahead, alignment2=None):
        f = m.FakeFSSequentialFile("f", alignment, alignment2=alignment2)
        return m.new_readahead_sequential_file(f, readahead), f

    def test_equal_alignment_moves(self):
        res, f = self._run(4096, 4096)
        self.assertFalse(res["wrapped"])
        self.assertEqual(res["out_file_id"], "f")
        self.assertIsNone(f.ptr)

    def test_greater_alignment_moves(self):
        res, _ = self._run(8192, 4096)
        self.assertFalse(res["wrapped"])
        self.assertEqual(res["out_file_id"], "f")

    def test_zero_readahead_moves(self):
        res, _ = self._run(4096, 0)
        self.assertFalse(res["wrapped"])

    def test_one_more_wraps(self):
        res, _ = self._run(4096, 4097)
        self.assertTrue(res["wrapped"])
        self.assertEqual(res["object"]["readahead_size_"], 8192)

    def test_gate_uses_first_call_only(self):
        # A lying file: gate sees 4096 (move), even though the
        # second call would report 1.
        res, f = self._run(4096, 4096, alignment2=1)
        self.assertFalse(res["wrapped"])
        self.assertEqual(len(f.calls), 1)

    def test_layout_uses_second_call(self):
        res, f = self._run(4096, 8192, alignment2=512)
        self.assertTrue(res["wrapped"])
        self.assertEqual(res["alignment_gate"], 4096)
        self.assertEqual(res["alignment_ctor"], 512)
        self.assertEqual(res["object"]["alignment_"], 512)
        self.assertEqual(len(f.calls), 2)


class RoundingTests(unittest.TestCase):
    def test_roundup_examples(self):
        self.assertEqual(m.roundup(13, 5), 15)
        self.assertEqual(m.roundup(201, 16), 208)
        self.assertEqual(m.roundup(4097, 4096), 8192)
        self.assertEqual(m.roundup(4096, 4096), 4096)
        self.assertEqual(m.roundup(0, 4096), 0)
        self.assertEqual(m.roundup(100, 1), 100)

    def test_roundup_zero_alignment_faults(self):
        with self.assertRaises(ZeroDivisionError):
            m.roundup(1, 0)

    def test_align_up_examples(self):
        self.assertEqual(m.align_up(0x100000001, 4096), 0x100001000)
        self.assertEqual(m.align_up(0x100000000, 4096), 0x100000000)
        self.assertEqual(m.align_up(0x1000, 1), 0x1000)

    def test_alloc_size_is_capacity_plus_alignment(self):
        f = m.FakeFSSequentialFile("f", 512)
        res = m.new_readahead_sequential_file(f, 1000)
        obj = res["object"]
        self.assertEqual(obj["readahead_size_"], 1024)
        self.assertEqual(obj["buffer_capacity_"], 1024)
        self.assertEqual(obj["buffer_buf_size"], 1024 + 512)


class LayoutTests(unittest.TestCase):
    def test_layout_offsets(self):
        self.assertEqual(m.LAYOUT, {
            "vptr": 0x00, "file_": 0x08, "alignment_": 0x10,
            "readahead_size_": 0x18, "lock_": 0x20,
            "buffer_alignment_": 0x48, "buffer_buf_": 0x50,
            "buffer_capacity_": 0x58, "buffer_cursize_": 0x60,
            "buffer_bufstart_": 0x68, "buffer_offset_": 0x70,
            "read_offset_": 0x78,
        })

    def test_object_size(self):
        self.assertEqual(m.OBJECT_SIZE, 0x80)

    def test_vtable_slots(self):
        self.assertEqual(m.VTABLE_SLOTS, {
            "0x64d1d80": "0x6048640",
            "0x64d1d88": "0x6048680",
            "0x64d1d90": "0x60486f0",
            "0x64d1d98": "0x6048ac0",
            "0x64d1da0": "0x6048630",
            "0x64d1da8": "0x6025720",
            "0x64d1db0": "0x60489e0",
            "0x64d1db8": "0x60485e0",
        })

    def test_default_alignment_is_4096(self):
        # The inherited FSSequentialFile::GetRequiredBufferAlignment
        # (0x6025720) is `mov $0x1000, %eax; ret`.
        data = open(BIN, "rb").read()
        off = _va2off(0x6025720)
        # endbr64; mov $0x1000, %eax; ret
        self.assertEqual(data[off:off + 10],
                         bytes.fromhex("f30f1efab800100000c3"))
        self.assertEqual(m.KDEFAULTPAGESIZE, 4096)


class ColdTests(unittest.TestCase):
    def test_lsda_sites(self):
        self.assertEqual(len(m.LSDA_SITES), 3)
        self.assertIsNone(m.LSDA_SITES[0]["landing_pad"])
        self.assertEqual(m.LSDA_SITES[1]["landing_pad"], "0x6048d5b")
        self.assertEqual(m.LSDA_SITES[2]["landing_pad"], "0x6048d4f")

    def test_cold_cleanup_orders(self):
        full = m.cold_cleanup(True, True)
        self.assertEqual(full[0], "delete[] buffer_.buf_ (+0x50)")
        self.assertIn("virtual-delete file_", full[1])
        partial = m.cold_cleanup(False, True)
        self.assertTrue(partial[0].startswith("virtual-delete file_"))

    def test_cold_stubs_jump_into_cold(self):
        # The two endbr64 stubs at the main FDE tail save the
        # exception in rbp and jump into .cold.
        data = open(BIN, "rb").read()
        stub1 = data[_va2off(0x6048d4f):_va2off(0x6048d5b)]
        self.assertEqual(stub1, bytes.fromhex("f30f1efa4889c5e9a3feffff"))
        stub2 = data[_va2off(0x6048d5b):_va2off(0x6048d67)]
        self.assertEqual(stub2, bytes.fromhex("f30f1efa4889c5e9a5feffff"))


class CensusTests(unittest.TestCase):
    def test_caller_sites(self):
        sites = []
        with open(PACKET / "callers.tsv") as fh:
            header = fh.readline().rstrip("\n").split("\t")
            for line in fh:
                sites.append(dict(zip(header, line.rstrip("\n")
                                      .split("\t"))))
        self.assertEqual(len(sites), 4)
        self.assertEqual({s["site"] for s in sites},
                         {"0x5e6a40a", "0x5e7fcff", "0x5f7569f",
                          "0x60cfec4"})
        self.assertTrue(all(s["kind"] == "call" for s in sites))

    def test_fde_hashes(self):
        data = open(BIN, "rb").read()
        self.assertEqual(hashlib.sha256(data).hexdigest(), DIGEST)
        census = json.load(open(CENSUS))["records"]
        by_start = {r["start"]: r for r in census}
        for start, end in ((0x6048C30, 0x6048D67),
                           (0x6048BFE, 0x6048C30)):
            body = data[_va2off(start):_va2off(end)]
            rec = by_start[start]
            self.assertEqual(hashlib.sha256(body).hexdigest(),
                             rec["target_body_sha256"])
            zeroed = bytearray(body)
            for rel in rec["relocations"]:
                o, w = rel["offset"], rel["width"]
                zeroed[o:o + w] = b"\x00" * w
            self.assertEqual(hashlib.sha256(bytes(zeroed)).hexdigest(),
                             rec["source_body_sha256"])

    def test_vtable_lea_target(self):
        # lea 0x4890e8(%rip),%rax at 0x6048c91 loads the vtable.
        data = open(BIN, "rb").read()
        off = _va2off(0x6048C91)
        self.assertEqual(data[off:off + 3], bytes.fromhex("488d05"))
        disp = int.from_bytes(data[off + 3:off + 7], "little",
                              signed=True)
        self.assertEqual(0x6048C98 + disp, 0x64D1D80)

    def test_gate_call_is_vtable_slot_5(self):
        # call *0x28(%rax) at 0x6048c4d: GetRequiredBufferAlignment.
        data = open(BIN, "rb").read()
        off = _va2off(0x6048C4D)
        self.assertEqual(data[off:off + 3], bytes.fromhex("ff5028"))


class LiveTests(unittest.TestCase):
    def test_live_engine_check(self):
        ok, report = m.live_engine_check()
        self.assertTrue(ok, report)
        self.assertEqual(len(report["legs"]), 9)
