"""Tests for the node #115 rocksdb::DBImpl::CreateWAL model.

Replays all 2,400 cases in cases.tsv through the tool, then checks
the model's key behaviours directly: the LogFileName rule
(wal_dir + "/" + "%06llu" % n + ".log", never truncated), the
GetWalDir fallback (empty wal_dir -> dbname), the fs selection
(raw fs_ unless the tracer is present AND its +0x68 byte is set),
the recycle branch (old log renamed to the new name, both
TEST_SYNC_POINTs absent from the binary), the open-failure return
(status propagated, no writer built, *new_log untouched), the
AddCompressionTypeRecord failure (*new_log already assigned, the
failure status returned), the WritableFileWriter params (both
trailing bools are checksum_handoff_file_types.Contains(kWalFile),
bit 0 of this+0x520), the log::Writer params (the recycle flag
comes from the immutable recycle_log_file_num, NOT from the
recycle_log_number argument), the dead Close guard (the
file_writer slot is nulled by the log::Writer ctor's move, so the
guard is never taken), the caller census (two calls, from
DBImpl::Open and DBImpl::SwitchMemtable; one tail jump into
.cold), the FDE body hashes, and the live engine check (real
files created/renamed by the model match the model image).
"""

import hashlib
import json
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import dbimpl_createwal115 as m

PACKET = (Path(__file__).resolve().parents[1] / "research" / "work-items"
          / "re-002-node115-dbimpl-createwal-115")
BIN = Path(__file__).resolve().parents[1] / "artifacts" / "node" / "115" / "hl-node"
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"


def _read_cases():
    rows = []
    with open(PACKET / "cases.tsv") as fh:
        header = fh.readline().rstrip("\n").split("\t")
        for line in fh:
            rows.append(dict(zip(header, line.rstrip("\n").split("\t"))))
    return rows


def _state(db_over=None, fs=None, script=None):
    db = {"dbname": "/tmp/db", "wal_dir": "", "recycle_log_file_num": 0,
          "manual_wal_flush": False, "wal_compression": 0,
          "checksum_handoff_bits": 0, "listeners": [],
          "clock": "default", "io_tracer_present": False,
          "io_tracer_enabled": False, "file_options": {}}
    db.update(db_over or {})
    return m.DBState(
        dbname=db["dbname"], wal_dir=db["wal_dir"],
        recycle_log_file_num=db["recycle_log_file_num"],
        manual_wal_flush=db["manual_wal_flush"],
        wal_compression=db["wal_compression"],
        checksum_handoff_bits=db["checksum_handoff_bits"],
        listeners=db["listeners"], clock=db["clock"],
        io_tracer_present=db["io_tracer_present"],
        io_tracer_enabled=db["io_tracer_enabled"],
        file_options=db["file_options"],
        fs=fs if fs is not None else m.FakeFS(),
        script=script or {})


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
        self.assertEqual(groups, {"gate": 600, "filenames": 600,
                                  "writer_params": 600, "bindings": 600})

    def test_replay_all(self):
        for row in _read_cases():
            inputs = json.loads(row["inputs_json"])
            expected = json.loads(row["expected_json"])
            self.assertEqual(m.run_case(inputs), expected, row["case_id"])

    def test_case_ids_unique(self):
        rows = _read_cases()
        self.assertEqual(len({r["case_id"] for r in rows}), 2400)

    def test_close_guard_never_taken(self):
        for row in _read_cases():
            expected = json.loads(row["expected_json"])
            self.assertFalse(expected["close_guard_taken"], row["case_id"])

    def test_new_log_assigned_iff_open_ok(self):
        for row in _read_cases():
            inputs = json.loads(row["inputs_json"])
            expected = json.loads(row["expected_json"])
            open_ok = not any(
                e.get("op") == "open_status" and e.get("code") != 0
                for e in expected["trace"])
            self.assertEqual(expected["new_log_assigned"], open_ok,
                             row["case_id"])


class FilenameTests(unittest.TestCase):
    def test_log_file_name(self):
        self.assertEqual(m.log_file_name("/tmp/wal", 7),
                         "/tmp/wal/000007.log")
        self.assertEqual(m.log_file_name("/tmp/wal", 0),
                         "/tmp/wal/000000.log")
        self.assertEqual(m.log_file_name("/tmp/wal", 999999),
                         "/tmp/wal/999999.log")
        # %06llu never truncates: 7 digits print in full.
        self.assertEqual(m.log_file_name("/tmp/wal", 1000000),
                         "/tmp/wal/1000000.log")
        self.assertEqual(m.log_file_name("/tmp/wal", 123456789),
                         "/tmp/wal/123456789.log")

    def test_empty_wal_dir_joins_slash(self):
        # The join is unconditional: wal_dir "" gives "/000007.log".
        self.assertEqual(m.log_file_name("", 7), "/000007.log")

    def test_get_wal_dir(self):
        self.assertEqual(m.get_wal_dir("/tmp/db", ""), "/tmp/db")
        self.assertEqual(m.get_wal_dir("/tmp/db", "/tmp/wal"), "/tmp/wal")
        self.assertEqual(m.get_wal_dir("db", "wal"), "wal")


class FsSelectionTests(unittest.TestCase):
    def test_raw_when_no_tracer(self):
        self.assertEqual(_state().select_fs(), "raw")

    def test_raw_when_tracer_disabled(self):
        st = _state({"io_tracer_present": True,
                     "io_tracer_enabled": False})
        self.assertEqual(st.select_fs(), "raw")

    def test_wrapped_when_tracer_enabled(self):
        st = _state({"io_tracer_present": True,
                     "io_tracer_enabled": True})
        self.assertEqual(st.select_fs(), "wrapped")

    def test_selection_recorded_in_trace(self):
        st = _state({"io_tracer_present": True,
                     "io_tracer_enabled": True})
        m.create_wal(st, 1, 0, 0)
        self.assertIn({"op": "select_fs", "selected": "wrapped"},
                      st.trace)


class GateTests(unittest.TestCase):
    def test_new_path_calls_new_writable_file(self):
        fs = m.FakeFS()
        st = _state(fs=fs)
        s = m.create_wal(st, 7, 0, 4096)
        self.assertTrue(s.is_ok())
        self.assertEqual([c["op"] for c in fs.calls],
                         ["optimize_for_log_write", "new_writable_file"])
        self.assertEqual(fs.calls[1]["fname"], "/tmp/db/000007.log")

    def test_recycle_path_calls_reuse_and_logs(self):
        fs = m.FakeFS(files={"/tmp/db/000003.log": b"old"})
        st = _state(fs=fs)
        s = m.create_wal(st, 9, 3, 0)
        self.assertTrue(s.is_ok())
        self.assertEqual(fs.calls[1]["op"], "reuse_writable_file")
        self.assertEqual(fs.calls[1]["old_fname"], "/tmp/db/000003.log")
        self.assertEqual(fs.calls[1]["new_fname"], "/tmp/db/000009.log")
        self.assertEqual(fs.files, {"/tmp/db/000009.log": b"old"})
        self.assertIn({"op": "log_info",
                       "msg": "reusing log 3 from recycle list"},
                      st.trace)

    def test_sync_points_absent_from_binary(self):
        st = _state(fs=m.FakeFS(files={"/tmp/db/000003.log": b""}))
        m.create_wal(st, 9, 3, 0)
        points = [e for e in st.trace if e["op"] == "sync_point"]
        self.assertEqual(len(points), 2)
        self.assertTrue(all(e["present_in_binary"] is False
                            for e in points))

    def test_open_failure_returns_status_no_writer(self):
        fs = m.FakeFS(script={"new_writable_file":
                              m.IOStatus.io_error("disk full")})
        st = _state(fs=fs)
        s = m.create_wal(st, 5, 0, 0)
        self.assertFalse(s.is_ok())
        self.assertEqual(s.code, 5)
        self.assertIsNone(st.new_log[0])
        self.assertEqual(fs.files, {})

    def test_reuse_missing_old_fails(self):
        st = _state(fs=m.FakeFS())
        s = m.create_wal(st, 8, 3, 0)
        self.assertFalse(s.is_ok())
        self.assertEqual(s.code, 5)
        self.assertIsNone(st.new_log[0])

    def test_compression_record_failure_keeps_writer(self):
        st = _state(script={"add_compression_type_record":
                            m.IOStatus.io_error("record failed")})
        s = m.create_wal(st, 11, 0, 0)
        self.assertFalse(s.is_ok())
        self.assertEqual(s.code, 5)
        # *new_log is assigned BEFORE the call in the binary.
        self.assertIsNotNone(st.new_log[0])
        self.assertFalse(any(e.get("op") == "close_guard"
                             and e.get("taken") for e in st.trace))

    def test_lifetime_hint_constant_two(self):
        fs = m.FakeFS()
        st = _state(fs=fs)
        m.create_wal(st, 1, 0, 8192)
        handle = fs.files  # the handle is not kept; check the trace
        self.assertIn({"op": "set_write_lifetime_hint", "hint": 2},
                      st.trace)
        self.assertIn({"op": "set_preallocation_block_size",
                       "size": 8192}, st.trace)


class WriterParamsTests(unittest.TestCase):
    def test_handoff_bit_clear(self):
        st = _state({"checksum_handoff_bits": 0})
        m.create_wal(st, 1, 0, 0)
        p = st.new_log[0].params
        self.assertIs(p["perform_data_verification"], False)
        self.assertIs(p["buffered_data_with_checksum"], False)

    def test_handoff_bit_set(self):
        st = _state({"checksum_handoff_bits": 1})
        m.create_wal(st, 1, 0, 0)
        p = st.new_log[0].params
        self.assertIs(p["perform_data_verification"], True)
        self.assertIs(p["buffered_data_with_checksum"], True)

    def test_handoff_bit_two_is_not_kwalfile(self):
        # Bit 0 is the kWalFile test; bit 1 alone does not set it.
        st = _state({"checksum_handoff_bits": 2})
        m.create_wal(st, 1, 0, 0)
        p = st.new_log[0].params
        self.assertIs(p["perform_data_verification"], False)

    def test_recycle_flag_from_immutable_not_argument(self):
        # recycle_log_file_num > 0 sets the flag even when the
        # recycle_log_number argument is 0.
        st = _state({"recycle_log_file_num": 3})
        m.create_wal(st, 1, 0, 0)
        self.assertIs(st.new_log[0].params["recycle"], True)
        # And a nonzero recycle argument does NOT set it when the
        # immutable option is 0.
        st = _state({"recycle_log_file_num": 0},
                    fs=m.FakeFS(files={"/tmp/db/000004.log": b""}))
        m.create_wal(st, 1, 4, 0)
        self.assertIs(st.new_log[0].params["recycle"], False)

    def test_manual_flush_and_compression_recorded(self):
        st = _state({"manual_wal_flush": True, "wal_compression": 2})
        m.create_wal(st, 1, 0, 0)
        p = st.new_log[0].params
        self.assertIs(p["manual_wal_flush"], True)
        self.assertEqual(p["wal_compression"], 2)
        self.assertEqual(p["log_number"], 1)

    def test_listeners_and_stats(self):
        st = _state({"listeners": ["L1", "L2"]})
        m.create_wal(st, 1, 0, 0)
        p = st.new_log[0].params
        self.assertEqual(p["listeners"], ["L1", "L2"])
        self.assertIsNone(p["stats"])
        self.assertIsNone(p["checksum_gen"])


class CloseGuardTests(unittest.TestCase):
    def test_guard_never_taken(self):
        for recycle in (0, 3):
            fs = m.FakeFS(files={"/tmp/db/000003.log": b""})
            st = _state(fs=fs)
            m.create_wal(st, 9, recycle, 0)
            guards = [e for e in st.trace if e["op"] == "close_guard"]
            self.assertEqual(len(guards), 1)
            self.assertIs(guards[0]["taken"], False)


class CensusTests(unittest.TestCase):
    def test_body_hashes(self):
        data = open(BIN, "rb").read()
        self.assertEqual(hashlib.sha256(data).hexdigest(), DIGEST)
        for start, end, want in (
                (0x5E5C270, 0x5E5C9A3,
                 "b880ae88e16d2303236572e99c4ff6b830f0a28f975fda43f7be504b5a36f5a1"),
                (0x5E5C1A0, 0x5E5C26E,
                 "524efe782ae066d528f239fa39712b2b81efad70fdc6b8c55212b91ace414734")):
            body = data[_va2off(start):_va2off(end)]
            self.assertEqual(hashlib.sha256(body).hexdigest(), want)

    def test_caller_census(self):
        rows = [line.rstrip("\n").split("\t")
                for line in open(PACKET / "callers.tsv")
                .read().splitlines()[1:]]
        calls = [r for r in rows if r[2] == "call"]
        self.assertEqual(len(calls), 2)
        self.assertEqual({r[3] for r in calls},
                         {"0x5e63ea0", "0x5e8a9c6"})
        self.assertEqual({r[4] for r in calls},
                         {"0x5e62c50", "0x5e8a890"})
        jumps = [r for r in rows if r[2] == "jmp"]
        self.assertEqual(len(jumps), 1)
        self.assertEqual(jumps[0][3], "0x5e5c94a")
        self.assertEqual(len([r for r in rows if r[2] == "lea"]), 0)


class LiveTests(unittest.TestCase):
    def test_live_engine_check(self):
        ok, _ = m.live_engine_check()
        self.assertTrue(ok)


if __name__ == "__main__":
    unittest.main()
