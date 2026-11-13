"""Tests for the node #115 DBImpl::SwitchMemtable model.

Replays all 2,400 cases in cases.tsv through the tool's run_case,
then checks the model's key behaviours directly: the no-create
plain loop, the create-ok record step (which runs even when logs_
was empty), the recoverable-state direct return, the CreateWAL /
WriteBuffer error paths, the recycle reuse, the min-WAL
track-and-verify branch (empty CFs contribute the new log number,
non-empty CFs their own, dropped CFs excluded), the LogAndApply
manifest failure, the preallocate formula, the Status ctor /
ToString / copy-assign rules, the throw / canary behaviour, and
the 6-site caller census.
"""

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import switch_memtable115 as m

PACKET = (Path(__file__).resolve().parents[1] / "research" / "work-items"
          / "re-002-node115-rocksdb-dbimpl-switch-memtable-115")


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
        self.assertEqual(groups, {"checks": 600, "status": 600,
                                  "throw": 600, "bindings": 600})

    def test_all_cases_replay(self):
        bad = []
        for r in _read_cases():
            inputs = json.loads(r["inputs_json"])
            expected = json.loads(r["expected_json"])
            got = m.run_case(inputs)
            if got != expected:
                bad.append(r["case_id"])
        self.assertEqual(bad, [], f"{len(bad)} cases failed: {bad[:5]}")

    def test_mode_names_match_behavior(self):
        # track-min-apply cases apply (min 9 > 5); track-min-no-apply
        # cases take the plain loop (min 3 <= 5).
        rows = {r["case_id"]: json.loads(r["expected_json"])
                for r in _read_cases()}
        self.assertIn("LogAndApply(DeleteWalsBefore 9)",
                      str(rows["checks-0013"]["effects"]))
        self.assertNotIn("LogAndApply",
                         str(rows["checks-0014"]["effects"]))


class SwitchTests(unittest.TestCase):
    def _run(self, db=None, cfs=None, oracle=None, **kw):
        db = db if db is not None else m.default_db_state()
        if cfs is not None:
            db["column_families"] = cfs
        cfd = db["column_families"][0]
        oracle = oracle if oracle is not None else m.default_oracle()
        return m.switch_memtable(db, cfd, m.default_write_context(),
                                 oracle, **kw)

    def test_defaults_ok_no_new_log(self):
        out = self._run()
        self.assertTrue(out["result"].is_ok())
        self.assertFalse(out["creating_new_log"])
        self.assertEqual(out["new_log_number"], 0)
        # The plain loop still sets the creation sequence.
        self.assertTrue(any("SetCreationSeq" in e
                            for e in out["effects"]))

    def test_create_ok_records_log(self):
        db = m.default_db_state()
        db["log_empty"] = False
        db["logs"] = [(3, m._writer(3))]
        oracle = m.default_oracle()
        oracle["create_wal"] = (m.Status.ok(), m._writer(7))
        oracle["new_file_number"] = 7
        out = self._run(db=db, oracle=oracle)
        self.assertTrue(out["result"].is_ok())
        self.assertEqual(out["db"]["logfile_number"], 7)
        self.assertEqual([n for n, _ in out["db"]["logs"]], [3, 7])
        self.assertEqual(out["db"]["alive_log_files"], [7])
        self.assertTrue(any("New memtable created with log file: #7"
                            in line["message"]
                            for line in out["log"]))

    def test_create_ok_records_log_even_when_logs_empty(self):
        db = m.default_db_state()
        db["log_empty"] = False
        db["logs"] = []
        oracle = m.default_oracle()
        oracle["create_wal"] = (m.Status.ok(), m._writer(7))
        oracle["new_file_number"] = 7
        out = self._run(db=db, oracle=oracle)
        self.assertTrue(out["result"].is_ok())
        self.assertEqual([n for n, _ in out["db"]["logs"]], [7])

    def test_recoverable_fail_returns_directly(self):
        oracle = m.default_oracle()
        oracle["recoverable_state"] = m.Status.error(
            "kIOError", "recover failed")
        out = self._run(oracle=oracle)
        self.assertEqual(out["result"].code, m.CODE["kIOError"])
        self.assertEqual(out["result"].state, "recover failed")
        self.assertFalse(any("SetBGError" in e
                             for e in out["effects"]))

    def test_create_fail_error_path(self):
        oracle = m.default_oracle()
        oracle["create_wal"] = (m.Status.error("kIOError", "wal failed"),
                                None)
        oracle["get_bg_error"] = m.Status.error(
            "kIOError", "bg: wal failed")
        db = m.default_db_state()
        db["log_empty"] = False
        out = self._run(db=db, oracle=oracle)
        self.assertEqual(out["result"].state, "bg: wal failed")
        self.assertTrue(any("SetBGError(io_s, kMemTable)" in e
                            for e in out["effects"]))
        self.assertTrue(any("return GetBGError()" in e
                            for e in out["effects"]))
        # Nothing to delete here: CreateWAL failed before the new
        # memtable was constructed and returned no writer.

    def test_write_buffer_fail_warns_with_two_spaces(self):
        oracle = m.default_oracle()
        oracle["create_wal"] = (m.Status.ok(), m._writer(7))
        oracle["write_buffer"] = m.Status.error(
            "kIOError", "write failed")
        oracle["get_bg_error"] = m.Status.error("kIOError", "bg: write")
        db = m.default_db_state()
        db["log_empty"] = False
        db["logs"] = [(3, {"file": {"seen_error": False}})]
        out = self._run(db=db, oracle=oracle)
        self.assertEqual(out["result"].state, "bg: write")
        self.assertTrue(any("from #3 to #7  WAL file" in line["message"]
                            for line in out["log"]))
        # The error path deletes the built memtable and writer.
        self.assertTrue(any("delete new_mem (MemTable dtor)" in e
                            for e in out["effects"]))
        self.assertTrue(any("delete new_log (log::Writer dtor)" in e
                            for e in out["effects"]))

    def test_recycle_reuses_front(self):
        db = m.default_db_state()
        db["log_empty"] = False
        db["logs"] = [(3, m._writer(3))]
        db["log_recycle_files"] = [5, 6]
        db["immutable"]["recycle_log_file_num"] = 2
        oracle = m.default_oracle()
        oracle["create_wal"] = (m.Status.ok(), m._writer(8))
        oracle["new_file_number"] = 8
        out = self._run(db=db, oracle=oracle)
        self.assertEqual(out["recycle_log_number"], 5)
        self.assertEqual(out["db"]["log_recycle_files"], [6])
        self.assertEqual(out["new_log_number"], 8)

    def test_min_wal_empty_cf_contributes_new_number(self):
        db = m.default_db_state()
        db["log_empty"] = False
        db["logs"] = [(3, m._writer(3))]
        db["immutable"]["track_and_verify_wals_in_manifest"] = True
        cfs = [m.default_column_family(0, "default", seq=0),
               m.default_column_family(1, "cf1", seq=0)]
        cfs[1]["log_number"] = 9
        oracle = m.default_oracle()
        oracle["create_wal"] = (m.Status.ok(), m._writer(11))
        oracle["new_file_number"] = 11
        oracle["min_wal_to_keep"] = 5
        out = self._run(db=db, cfs=cfs, oracle=oracle)
        self.assertIn("min WAL with unflushed data: 11",
                      out["effects"])
        self.assertTrue(any("LogAndApply(DeleteWalsBefore 11)" in e
                            for e in out["effects"]))

    def test_min_wal_plain_loop_when_below_threshold(self):
        db = m.default_db_state()
        db["log_empty"] = False
        db["logs"] = [(3, m._writer(3))]
        db["immutable"]["track_and_verify_wals_in_manifest"] = True
        cfs = [m.default_column_family(0, "default", seq=0),
               m.default_column_family(1, "cf1", seq=0)]
        cfs[1]["mem"]["first_seqno"] = 5
        cfs[1]["mem"]["earliest_seqno"] = 5
        cfs[1]["log_number"] = 3
        oracle = m.default_oracle()
        oracle["create_wal"] = (m.Status.ok(), m._writer(11))
        oracle["new_file_number"] = 11
        oracle["min_wal_to_keep"] = 5
        out = self._run(db=db, cfs=cfs, oracle=oracle)
        self.assertIn("min WAL with unflushed data: 3",
                      out["effects"])
        self.assertFalse(any("LogAndApply" in e
                             for e in out["effects"]))

    def test_log_and_apply_ioerror_sets_bg_error_manifest(self):
        db = m.default_db_state()
        db["log_empty"] = False
        db["logs"] = [(3, m._writer(3))]
        db["immutable"]["track_and_verify_wals_in_manifest"] = True
        cfs = [m.default_column_family(0, "default", seq=0),
               m.default_column_family(1, "cf1", seq=0)]
        cfs[1]["log_number"] = 9
        oracle = m.default_oracle()
        oracle["create_wal"] = (m.Status.ok(), m._writer(11))
        oracle["new_file_number"] = 11
        oracle["min_wal_to_keep"] = 5
        oracle["log_and_apply"] = m.Status.error(
            "kIOError", "manifest write failed")
        oracle["versions_io_status"] = m.Status.error(
            "kIOError", "manifest write failed")
        oracle["set_bg_error"] = m.Status.error(
            "kIOError", "manifest write failed")
        out = self._run(db=db, cfs=cfs, oracle=oracle)
        self.assertEqual(out["result"].code, m.CODE["kIOError"])
        self.assertTrue(any("SetBGError(io_status, kManifestWrite)" in e
                            for e in out["effects"]))

    def test_preallocate_formula(self):
        db = m.default_db_state()
        self.assertEqual(
            m.get_wal_preallocate_block_size(db, 67108864), 73819750)
        db["mutable"]["max_total_wal_size"] = 1000
        self.assertEqual(
            m.get_wal_preallocate_block_size(db, 67108864), 1000)


class StatusTests(unittest.TestCase):
    def test_ctor_state_buffer_is_msg_plus_nul(self):
        st = m.status_ctor(5, "wal failed")
        self.assertEqual(st.state_buffer(), b"wal failed\x00")
        self.assertEqual(st.state_alloc(), len("wal failed") + 1)

    def test_ctor_joins_msg2_with_colon_space(self):
        st = m.status_ctor(5, "a", "b")
        self.assertEqual(st.state, "a: b")

    def test_tostring_uses_human_phrases(self):
        st = m.Status(5, 0, 0, "wal failed")
        self.assertEqual(m.status_tostring(st), "IO error: wal failed")
        self.assertEqual(m.status_tostring(m.Status.ok()), "OK")
        self.assertEqual(
            m.status_tostring(m.Status(99, 0, 0, "x")),
            "Unknown code(99): x")

    def test_copy_assign_steals_fresh_state(self):
        out = m.run_case({"group": "status", "case_id": "t",
                          "kind": "copy-assign",
                          "status": {"code": 5, "subcode": 0,
                                     "severity": 0,
                                     "state": "create wal failed"}})
        self.assertEqual(out["status"]["code"], 5)
        self.assertEqual(out["status"]["state"], "create wal failed")

    def test_alloc_fail_raises_bad_alloc(self):
        out = m.run_case({"group": "status", "case_id": "t",
                          "kind": "alloc-fail"})
        self.assertEqual(out["error"], "BadAlloc")
        self.assertEqual(out["site"], "0x5e8b477")
        self.assertEqual(out["pad"], "0x5e8c4b8")


class ThrowTests(unittest.TestCase):
    def _throw_case(self, fail_at, **kw):
        inputs = {"group": "throw", "case_id": "t",
                  "fail_at": fail_at, "db_overrides": {
                      "log_empty": False,
                      "logs": [[3, m._writer(3)]]},
                  "oracle": {"new_file_number": 7,
                             "last_sequence": 100,
                             "create_wal": {
                                 "status": {"code": 0, "subcode": 0,
                                            "severity": 0,
                                            "state": None},
                                 "writer": m._writer(7)}}}
        inputs.update(kw)
        return m.run_case(inputs)

    def test_throw_plus_bad_canary_is_stack_check_failed(self):
        out = self._throw_case("write-buffer", canary_ok=False)
        self.assertEqual(out["error"], "StackCheckFailed")
        self.assertEqual(out["pad"], "0x5e8c50c")

    def test_assert_held_throw_has_no_pad(self):
        out = self._throw_case("assert-held")
        self.assertEqual(out["error"], "CalleeThrew")
        self.assertIsNone(out["pad"])

    def test_alloc_failure_at_new_superversion(self):
        out = self._throw_case("new-superversion", alloc_ok=False)
        self.assertEqual(out["error"], "BadAlloc")

    def test_normal_return_bad_canary_is_stack_check_failed(self):
        out = self._throw_case(None, canary_ok=False)
        self.assertEqual(out["error"], "StackCheckFailed")


class BindingsTests(unittest.TestCase):
    def test_caller_site_independence(self):
        results = set()
        for site in sorted(m.CALLER_SITES):
            out = m.run_case({
                "group": "bindings", "case_id": "t",
                "caller_site": site,
                "db_overrides": {"log_empty": False,
                                 "logs": [[3, m._writer(3)]]},
                "oracle": {"new_file_number": 7,
                           "last_sequence": 100}})
            results.add(out["result_sha256"])
            self.assertEqual(out["caller_function"],
                             m.CALLER_SITES[site])
        self.assertEqual(len(results), 1)

    def test_switchwal_is_a_caller(self):
        self.assertEqual(m.CALLER_SITES["0x5e8c901"],
                         "rocksdb::DBImpl::SwitchWAL")
        self.assertEqual(len(m.CALLER_SITES), 6)

    def test_fde_hashes(self):
        self.assertEqual(len(m.BODY_SHA256), 64)
        self.assertEqual(len(m.SOURCE_SHA256), 64)
        self.assertEqual(len(m.COLD_BODY_SHA256), 64)
        self.assertEqual(len(m.COLD_SOURCE_SHA256), 64)
        self.assertEqual(len(m.RELOCATIONS.split(";")), 110)
        self.assertEqual(len(m.COLD_RELOCATIONS.split(";")), 13)


if __name__ == "__main__":
    unittest.main()
