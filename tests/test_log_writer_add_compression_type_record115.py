"""Tests for the node #115 log::Writer::AddCompressionTypeRecord model.

Replays all 2,400 cases in cases.tsv through the tool's replay_case,
then checks the model's key behaviours directly: the kNoCompression
gate, the 4-byte PutFixed32 encode, the emit-failure path, the
flush-failure-still-installs quirk, the Create gate (kind 7 only),
the buffer sizes (0x7ff5/0x7ff9), the status-copy byte rules, and the
live engine check (a real CCtx takes parameter 201 -> 1 and resets
with directive 1).
"""

import json
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import log_writer_add_compression_type_record115 as m

PACKET = (Path(__file__).resolve().parents[1] / "research" / "work-items"
          / "re-002-node115-rocksdb-log-writer-add-compression-type-record-115")


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
        self.assertEqual(groups, {"gate_encode": 600, "emit_flush": 600,
                                  "create_install": 600, "bindings": 600})

    def test_all_cases_replay(self):
        bad = []
        for r in _read_cases():
            ok, detail = m.replay_case(r)
            if not ok:
                bad.append((r["id"], detail))
        self.assertEqual(bad, [], f"{len(bad)} cases failed: {bad[:5]}")


class GateTests(unittest.TestCase):
    def _run(self, **kw):
        p = {"type": 7, "manual": 0, "recycle": 0,
             "emit": {"code": 0, "subcode": 0, "b3": 0, "b4": 0,
                      "b5": 0, "state": 0},
             "flush": {"code": 0, "subcode": 0, "b3": 0, "b4": 0,
                       "b5": 0, "state": 0}}
        p.update(kw)
        return m._run_scenario(p)

    def test_no_compression_returns_ok_and_touches_nothing(self):
        out = self._run(type=0)
        self.assertEqual(out["final"]["code"], 0)
        self.assertEqual(out["type_after"], 0)
        self.assertEqual(out["compress_after"], 0)
        self.assertEqual(out["buffer_after"], 0)
        self.assertEqual(out["events"][0], ["gate_type", 0])
        self.assertEqual(out["events"][1], ["return_ok_zeroed", None])

    def test_encode_is_put_fixed32(self):
        for ctype in (1, 2, 7, 0x40, 0xFF):
            self.assertEqual(m.put_fixed32(ctype),
                             struct.pack("<I", ctype))
        out = self._run(type=7)
        self.assertEqual(out["events"][1], ["encode", "07000000"])

    def test_gate_sweeps_all_256_types(self):
        seen = set()
        for r in _read_cases():
            if r["group"] == "gate_encode":
                seen.add(json.loads(r["param"])["type"])
        self.assertEqual(seen, set(range(256)))


class EmitFlushTests(unittest.TestCase):
    def _run(self, **kw):
        p = {"type": 7, "manual": 0, "recycle": 0,
             "emit": {"code": 0, "subcode": 0, "b3": 0, "b4": 0,
                      "b5": 0, "state": 0},
             "flush": {"code": 0, "subcode": 0, "b3": 0, "b4": 0,
                       "b5": 0, "state": 0}}
        p.update(kw)
        return m._run_scenario(p)

    def test_emit_failure_clears_type_and_installs_nothing(self):
        out = self._run(emit={"code": 5, "subcode": 1, "b3": 0, "b4": 0,
                              "b5": 0, "state": 4242})
        self.assertEqual(out["type_after"], 0)
        self.assertEqual(out["compress_after"], 0)
        self.assertEqual(out["buffer_after"], 0)
        self.assertEqual(out["final"]["code"], 5)
        self.assertEqual(out["final"]["state"], 4242)
        kinds = [k for k, _ in out["events"]]
        self.assertNotIn("flush", kinds)
        self.assertNotIn("create", kinds)

    def test_flush_skipped_when_manual_flush(self):
        out = self._run(manual=1)
        kinds = [k for k, _ in out["events"]]
        self.assertNotIn("flush", kinds)
        self.assertIn("create", kinds)

    def test_flush_failure_still_installs(self):
        # The binary does not re-check the Flush status before the
        # install (upstream checks s.ok() once, before the Flush).
        out = self._run(flush={"code": 2, "subcode": 0, "b3": 0, "b4": 0,
                               "b5": 0, "state": 0})
        self.assertNotEqual(out["compress_after"], 0)
        self.assertNotEqual(out["buffer_after"], 0)
        self.assertEqual(out["final"]["code"], 2)

    def test_flush_error_state_moves_into_final(self):
        out = self._run(flush={"code": 3, "subcode": 2, "b3": 1, "b4": 0,
                               "b5": 1, "state": 777})
        self.assertEqual(out["final"]["code"], 3)
        self.assertEqual(out["final"]["subcode"], 2)
        self.assertEqual(out["final"]["b3"], 1)
        self.assertEqual(out["final"]["state"], 777)


class CreateInstallTests(unittest.TestCase):
    def _run(self, **kw):
        p = {"type": 7, "manual": 0, "recycle": 0,
             "emit": {"code": 0, "subcode": 0, "b3": 0, "b4": 0,
                      "b5": 0, "state": 0},
             "flush": {"code": 0, "subcode": 0, "b3": 0, "b4": 0,
                       "b5": 0, "state": 0}}
        p.update(kw)
        return m._run_scenario(p)

    def test_create_gate_kind_7_only(self):
        for ctype in (1, 2, 3, 4, 5, 6, 0x40, 0xFF):
            out = self._run(type=ctype)
            self.assertEqual(out["compress_after"], 0,
                             f"type {ctype} should install null")
            # ... but the buffer is still allocated.
            self.assertNotEqual(out["buffer_after"], 0)
        out = self._run(type=7)
        self.assertNotEqual(out["compress_after"], 0)

    def test_buffer_size_by_recycle(self):
        self.assertEqual(self._run(recycle=0)["buffer_size"], 0x7FF9)
        self.assertEqual(self._run(recycle=1)["buffer_size"], 0x7FF5)

    def test_old_buffer_freed_old_compress_leaked(self):
        out = self._run(old_buffer=42, old_compress=77)
        self.assertEqual(out["freed_buffers"], [42])
        kinds = [k for k, _ in out["events"]]
        self.assertIn("leak_old_compress", kinds)
        self.assertIn("delete_old_buffer", kinds)

    def test_template_is_the_default_options(self):
        tpl = m.build_template()
        self.assertEqual(len(tpl), 48)
        fields = dict((n, v) for n, _o, _s, v in m.template_field_map())
        self.assertEqual(fields["window_bits"], -14)
        self.assertEqual(fields["level"], 32767)
        self.assertEqual(fields["parallel_threads"], 1)
        self.assertEqual(fields["use_zstd_dict_trainer"], 1)
        self.assertEqual(struct.unpack_from("<q", tpl, 0)[0],
                         0x00007FFFFFFFFFF2)
        self.assertEqual(struct.unpack_from("<Q", tpl, 0x10)[0],
                         0x100000000)


class StatusCopyTests(unittest.TestCase):
    def test_copy_zeroes_byte_2_and_leaves_6_7_untouched(self):
        s = m.Status(code=3, subcode=1, b3=1, b4=0, b5=1, state=999)
        out = s.out_bytes()
        self.assertEqual(len(out), 16)
        self.assertEqual(out[0], 3)
        self.assertEqual(out[1], 1)
        self.assertEqual(out[2], 0)
        self.assertEqual(out[3], 1)
        self.assertEqual(out[5], 1)
        self.assertEqual(out[6:8], b"XX")
        self.assertEqual(struct.unpack_from("<Q", out, 8)[0], 999)

    def test_early_ok_status(self):
        s = m.Status.ok()
        out = s.out_bytes()
        self.assertEqual(out[:6], b"\x00\x00\x00\x00\x00\x00")
        self.assertEqual(out[6:8], b"XX")
        self.assertEqual(out[8:], b"\x00" * 8)


class BindingsTests(unittest.TestCase):
    def test_functions_tsv_matches_binary_and_census(self):
        rows = list(open(PACKET / "functions.tsv"))[1:]
        self.assertEqual(len(rows), 2)
        data = m._read_binary()
        for row in rows:
            cols = row.rstrip("\n").split("\t")
            start, end = int(cols[1], 16), int(cols[2], 16)
            body = data[m._va_to_off(start):m._va_to_off(end)]
            import hashlib
            self.assertEqual(hashlib.sha256(body).hexdigest(), cols[4])

    def test_caller_census(self):
        census = json.load(open(PACKET / "census.json"))
        self.assertEqual(census["validated_sites"], 2)
        self.assertEqual(census["targets"]["0x5f041d0"]["calls"], 1)
        self.assertEqual(census["targets"]["0x5f04190"]["jumps"], 1)
        sites = [l.split("\t") for l in
                 open(PACKET / "callers.tsv").read().splitlines()[1:]]
        by_target = {row[0]: row for row in sites}
        self.assertEqual(by_target["0x5f041d0"][3], "0x5e5c5a3")
        self.assertEqual(by_target["0x5f04190"][3], "0x5f0440b")

    def test_live_engine_check(self):
        created, set_ret, reset_ret = m.live_engine_check()
        self.assertTrue(created)
        self.assertEqual(set_ret, 1)  # setParameter echoes the value
        self.assertEqual(reset_ret, 0)


if __name__ == "__main__":
    unittest.main()
