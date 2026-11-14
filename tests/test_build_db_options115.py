"""Tests for the node #115 rocksdb::BuildDBOptions model.

Replays all 2,400 cases in cases.tsv through the tool, then checks
the model's key behaviours directly: the 91-field copy map (74
immutable-sourced, 17 mutable-sourced, in binary/source order, with
the three structs laying their fields out in different orders), the
shared_ptr copy-assign semantics (self-assign no-op, acquire on a
new target, release-and-destroy on the old one, aliasing counts
across fields and the listeners vector), the byte image (every
copied field lands at the binary's output offset; the two unwritten
fields keep the DBOptions() ctor defaults), the caller census (12
direct calls including DBImpl::CreateWAL, no jumps, no LEA refs),
the FDE body/source hashes, the in-FDE landing pad, and the live
engine check (independent disassembly re-parse of the copy map).
"""

import hashlib
import json
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import build_db_options115 as m

PACKET = (Path(__file__).resolve().parents[1] / "research" / "work-items"
          / "re-002-node115-rocksdb-build-db-options-115")
BIN = Path(__file__).resolve().parents[1] / "artifacts" / "node" / "115" / "hl-node"
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"


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
        self.assertEqual(groups, {"immutable": 600, "mutable": 600,
                                  "shared_ptr": 600, "bindings": 600})

    def test_replay_all(self):
        for row in _read_cases():
            inputs = json.loads(row["inputs_json"])
            expected = json.loads(row["expected_json"])
            self.assertEqual(m.run_case(inputs), expected, row["case_id"])

    def test_case_ids_unique(self):
        rows = _read_cases()
        self.assertEqual(len({r["case_id"] for r in rows}), 2400)

    def test_immutable_group_isolates_immutable_fields(self):
        # The mutable half is fixed at defaults, so every
        # mutable-sourced output field equals its default.
        defaults = m.default_mutable()
        for row in _read_cases():
            if row["group"] != "immutable":
                continue
            expected = json.loads(row["expected_json"])
            out = expected["output"]
            for name, src, _o, _oo, _k in m.COPY_MAP:
                if src == "mut":
                    self.assertEqual(out[name], defaults[name],
                                     (row["case_id"], name))

    def test_mutable_group_isolates_mutable_fields(self):
        defaults = m.default_immutable()
        for row in _read_cases():
            if row["group"] != "mutable":
                continue
            expected = json.loads(row["expected_json"])
            out = expected["output"]
            for name, src, _o, _oo, _k in m.COPY_MAP:
                if src == "imm":
                    want = defaults[name]
                    got = out[name]
                    if isinstance(want, list):
                        self.assertEqual(got, want,
                                         (row["case_id"], name))
                    elif want is None:
                        self.assertIsNone(got, (row["case_id"], name))
                    else:
                        self.assertEqual(got, want,
                                         (row["case_id"], name))

    def test_every_case_has_91_fields_and_image(self):
        for row in _read_cases():
            expected = json.loads(row["expected_json"])
            self.assertEqual(len(expected["output"]), 91 + 2,
                             row["case_id"])
            self.assertEqual(len(expected["copy_order"]), 91,
                             row["case_id"])
            self.assertEqual(len(bytes.fromhex(expected["image_hex"])),
                             0x290, row["case_id"])
            self.assertEqual(expected["unwritten"],
                             {"write_dbid_to_manifest": False,
                              "compaction_service": None},
                             row["case_id"])


class FieldMapTests(unittest.TestCase):
    def test_copy_map_counts(self):
        self.assertEqual(len(m.COPY_MAP), 91)
        imm = [e for e in m.COPY_MAP if e[1] == "imm"]
        mut = [e for e in m.COPY_MAP if e[1] == "mut"]
        self.assertEqual(len(imm), 74)
        self.assertEqual(len(mut), 17)

    def test_no_duplicate_output_offsets(self):
        outs = [(e[3], e[4]) for e in m.COPY_MAP]
        # Shared_ptr fields occupy 16 bytes (ptr + control); the
        # rest occupy their kind width. No two fields overlap.
        spans = []
        for _n, _s, _o, off, kind in m.COPY_MAP:
            spans.append((off, off + m._kind_width(kind)))
        spans.sort()
        for (a0, a1), (b0, _b1) in zip(spans, spans[1:]):
            self.assertLessEqual(a1, b0, (a0, a1, b0))

    def test_struct_sizes(self):
        self.assertEqual(m.SIZE_DBOPTIONS, 0x290)
        self.assertEqual(m.SIZE_IMMUTABLE, 0x240)
        self.assertEqual(m.SIZE_MUTABLE, 0x6C)

    def test_reordered_fields(self):
        # The three structs lay fields out differently; the copy
        # map, not declaration order, is the layout evidence.
        by_name = {e[0]: e for e in m.COPY_MAP}
        # max_write_batch_group_size_bytes: immutable +0xf8, out
        # +0x1d8 (in DBOptions it sits after
        # enable_write_thread_adaptive_yield).
        self.assertEqual(by_name["max_write_batch_group_size_bytes"],
                         ("max_write_batch_group_size_bytes", "imm",
                          0xf8, 0x1d8, "u64"))
        # persist_stats_to_disk: immutable +0x199 (after the bool
        # run), output +0x138.
        self.assertEqual(by_name["persist_stats_to_disk"],
                         ("persist_stats_to_disk", "imm", 0x199, 0x138,
                          "bool"))
        # enforce_single_del_contracts: the last immutable field
        # (+0x238, past the convenience tail) lands at +0x289.
        self.assertEqual(by_name["enforce_single_del_contracts"],
                         ("enforce_single_del_contracts", "imm", 0x238,
                          0x289, "bool"))
        # avoid_flush_during_shutdown is the only bool in the
        # mutable half (mut +0x0c -> out +0x213).
        self.assertEqual(by_name["avoid_flush_during_shutdown"],
                         ("avoid_flush_during_shutdown", "mut", 0x0c,
                          0x213, "bool"))

    def test_defaults_build_matches_declaration_defaults(self):
        out, _events, _reg, _img = m.build_db_options(
            m.default_immutable(), m.default_mutable())
        self.assertEqual(out["paranoid_checks"], 1)
        self.assertEqual(out["verify_sst_unique_id_in_manifest"], 1)
        self.assertEqual(out["info_log_level"], 1)
        self.assertEqual(out["max_open_files"], -1)
        self.assertEqual(out["max_file_opening_threads"], 16)
        self.assertEqual(out["max_manifest_file_size"],
                         1024 * 1024 * 1024)
        self.assertEqual(out["keep_log_file_num"], 1000)
        self.assertEqual(out["manifest_preallocation_size"],
                         4 * 1024 * 1024)
        self.assertEqual(out["wal_recovery_mode"], 2)
        self.assertEqual(out["lowest_used_cache_tier"], 1)
        self.assertEqual(out["enforce_single_del_contracts"], 1)
        self.assertEqual(out["write_dbid_to_manifest"], False)
        self.assertIsNone(out["compaction_service"])
        self.assertEqual(out["db_host_id"], "")


class SharedPtrTests(unittest.TestCase):
    def _slot(self):
        return m.SharedPtrSlot()

    def test_self_assign_is_noop(self):
        events = []
        slot = self._slot()
        t = m.SharedTarget("x", 0)
        slot.assign(t, events, "rate_limiter")
        self.assertEqual(t.use_count, 2)
        events.clear()
        slot.assign(t, events, "rate_limiter")
        self.assertEqual(t.use_count, 2)
        self.assertEqual(events[0]["op"], "shared_ptr_noop")

    def test_null_to_target_acquires(self):
        events = []
        slot = self._slot()
        t = m.SharedTarget("x", 0)
        slot.assign(t, events, "info_log")
        self.assertEqual(t.use_count, 2)
        self.assertEqual(events[0]["op"], "shared_ptr_acquire")

    def test_target_to_null_releases_and_destroys(self):
        events = []
        slot = self._slot()
        t = m.SharedTarget("x", 0)
        slot.assign(t, events, "info_log")
        events.clear()
        slot.assign(None, events, "info_log")
        self.assertEqual(t.use_count, 1)
        self.assertEqual(
            [e["op"] for e in events], ["shared_ptr_release"])
        # The input struct still holds its reference; releasing
        # the last output reference does not destroy it yet.
        self.assertFalse(t.destroyed)

    def test_replace_destroys_last_reference(self):
        events = []
        slot = self._slot()
        a = m.SharedTarget("a", 0)
        b = m.SharedTarget("b", 1)
        slot.assign(a, events, "statistics")
        # Drop the input struct's reference by hand, so the slot
        # holds the only one.
        a.use_count = 1
        events.clear()
        slot.assign(b, events, "statistics")
        self.assertEqual(
            [e["op"] for e in events],
            ["shared_ptr_acquire", "shared_ptr_release",
             "shared_ptr_destroy"])
        self.assertTrue(a.destroyed)

    def test_aliasing_counts(self):
        # One target in three shared_ptr fields plus two listeners
        # elements: input holds 5 references, the build adds 5.
        imm = m.default_immutable()
        for name in ("rate_limiter", "statistics", "row_cache"):
            imm[name] = "shared"
        imm["listeners"] = ["shared", "shared"]
        out, events, registry, _img = m.build_db_options(
            imm, m.default_mutable())
        self.assertEqual(registry["shared"], 10)
        # Copy order: rate_limiter first (5 input refs + 1), then
        # statistics, then the two listeners elements, then
        # row_cache last (10).
        self.assertEqual(out["rate_limiter"]["use_count"], 6)
        self.assertEqual(out["row_cache"]["use_count"], 10)
        self.assertEqual(
            len([e for e in events
                 if e["op"] == "shared_ptr_acquire"]), 5)

    def test_null_shared_ptrs_stay_null(self):
        out, _events, registry, image = m.build_db_options(
            m.default_immutable(), m.default_mutable())
        self.assertEqual(registry, {})
        for name in ("rate_limiter", "sst_file_manager", "info_log",
                     "statistics", "write_buffer_manager", "row_cache",
                     "file_checksum_gen_factory"):
            self.assertIsNone(out[name])
            _n, _s, _o, off, _k = next(
                e for e in m.COPY_MAP if e[0] == name)
            self.assertEqual(image[off:off + 16], b"\x00" * 16)


class ByteImageTests(unittest.TestCase):
    def _build(self, **overrides):
        imm = m.default_immutable()
        mut = m.default_mutable()
        for name, value in overrides.get("imm", {}).items():
            imm[name] = value
        for name, value in overrides.get("mut", {}).items():
            mut[name] = value
        return m.build_db_options(imm, mut)

    def test_bool_bytes_at_leading_offsets(self):
        _o, _e, _r, image = self._build(
            imm={"create_if_missing": True, "paranoid_checks": False,
                 "verify_sst_unique_id_in_manifest": True})
        self.assertEqual(image[0x00], 1)
        self.assertEqual(image[0x01], 0)
        self.assertEqual(image[0x03], 0)
        self.assertEqual(image[0x06], 1)
        self.assertEqual(image[0x07], 0)  # padding, never written

    def test_int_fields_little_endian(self):
        _o, _e, _r, image = self._build(
            mut={"max_open_files": -1, "max_background_jobs": 2})
        self.assertEqual(image[0x44:0x48],
                         (-1).to_bytes(4, "little", signed=True))
        self.assertEqual(image[0xd0:0xd4], (2).to_bytes(4, "little"))

    def test_u64_fields(self):
        _o, _e, _r, image = self._build(
            mut={"max_total_wal_size": 0x0102030405060708})
        self.assertEqual(image[0x50:0x58],
                         (0x0102030405060708).to_bytes(8, "little"))

    def test_sso_string_layout(self):
        _o, _e, _r, image = self._build(imm={"db_log_dir": "wal"})
        # ptr slot = OUT_BASE + 0x88 + 0x10, size 3, bytes inline.
        ptr = int.from_bytes(image[0x88:0x90], "little")
        self.assertEqual(ptr, m.OUT_BASE + 0x88 + 0x10)
        self.assertEqual(int.from_bytes(image[0x90:0x98], "little"), 3)
        self.assertEqual(image[0x98:0x9b], b"wal")

    def test_long_string_gets_heap_id(self):
        _o, _e, _r, image = self._build(imm={"db_log_dir": "x" * 100})
        ptr = int.from_bytes(image[0x88:0x90], "little")
        self.assertGreaterEqual(ptr, m.HEAP_BASE)
        self.assertEqual(int.from_bytes(image[0x90:0x98], "little"),
                         100)
        self.assertEqual(int.from_bytes(image[0x98:0xa0], "little"),
                         100)

    def test_unwritten_fields_keep_ctor_defaults(self):
        _o, _e, _r, image = self._build()
        self.assertEqual(image[0x21a], 0)
        self.assertEqual(image[0x278:0x288], b"\x00" * 16)
        self.assertEqual(image[0x288], 1)  # lowest_used_cache_tier
        self.assertEqual(image[0x289], 1)  # enforce_single_del_...

    def test_one_byte_enums(self):
        _o, _e, _r, image = self._build(
            imm={"info_log_level": 3, "wal_recovery_mode": 1,
                 "wal_compression": 2, "lowest_used_cache_tier": 0})
        self.assertEqual(image[0x40], 3)
        self.assertEqual(image[0x1f2], 1)
        self.assertEqual(image[0x217], 2)
        self.assertEqual(image[0x288], 0)


class CensusTests(unittest.TestCase):
    def test_body_and_source_hashes(self):
        data = open(BIN, "rb").read()
        self.assertEqual(hashlib.sha256(data).hexdigest(), DIGEST)
        body = data[_va2off(0x60C2E20):_va2off(0x60C3477)]
        self.assertEqual(len(body), 1623)
        self.assertEqual(hashlib.sha256(body).hexdigest(),
                         m.BODY_SHA256)
        census = json.load(open(
            Path(__file__).resolve().parents[1] / "research"
            / "work-items" / "RE-002-node115-vendor-census"
            / "census.json"))["records"]
        rec = next(r for r in census if r["start"] == 0x60C2E20)
        self.assertEqual(rec["target_body_sha256"], m.BODY_SHA256)
        self.assertEqual(rec["source_body_sha256"], m.SOURCE_SHA256)
        self.assertIn("BuildDBOptions", rec["symbol"])
        self.assertEqual(rec["member"],
                         "d7ece8bd5f9dc186-options_helper.o")
        self.assertEqual(len(rec["relocations"]), 19)

    def test_caller_census(self):
        rows = [line.rstrip("\n").split("\t")
                for line in open(PACKET / "callers.tsv")
                .read().splitlines()[1:]]
        calls = [r for r in rows if r[2] == "call"]
        self.assertEqual(len(calls), 12)
        sites = sorted(r[3] for r in calls)
        self.assertEqual(sites, sorted(m.CALLER_SITES))
        # CreateWAL (the #6222 packet) calls it at 0x5e5c2f8.
        self.assertIn("0x5e5c2f8", sites)
        createwal = next(r for r in calls if r[3] == "0x5e5c2f8")
        self.assertEqual(createwal[4], "0x5e5c270")
        self.assertEqual(createwal[5], "0x5e5c9a3")
        self.assertEqual(len([r for r in rows if r[2] == "jmp"]), 0)
        self.assertEqual(len([r for r in rows if r[2] == "lea"]), 0)

    def test_landing_pad_inside_main_fde(self):
        # No separate .cold FDE: the pad sits at the tail of the
        # main FDE -- endbr64; mov %rax,%rbp; jmp 0x60c2e04.
        data = open(BIN, "rb").read()
        pad = data[_va2off(0x60C346B):_va2off(0x60C3477)]
        self.assertEqual(pad.hex(),
                         "f30f1efa4889c5e98df9ffff")
        # The pad target destroys the output and resumes unwinding:
        # mov %rbx,%rdi; call 0x5d354b0; mov %rbp,%rdi; call
        # _Unwind_Resume@plt.
        target = data[_va2off(0x60C2E04):_va2off(0x60C2E0F)]
        self.assertEqual(target[:3].hex(), "4889df")
        self.assertEqual(target[3], 0xE8)  # call

    def test_ctor_census_bound(self):
        # DBOptions::DBOptions() is census-bound too (the oracle
        # ctor this packet builds on).
        census = json.load(open(
            Path(__file__).resolve().parents[1] / "research"
            / "work-items" / "RE-002-node115-vendor-census"
            / "census.json"))["records"]
        rec = next(r for r in census if r["start"] == 0x60B2DB0)
        self.assertIn("DBOptionsC1Ev", rec["symbol"])


class ManifestTests(unittest.TestCase):
    def test_manifest_verifies(self):
        lines = (PACKET / "MANIFEST.sha256").read_text().splitlines()
        self.assertTrue(lines)
        for line in lines:
            want, name = line.split(None, 1)
            got = hashlib.sha256(
                (PACKET / name).read_bytes()).hexdigest()
            self.assertEqual(got, want, name)


class LiveTests(unittest.TestCase):
    def test_live_engine_check(self):
        ok, _ = m.live_engine_check()
        self.assertTrue(ok)


if __name__ == "__main__":
    unittest.main()
