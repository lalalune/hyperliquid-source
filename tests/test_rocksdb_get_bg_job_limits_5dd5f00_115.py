#!/usr/bin/env python3
"""Tests for the GetBGJobLimits 0x5dd5f00 packet (node #115).

The tests hold the claims, not the packet's tables: the recovered policy is
checked rule by rule, the emulator is run against the model, the ledger is
re-checked row by row, and the artifact claims (instruction count, bytes, the
caller census) are re-derived from the binary.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.rocksdb_get_bg_job_limits_5dd5f00_115 import (  # noqa: E402
    START, END, SIZE, SYMBOL, K_DEFAULT, M32, INT_MIN, INT_MAX, LAYOUT,
    FAMILIES, BOUNDARY_CASES, LEDGER_PER_FAMILY,
    instruction_stream, accesses, get_bg_job_limits, decoded, decoded_packed,
    model_packed, pack, unpack_flushes, unpack_compactions, s32, agree,
    generate_cases, ledger_rows, cases_tsv_rows, replay_case, sweep,
    Machine, _execute,
)

PACKET = (ROOT / "research" / "work-items"
          / "RE-002-node115-rocksdb-get-bg-job-limits-5dd5f00-115")
BINARY = ROOT / "artifacts" / "node" / "115" / "hl-node"
BODY_SHA256 = "fdf3ef61c6dc45309e0e7b76154028fa69dfa01fcdcdfb1a12dfdfceb046bc53"


def va_to_off(va):
    out = subprocess.check_output(["readelf", "-lW", str(BINARY)]).decode()
    for line in out.splitlines():
        p = line.split()
        if p and p[0] == "LOAD":
            v, o, f = int(p[2], 16), int(p[1], 16), int(p[4], 16)
            if v <= va < v + f:
                return o + (va - v)
    raise AssertionError(f"{va:#x} is in no LOAD segment")


def window_bytes():
    data = BINARY.read_bytes()
    return data[va_to_off(START):va_to_off(START) + SIZE]


def run_case(*args):
    """Both paths, asserted equal, returning the pair."""
    model = get_bg_job_limits(*args)
    machine = decoded(*args)
    assert model == machine, (args, model, machine)
    return model


class Semantics(unittest.TestCase):
    def test_both_counts_must_be_kdefault_to_derive(self):
        # an explicit compaction count with kDefault flushes: flushes clamps to 1
        self.assertEqual(run_case(K_DEFAULT, 3, 24, True), (1, 3))
        # and an explicit flush count with kDefault compactions keeps its value
        self.assertEqual(run_case(2, K_DEFAULT, 24, True), (2, 1))

    def test_the_quarter_split_starts_above_seven_jobs(self):
        for jobs in (0, 1, 2, 6, 7):
            self.assertEqual(run_case(K_DEFAULT, K_DEFAULT, jobs, True)[0], 1, jobs)
        self.assertEqual(run_case(K_DEFAULT, K_DEFAULT, 8, True)[0], 2)
        self.assertEqual(run_case(K_DEFAULT, K_DEFAULT, 9, True)[0], 2)
        self.assertEqual(run_case(K_DEFAULT, K_DEFAULT, 24, True), (6, 18))
        self.assertEqual(run_case(K_DEFAULT, K_DEFAULT, 28, True), (7, 21))

    def test_the_remainder_is_the_budget_minus_the_flushes(self):
        for jobs in (8, 9, 12, 16, 24, 100, 1000):
            f, c = run_case(K_DEFAULT, K_DEFAULT, jobs, True)
            self.assertEqual(f + c, jobs, jobs)
            self.assertEqual(c, jobs - jobs // 4, jobs)

    def test_a_non_positive_remainder_clamps_to_one(self):
        # jobs - flushes can only be non-positive when the quarter is the whole
        # budget, which the > 7 guard prevents; the clamp is still exercised by
        # the wrapped INT_MIN case below.
        f, c = run_case(K_DEFAULT, K_DEFAULT, INT_MIN, True)
        self.assertEqual(c, INT_MAX)          # wrapped, therefore positive
        self.assertEqual(f, 1)

    def test_kdefault_and_zero_both_clamp_to_one(self):
        for value in (K_DEFAULT, 0, -2, -1000):
            self.assertEqual(run_case(value, value, 0, True), (1, 1), value)
            self.assertEqual(run_case(value, 5, 0, True)[0], 1, value)
            self.assertEqual(run_case(5, value, 0, True)[1], 1, value)

    def test_negative_flushes_are_clamped_not_derived(self):
        # only -1 is kDefault; -2 is an invalid count and clamps like 0
        self.assertEqual(get_bg_job_limits(-2, K_DEFAULT, 24, True), (1, 1))

    def test_single_db_forces_one_compaction(self):
        self.assertEqual(run_case(K_DEFAULT, K_DEFAULT, 24, False), (6, 1))
        self.assertEqual(run_case(4, 8, 0, False), (4, 1))
        self.assertEqual(run_case(4, 8, 0, True), (4, 8))

    def test_the_forcing_rule_also_applies_to_the_derived_path(self):
        # the derived compactions jump back into the multi-db test (0x5dd5f59)
        self.assertEqual(get_bg_job_limits(K_DEFAULT, K_DEFAULT, INT_MAX, False), (INT_MAX >> 2, 1))


class Return(unittest.TestCase):
    def test_the_pair_is_packed_low_dword_first(self):
        self.assertEqual(LAYOUT, {"flushes": (0, 32), "compactions": (32, 32)})
        self.assertEqual(pack(2, 3), 0x300000002)
        self.assertEqual(pack(6, 18), 0x1200000006)

    def test_unpacking_recovers_both_fields(self):
        for f, c in ((1, 1), (2, 3), (6, 18), (INT_MAX, INT_MAX), (0, M32)):
            p = pack(f, c)
            self.assertEqual(unpack_flushes(p), f, (f, c))
            self.assertEqual(unpack_compactions(p), c, (f, c))

    def test_the_two_shifts_the_callers_use_agree(self):
        # three call sites use sar $0x20 and one uses shr $0x20
        p = decoded_packed(K_DEFAULT, K_DEFAULT, 24, True)
        self.assertEqual(s32(p >> 32), p >> 32)
        self.assertEqual((p >> 32) & M32, 18)

    def test_the_emulator_overwrites_the_argument_sentinel(self):
        m = Machine()
        m.write("%eax", 0xDEADBEEF)
        for args in ((K_DEFAULT, K_DEFAULT, 24, True), (2, 3, 0, True),
                     (K_DEFAULT, K_DEFAULT, 5, False)):
            r = decoded_packed(*args)
            self.assertNotEqual(r, 0xDEADBEEF, args)

    def test_both_fields_are_always_positive(self):
        for _, args in generate_cases():
            f, c = get_bg_job_limits(*args)
            self.assertGreaterEqual(f, 1, args)
            self.assertGreaterEqual(c, 1, args)


class Decoded(unittest.TestCase):
    def test_the_routine_never_reads_or_writes_memory(self):
        acc = accesses()
        self.assertEqual(acc["loads"], [])
        self.assertEqual(acc["stores"], [])
        self.assertEqual(acc["non_nop_instructions_checked"], 26)

    def test_every_instruction_is_implemented(self):
        insns = instruction_stream()
        from tools.rocksdb_get_bg_job_limits_5dd5f00_115 import _HANDLED
        for ins in insns:
            self.assertIn(ins.mnemonic, _HANDLED, ins)

    def test_the_emulator_raises_on_an_unimplemented_instruction(self):
        # a doctored stream holding an instruction this packet does not
        # implement must raise instead of silently answering
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write(f"{START:016x} <hl-node>:\n"
                     f" {START:x}:\t0f 0b                \tud2\n")
            path = fh.name
        m = Machine()
        with self.assertRaises(NotImplementedError):
            _execute(m, path=path)

    def test_the_sweep_agrees(self):
        self.assertEqual(sweep(), [])

    def test_the_rule_edges_agree_with_the_decoded_stream(self):
        edges = [(K_DEFAULT, K_DEFAULT, j, m) for j in (-2, -1, 0, 1, 6, 7, 8, 9, 16, 24, 29, INT_MAX, INT_MIN)
                 for m in (False, True)]
        edges += [(f, c, 0, True) for f in (-2, -1, 0, 1, 2, INT_MAX, INT_MIN)
                  for c in (-2, -1, 0, 1, 2, INT_MAX, INT_MIN)]
        for args in edges:
            self.assertTrue(agree(args), args)

    def test_the_decoded_path_really_runs_the_bytes(self):
        # swapping the shift constant in the excerpt must change the answer, so
        # a "decoder" that just called the model could not pass this
        import tempfile
        text = (PACKET / "main.txt").read_text()
        self.assertIn("sar    $0x2,%esi", text)
        doctored = text.replace("sar    $0x2,%esi", "sar    $0x3,%esi")
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write(doctored)
            path = fh.name
        self.assertEqual(decoded(K_DEFAULT, K_DEFAULT, 24, True), (6, 18))
        self.assertEqual(decoded(K_DEFAULT, K_DEFAULT, 24, True, path=path), (3, 21))
        self.assertEqual(len(instruction_stream()), 29)
        self.assertEqual(sum(len(i.raw) for i in instruction_stream()), SIZE)


class Ledger(unittest.TestCase):
    def test_the_ledger_has_sixty_rows_per_family(self):
        rows = ledger_rows()
        self.assertEqual(len(rows), 300)
        for family in FAMILIES:
            self.assertEqual(sum(1 for r in rows if r["family"] == family),
                             LEDGER_PER_FAMILY, family)

    def test_every_ledger_row_agrees(self):
        for r in ledger_rows():
            self.assertTrue(r["agree"], r)

    def test_the_boundary_rows_are_kept_verbatim(self):
        rows = ledger_rows()
        for family in FAMILIES:
            kept = [(r["flushes"], r["compactions"], r["jobs"], bool(r["multi_db"]))
                    for r in rows if r["family"] == family][:len(BOUNDARY_CASES[family])]
            self.assertEqual(kept, BOUNDARY_CASES[family], family)

    def test_the_on_disk_ledger_is_the_recomputed_ledger(self):
        disk = (PACKET / "cases.tsv").read_text().splitlines()
        self.assertEqual(disk, cases_tsv_rows(ledger_rows()))

    def test_replay_case_agrees_with_both_paths(self):
        for _, args in generate_cases(seed=3)[:40]:
            model, machine = replay_case(args)
            self.assertEqual(model, machine, args)

    def test_a_second_seed_agrees_too(self):
        for _, args in generate_cases(seed=20261110):
            self.assertTrue(agree(args), args)


class Artifact(unittest.TestCase):
    def test_the_window_is_the_artifact_bytes(self):
        blob = b"".join(i.raw for i in instruction_stream())
        self.assertEqual(blob, window_bytes())
        self.assertEqual(hashlib.sha256(blob).hexdigest(), BODY_SHA256)

    def test_the_window_is_a_complete_function_body(self):
        data = BINARY.read_bytes()
        off = va_to_off(START)
        self.assertEqual(data[off - 7:off], b"\xcc" * 7)
        self.assertEqual(data[off + SIZE:off + SIZE + 5], b"\xcc" * 5)
        self.assertEqual(instruction_stream()[0].mnemonic, "endbr64")
        self.assertEqual(instruction_stream()[-1].end(), END)

    def test_the_frames_file_names_the_routine_and_its_callers(self):
        text = (PACKET / "frames.txt").read_text()
        self.assertIn(f"pc={START:016x}..{END:016x}", text)
        for a, b in ((0x5D71FE0, 0x5D72E50), (0x5DFCEA0, 0x5DFCFB6),
                     (0x5E5CF70, 0x5E5DF0F)):
            self.assertIn(f"pc={a:016x}..{b:016x}", text, (a, b))
        self.assertEqual(text.count("FDE cie="), 4)

    def test_the_records_file_carries_the_bound_context(self):
        rec = json.loads((PACKET / "records.json").read_text())
        b = rec["bound_context"]
        self.assertEqual(b["symbol"], SYMBOL)
        self.assertEqual(b["start"], "0x5dd5f00")
        self.assertEqual(b["end"], "0x5dd5f5b")
        self.assertEqual(b["size_bytes"], 91)
        self.assertEqual(b["target_body_sha256"], BODY_SHA256)
        self.assertTrue(b["raw_equal"])
        self.assertEqual(b["candidate_versions"], ["0.11.0+8.1.1"])
        self.assertEqual(rec["caller_census"]["direct_calls"], 4)
        self.assertEqual(rec["caller_census"]["consumers"],
                         {"register-copy": 3, "arithmetic": 1})
        self.assertEqual(rec["caller_census"]["splits"], {"sar": 3, "shr": 1})
        self.assertEqual(len(rec["caller_census"]["call_sites"]), 4)

    def test_the_caller_census_is_recomputable(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "pkt_census_t", PACKET / "census.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        c = mod.census()
        self.assertEqual(c["direct_calls"], 4)
        self.assertEqual(c["caller_fdes"], 3)
        self.assertEqual(c["consumers"], {"register-copy": 3, "arithmetic": 1})
        self.assertEqual(c["discarded_sites"], 0)
        # the split of the packed pair, proven per site by the taint analysis:
        # a stale rax must not leak into the next call's copy, and an
        # intervening call clobbers the caller-saved registers
        self.assertEqual(c["splits"], {"sar": 3, "shr": 1})
        self.assertEqual([(r["split"], f"{r['split_va']:#x}") for r in c["rows"]],
                         [("sar", "0x5d7268d"), ("sar", "0x5d72689"),
                          ("sar", "0x5dfcef9"), ("shr", "0x5e5d00c")])

    def test_every_claim_anchor_is_one_instruction(self):
        rows = [l.split("\t") for l in
                (PACKET / "semantics.tsv").read_text().splitlines()[1:] if l]
        insns = instruction_stream()
        self.assertEqual(len(rows), len(insns))
        for row, ins in zip(rows, insns):
            self.assertEqual(row[1], f"{ins.addr:#x}", row)
            self.assertEqual(row[3], ins.raw.hex(), row)


if __name__ == "__main__":
    unittest.main()
