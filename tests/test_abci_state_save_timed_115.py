import copy
import pathlib
import struct
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import abci_state_save_timed_115 as tool  # noqa: E402

EVIDENCE = ROOT / "research/work-items/abci-state-save-timed-115"
FILES = ("cases.tsv", "mutants.tsv", "calls.tsv", "summary.json", "measure.json")
FULL, PA, PB = tool.FULL, tool.PLAIN_A, tool.PLAIN_B


def mutate(image, off, mask=0x01):
    data = bytearray(image.data)
    data[off] ^= mask
    mutant = copy.copy(image)
    mutant.data = bytes(data)
    mutant.cache = {}
    return mutant


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = tool.load_image()
        cls.cases = tool.full_cases()
        cls.plain = tool.plain_cases()

    def pick(self, **want):
        for c in self.cases:
            if all(c.get(k) == v for k, v in want.items()):
                return c
        raise AssertionError(f"no case {want}")

    def run_full(self, case):
        got = tool.run_body(self.image, FULL, case)
        self.assertEqual(got, tool.reconstruct(self.image, FULL, case))
        return got

    def roles(self, got):
        return [row[0] for row in got[1]]


class SaveRoutes(Base):
    def test_dev_null_skips_serialization_but_still_logs(self):
        got = self.run_full(self.pick(path=b"/dev/null"))
        self.assertEqual(got[0], "ret")
        self.assertEqual(self.roles(got), ["now", "now", "dur", "utcnow", "log"])
        self.assertNotIn("norm", self.roles(got))
        self.assertEqual(self.roles(got)[:2], ["now", "now"])
        self.assertEqual(self.roles(got)[-1], "log")

    def test_only_the_exact_nine_bytes_skip(self):
        for path in (b"/dev/nul", b"/dev/nullx", b"/dev/nulL", b""):
            got = self.run_full(self.pick(path=path, norm=b"a.rmp", fmt_err=0, oom=0, cap=0x40, prep_err=0, write_err=0, len=7))
            self.assertIn("norm", self.roles(got))

    def test_rmp_extension_picks_message_pack_any_case(self):
        for norm in (b"a.rmp", b"a.RMP", b"a.RmP", b"a.b.rmp", b"d/.rmp"):
            got = self.run_full(self.pick(path=b"a", norm=norm, fmt_err=0, oom=0, cap=0x40, prep_err=0, write_err=0, len=7))
            self.assertIn("ser_rmp", self.roles(got), norm)
            self.assertNotIn("ser_json", self.roles(got), norm)
            self.assertNotIn("malloc", self.roles(got), norm)

    def test_everything_else_is_pretty_json(self):
        for norm in (None, b"a.json", b".rmp", b"..", b"a.", b"rmp", b"a.rmp.bak", b"x.rm", b"x.rmpp", b"", b"/", b"."):
            got = self.run_full(self.pick(path=b"a", norm=norm, fmt_err=0, oom=0, cap=0x40, prep_err=0, write_err=0, len=7))
            self.assertIn("ser_json", self.roles(got), norm)
            self.assertNotIn("ser_rmp", self.roles(got), norm)
            row = next(r for r in got[1] if r[0] == "ser_json")
            self.assertEqual(row[6:9], (tool.full_consts(self.image)["indent"], 2, 0))

    def test_extension_comes_from_the_normalised_path(self):
        case = dict(self.pick(path=b"a", norm=b"a.json", fmt_err=0, oom=0, cap=0x40, prep_err=0, write_err=0, len=7))
        case["path"] = b"x.rmp"
        self.assertIn("ser_json", self.roles(self.run_full(case)))

    def test_hidden_file_and_dot_dot_have_no_extension(self):
        self.assertIsNone(tool.extension_of(b".rmp"))
        self.assertIsNone(tool.extension_of(b".."))
        self.assertEqual(tool.extension_of(b"a."), b"")
        self.assertEqual(tool.extension_of(b"...") , b"")
        self.assertEqual(tool.extension_of(b"d/.rmp"), b"rmp")

    def test_default_writer_configuration_constants(self):
        got = self.run_full(self.pick(path=b"a", norm=b"a.rmp", fmt_err=0, oom=0, cap=0x40, prep_err=0, write_err=0, len=7))
        row = next(r for r in got[1] if r[0] == "ser_rmp")
        self.assertEqual(row[5:8], (("sp", -0x128 + 0x68), 0x1000400, 0))
        self.assertEqual(row[8:], (0, 1, 0))     # buffer vector starts empty: cap 0, dangling pointer 1, len 0

    def test_normaliser_receives_path_and_absolute_flag(self):
        for path, flag in ((b"/s/a", 1), (b"a", 0), (b"", 0), (b"/", 1)):
            got = self.run_full(self.pick(path=path, norm=b"a.rmp", fmt_err=0, oom=0, cap=0x40, prep_err=0, write_err=0, len=7))
            row = next(r for r in got[1] if r[0] == "norm")
            self.assertEqual(row, ("norm", tool.PATH_ADDR, len(path), 6, 0x201, flag))


class FailureBranches(Base):
    def test_allocation_failure_stops_before_serializing(self):
        got = self.run_full(self.pick(path=b"a", norm=None, oom=1))
        self.assertEqual(got[0], "oom")
        self.assertEqual(self.roles(got)[-2:], ["malloc", "oom"])

    def test_serializer_errors_unwrap_with_the_converted_error(self):
        rmp = self.run_full(self.pick(path=b"a", norm=b"a.rmp", fmt_err=1, cap=0x40))
        js = self.run_full(self.pick(path=b"a", norm=b"a.json", fmt_err=1))
        self.assertEqual(rmp[0], "unwrap")
        self.assertEqual(js[0], "unwrap")
        self.assertEqual(rmp[1][-1][3], tool.ERR_B_RET)
        self.assertEqual(js[1][-1][3], tool.ERR_A_RET)
        self.assertEqual(rmp[1][-1][2], 0x2B)

    def test_buffer_released_only_when_capacity_nonzero(self):
        zero = self.run_full(self.pick(path=b"a", norm=b"a.rmp", fmt_err=0, oom=0, cap=0, prep_err=0, write_err=0, len=7))
        some = self.run_full(self.pick(path=b"a", norm=b"a.rmp", fmt_err=0, oom=0, cap=0x40, prep_err=0, write_err=0, len=7))
        self.assertNotIn("free", self.roles(zero))
        self.assertIn(("free", tool.BUF, 0x40, 0), some[1])

    def test_marker_capacity_from_json_is_an_error(self):
        got = self.run_full(self.pick(path=b"a", norm=None, fmt_err=0, oom=0, cap=tool.NONE_CAP, prep_err=0, write_err=0, len=7))
        self.assertEqual(got[0], "unwrap")
        self.assertNotIn("prep", self.roles(got))
        marker_rmp = self.run_full(self.pick(path=b"a", norm=b"a.rmp", fmt_err=0, oom=0, cap=tool.NONE_CAP, prep_err=0,
                                             write_err=0, len=7))
        self.assertEqual(marker_rmp[0], "ret")

    def test_prepare_then_write_order_and_errors(self):
        ok = self.run_full(self.pick(path=b"a", norm=b"a.rmp", fmt_err=0, oom=0, cap=0x40, prep_err=0, write_err=0, len=7))
        roles = self.roles(ok)
        self.assertLess(roles.index("prep"), roles.index("write"))
        prep = self.run_full(self.pick(path=b"a", norm=b"a.rmp", fmt_err=0, cap=0x40, prep_err=1, write_err=0, len=7))
        self.assertNotIn("write", self.roles(prep))
        self.assertEqual(prep[1][-1][3], tool.PREP_ERR)
        write = self.run_full(self.pick(path=b"a", norm=b"a.rmp", fmt_err=0, cap=0x40, prep_err=0, write_err=1, len=7))
        self.assertEqual(write[1][-1][3], tool.WRITE_ERR)
        self.assertEqual(self.roles(write)[-3:], ["write", "free", "unwrap"])
        self.assertNotIn("log", self.roles(write))


class TimedRecord(Base):
    def log_row(self, got):
        return next(r for r in got[1] if r[0] == "log")

    def test_seconds_value(self):
        want = {None: 0.0, (0, 0): 0.0, (1, 0): 1.0, (5, 999_999_999): 5.999999999}
        for dur, value in want.items():
            case = dict(self.pick(path=b"/dev/null"))
            case.update(dur=dur)
            bits = self.log_row(tool.run_body(self.image, FULL, case))[4]
            self.assertEqual(bits, tool.f64_bits(value), dur)

    def test_nanoseconds_are_read_as_signed(self):
        case = dict(self.pick(path=b"/dev/null"))
        case.update(dur=(3, 0xFFFF_FFFF))
        bits = self.log_row(tool.run_body(self.image, FULL, case))[4]
        self.assertEqual(bits, tool.f64_bits(3 - 1e-9))

    def test_huge_seconds_round_once(self):
        case = dict(self.pick(path=b"/dev/null"))
        case.update(dur=((1 << 53) + 1, 1))
        bits = self.log_row(tool.run_body(self.image, FULL, case))[4]
        self.assertEqual(bits, tool.f64_bits(float(1 << 53) + 1e-9))

    def test_clock_error_logs_zero(self):
        case = dict(self.pick(path=b"/dev/null"))
        case.update(dur=None)
        self.assertEqual(self.log_row(tool.run_body(self.image, FULL, case))[4], 0)

    def test_utc_stamp_fields_are_reordered(self):
        case = dict(self.pick(path=b"/dev/null"))
        case.update(ts=(0xAAAA_0001, 0xBBBB_0002, 0xCCCC_0003))
        row = self.log_row(tool.run_body(self.image, FULL, case))
        self.assertEqual(row[5], 1)
        self.assertEqual(row[6], 0xBBBB_0002 | (0xCCCC_0003 << 32))
        self.assertEqual(row[7], 0xAAAA_0001)

    def test_once_cell_called_only_when_flag_set(self):
        for flag in (0, 1):
            case = dict(self.pick(path=b"/dev/null"))
            case.update(once=flag)
            roles = [r[0] for r in tool.run_body(self.image, FULL, case)[1]]
            self.assertEqual("once" in roles, bool(flag))

    def test_log_names_the_message_and_timestamp_format(self):
        consts = tool.full_consts(self.image)
        row = self.log_row(tool.run_body(self.image, FULL, self.pick(path=b"/dev/null")))
        self.assertEqual(tool.rodata_bytes(self.image, row[2], 21), b"serialized abci state")
        self.assertEqual(tool.rodata_bytes(self.image, row[8], row[9]), b"%Y-%m-%dT%H:%M:%S%.3fZ")
        self.assertEqual(row[1], consts["target"])


class PlainTwins(Base):
    def test_twins_agree_and_only_differ_in_the_serializer(self):
        for case in self.plain[::7]:
            a = tool.run_body(self.image, PA, case)
            b = tool.run_body(self.image, PB, case)
            self.assertEqual(a, b if a[0] == b[0] else None)
            self.assertEqual(a, tool.reconstruct(self.image, PA, case))
            self.assertEqual(b, tool.reconstruct(self.image, PB, case))
        self.assertNotEqual(tool.DIRECT[PA]["ser"], tool.DIRECT[PB]["ser"])

    def test_serializer_error_unwraps_without_timing(self):
        case = next(c for c in self.plain if c["ser_err"])
        got = tool.run_body(self.image, PA, case)
        self.assertEqual(got[0], "unwrap")
        self.assertEqual(self.roles(got), ["now", "ser", "unwrap"])


class SharedEqual(Base):
    def test_real_comparison_matches_ascii_fold(self):
        for a, b in tool.eq_cases():
            self.assertEqual(tool.run_eq(self.image, a, b), ("ret", tool.model_eq(a, b)), (a, b))

    def test_boundary_characters_do_not_fold(self):
        for a, b in ((b"@", b"`"), (b"[", b"{"), (b"Z", b"z"), (b"A", b"a"), (b"\xc1", b"\xe1")):
            self.assertEqual(tool.run_eq(self.image, a, b)[1], int(a.lower() == b.lower() and a < b"\x80"), (a, b))

    def test_wrong_models_caught(self):
        for name in tool.EQ_VARIANTS:
            self.assertTrue(any(tool.model_eq(a, b, name) != tool.run_eq(self.image, a, b)[1]
                                for a, b in tool.eq_cases()), name)


class WrongModels(Base):
    def test_full_variants_caught(self):
        for name in tool.FULL_VARIANTS:
            caught = any(tool.reconstruct(self.image, FULL, c, name) != tool.run_body(self.image, FULL, c)
                         for c in self.cases)
            self.assertTrue(caught, name)

    def test_plain_variants_caught(self):
        for name in tool.PLAIN_VARIANTS:
            caught = any(tool.reconstruct(self.image, PA, c, name) != tool.run_body(self.image, PA, c)
                         for c in self.plain)
            self.assertTrue(caught, name)


class Controls(Base):
    def test_corrupt_target_digest_rejected(self):
        saved = tool.SHA256
        tool.SHA256 = "0" * 64
        try:
            with self.assertRaises(tool.Fail):
                tool.load_image()
        finally:
            tool.SHA256 = saved

    def test_out_of_range_and_mid_function_start_rejected(self):
        with self.assertRaises(tool.Fail):
            tool.body_insns(self.image, FULL + 1)
        with self.assertRaises(Exception):
            tool.body_insns(self.image, 0x10)

    def test_flipped_jumps_change_results(self):
        case = self.pick(path=b"a", norm=b"a.rmp", fmt_err=0, oom=0, cap=0x40, prep_err=0, write_err=0, len=7)
        real = tool.run_body(self.image, FULL, case)
        changed = sum(tool.run_body(mutate(self.image, off), FULL, case) != real for _, off in tool.jcc_sites(self.image, FULL))
        self.assertGreaterEqual(changed, 12)

    def test_corrupted_extension_literal_changes_the_comparison(self):
        case = self.pick(path=b"a", norm=b"a.rmp", fmt_err=0, oom=0, cap=0x40, prep_err=0, write_err=0, len=7)
        real = tool.run_body(self.image, FULL, case)
        off = self.image.file_offset(tool.full_consts(self.image)["rmp"])
        self.assertNotEqual(tool.run_body(mutate(self.image, off), FULL, case), real)

    def test_corrupted_buffer_size_constant_changes_the_allocation(self):
        case = self.pick(path=b"a", norm=None, fmt_err=0, oom=0, cap=0x40, prep_err=0, write_err=0, len=7)
        real = tool.run_body(self.image, FULL, case)
        site = next(i for i in tool.body_insns(self.image, FULL)[2] if self.image.data[i.off:i.off + 5] == b"\xbf\x80\x00\x00\x00")
        self.assertNotEqual(tool.run_body(mutate(self.image, site.off + 1, 0x10), FULL, case), real)

    def test_unknown_callee_stops_run(self):
        case = self.pick(path=b"a", norm=None, oom=1)
        m = tool.Machine(self.image, case, FULL)
        m.roles = {}
        tool.setup(m, case, FULL)
        m.pc = FULL
        with self.assertRaises(Exception):
            for _ in range(200):
                m.step()

    def test_scalar_double_ops_cover_the_bytes(self):
        keys = {i.key for i in tool.body_insns(self.image, PA)[2] if isinstance(i.key, tuple)}
        for need in ((0x0F, 0x2A), (0x0F, 0x14), (0x0F, 0x5C), (0x0F, 0x15), (0x0F, 0x58), (0x0F, 0x5E), (0x0F, 0x2E)):
            self.assertIn(need, keys)

    def test_static_facts_from_bytes(self):
        rows = tool.call_rows(self.image, FULL)
        targets = {r[2] for r in rows}
        for name in ("ser_rmp", "ser_json", "eq", "now", "dur"):
            self.assertIn(tool.DIRECT[FULL][name], targets)
        for name in tool.USED_SLOTS[FULL]:
            self.assertIn(self.image.slots[tool.SLOTS[name]], targets, name)
        self.assertEqual(len(tool.rip_leas(self.image, FULL)), 18)
        self.assertEqual(len(tool.rip_leas(self.image, PA)), 16)

    def test_utc_words_layout(self):
        self.assertEqual(struct.calcsize("<III"), 12)


class Evidence(Base):
    def test_regeneration_matches_committed_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            summary = tool.generate(tmp)
            self.assertEqual(summary["mismatches"], 0)
            self.assertEqual(summary["mutants"]["survived"], 0)
            self.assertEqual(summary["measure"]["negative_controls"], summary["measure"]["negative_detected"])
            self.assertGreaterEqual(summary["measure"]["cases"], 10000)
            self.assertGreaterEqual(summary["measure"]["negative_controls"], 30)
            for name in FILES:
                self.assertEqual((pathlib.Path(tmp) / name).read_bytes(), (EVIDENCE / name).read_bytes(), name)


class CommittedEvidence(Base):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        import json
        cls.summary = json.loads((EVIDENCE / "summary.json").read_text())
        cls.measure = json.loads((EVIDENCE / "measure.json").read_text())

    def rows(self, name):
        lines = (EVIDENCE / name).read_text().splitlines()
        return [line.split("\t") for line in lines[1:]]

    def test_measure_matches_summary(self):
        self.assertEqual(self.measure["cases"], self.summary["cases"])
        self.assertEqual(self.measure["negative_controls"], self.measure["negative_detected"])
        parts = sum(b["cases"] for b in self.summary["bodies"].values()) + self.summary["eq_ignore_ascii_case"]["cases"]
        self.assertEqual(parts, self.summary["cases"])

    def test_no_mutant_survived_and_unreached_are_pads(self):
        verdicts = [row[3] for row in self.rows("mutants.tsv")]
        self.assertEqual(verdicts.count("survived"), 0)
        self.assertEqual(verdicts.count("killed"), self.summary["mutants"]["killed"])
        for row in self.rows("mutants.tsv"):
            if row[3] == "unreached":
                self.assertGreater(int(row[1], 16), int(row[0], 16) + 0x200)

    def test_calls_table_matches_the_stub_tables(self):
        targets = {(int(r[0], 16), int(r[3], 16)) for r in self.rows("calls.tsv")}
        for start, roles in tool.DIRECT.items():
            for address in roles.values():
                self.assertIn((start, address), targets)
        for start, names in tool.USED_SLOTS.items():
            for name in names:
                self.assertIn((start, self.image.slots[tool.SLOTS[name]]), targets)

    def test_twins_have_identical_digests(self):
        bodies = self.summary["bodies"]
        self.assertEqual(bodies["0x4e4a960"]["result_digest"], bodies["0x4e4ac70"]["result_digest"])
        self.assertTrue(self.summary["twins_agree"])
        self.assertNotEqual(bodies["0x4e4a960"]["result_digest"], bodies["0x26a2c80"]["result_digest"])

    def test_rodata_literals_come_from_bytes(self):
        lit = self.summary["rodata"]
        consts = tool.full_consts(self.image)
        self.assertEqual(lit["extension_literal"].encode(), tool.RMP_EXT)
        self.assertEqual(tool.rodata_bytes(self.image, consts["rmp"], 3), tool.RMP_EXT)
        self.assertEqual(lit["timestamp_format"].encode(), tool.rodata_bytes(self.image, consts["fmt"], 0x16))
        self.assertEqual(lit["hex_message_length"], 0x2B)

    def test_sample_rows_cover_every_outcome_family(self):
        outcomes = {row[-2].split("/")[0] for row in self.rows("cases.tsv")}
        self.assertEqual(outcomes, {"ret", "unwrap", "oom"})
        self.assertTrue(all(row[-1] == "match" for row in self.rows("cases.tsv")))

    def test_manifest_hashes_match_files(self):
        import hashlib
        for line in (EVIDENCE / "MANIFEST.sha256").read_text().splitlines():
            digest, name = line.split("  ")
            self.assertEqual(hashlib.sha256((EVIDENCE / name).read_bytes()).hexdigest(), digest, name)

    def test_packet_carries_no_server_paths(self):
        banned = [b"/" + word + b"/" for word in (b"home", b"mnt", b"srv", b"root", b"tmp", b"opt", b"var", b"etc")]
        for path in (EVIDENCE.glob("*"), ):
            for item in path:
                blob = item.read_bytes()
                self.assertFalse(any(b in blob for b in banned), item.name)
        for item in (pathlib.Path(tool.__file__), pathlib.Path(__file__)):
            blob = item.read_bytes()
            self.assertFalse(any(("/" + w + "/").encode() in blob
                                 for w in ("home", "mnt", "srv", "root", "tmp", "opt", "var", "etc")), item.name)


if __name__ == "__main__":
    unittest.main()
