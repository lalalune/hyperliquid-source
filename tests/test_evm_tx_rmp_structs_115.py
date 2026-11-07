"""Tests for tools/evm_tx_rmp_structs_115.py (node #115 EVM transaction / block header rmp struct serializers)."""
import hashlib
import pathlib
import shutil
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import evm_tx_rmp_structs_115 as T  # noqa: E402

FOLDER = ROOT / "research" / "work-items" / "evm-tx-rmp-struct-serializers-115"
FILES = ("bodies.tsv", "cases-sample.tsv", "controls.tsv", "fields.tsv", "inline-cases-sample.tsv", "roles.tsv",
         "summary.json", "unreached.tsv")


def setUpModule():
    global IMAGE, EXT, CASES
    data = T.BINARY.read_bytes()
    if hashlib.sha256(data).hexdigest() != T.SHA256:
        raise AssertionError("node #115 binary digest mismatch")
    IMAGE = T.Image(data)
    EXT = T.extents(IMAGE)
    CASES = T.all_cases(40)


def by_body(cases, va):
    return [c for c in cases if c["body"] == va]


def case_for(va, flag, fault=-1, st=None):
    fam, struct_ = T.BODIES[va]
    c = {"body": va, "family": fam, "struct": struct_, "k": 0, "st": bytearray(st or bytes(T.ST_SIZE)),
         "ser": bytearray(16), "flag": flag, "fault": -1, "plan": [], "okplan": []}
    c["ser"][T.FLAG_AT] = flag
    calls, _ = T.model(c)
    c["fault"] = fault
    for rec in calls:
        kind = T.ROLE_KIND[rec[0]]
        okw = T.WRITER_OK if kind in ("rax_writer", "slot_writer") else T.OK_TAG
        c["okplan"].append((okw, 0x11, 0x22))
        c["plan"].append((0x0bad1, 0x0bad2, 0x0bad3))
    return c


class StaticTests(unittest.TestCase):
    def test_every_body_matches_its_field_table(self):
        rows = T.statics_of(IMAGE, EXT)
        self.assertEqual(len(rows), 13)
        self.assertEqual(sum(r["insns"] for r in rows.values()), 2158)
        for va, r in rows.items():
            self.assertEqual(r["end"], EXT[va])
            self.assertEqual(r["family"], T.BODIES[va][0])

    def test_family_copies_share_the_field_table(self):
        pairs = {}
        for va, (fam, struct_) in T.BODIES.items():
            pairs.setdefault(struct_, {})[fam] = va
        self.assertEqual(sorted(k for k, v in pairs.items() if len(v) == 2),
                         ["destination_call", "eip1559", "eip2930", "eip4844", "eip7702", "legacy"])
        self.assertEqual(sorted(pairs["block_header"]), ["a"])

    def test_role_table_is_one_to_one(self):
        seen = {}
        for role, kind, a, b in T.ROLES:
            for va in (a, b):
                if va is not None:
                    self.assertNotIn(va, seen)
                    seen[va] = role

    def test_wrong_role_address_is_rejected(self):
        saved = dict(T.ROLE_OF)
        try:
            T.ROLE_OF[0x25e8750] = ("b", "str")
            with self.assertRaises(T.ToolError):
                T.body_row(IMAGE, EXT, 0x22f2a20)
        finally:
            T.ROLE_OF.clear()
            T.ROLE_OF.update(saved)

    def test_wrong_field_name_is_rejected(self):
        saved = T.STRUCTS["legacy"]
        try:
            rows = list(saved[1])
            rows[1] = ("nounce",) + rows[1][1:]
            T.STRUCTS["legacy"] = (saved[0], rows)
            with self.assertRaises(T.ToolError):
                T.body_row(IMAGE, EXT, 0x2331bf0)
        finally:
            T.STRUCTS["legacy"] = saved

    def test_wrong_header_count_is_rejected(self):
        saved = T.STRUCTS["eip1559"]
        try:
            T.STRUCTS["eip1559"] = (saved[0] + 1, saved[1])
            with self.assertRaises(T.ToolError):
                T.body_row(IMAGE, EXT, 0x2332430)
        finally:
            T.STRUCTS["eip1559"] = saved

    def test_wrong_header_tag_byte_is_rejected(self):
        saved = T.HEADER_TERMS
        try:
            T.HEADER_TERMS = tuple((k, o + 1 if o == 0x29d else o) for k, o in saved)
            with self.assertRaises(T.ToolError):
                T.body_row(IMAGE, EXT, 0x22daf00)
        finally:
            T.HEADER_TERMS = saved

    def test_address_that_is_not_an_fde_start_is_rejected(self):
        saved = dict(T.BODIES)
        try:
            T.BODIES[0x22f2a21] = ("a", "destination_call")
            with self.assertRaises(T.ToolError):
                T.extents(IMAGE)
        finally:
            T.BODIES.clear()
            T.BODIES.update(saved)

    def test_corrupted_binary_digest_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = pathlib.Path(tmp) / "hl-node"
            data = bytearray(T.BINARY.read_bytes())
            data[0x1000] ^= 0xff
            bad.write_bytes(bytes(data))
            saved = T.BINARY
            try:
                T.BINARY = bad
                with self.assertRaises(T.ToolError):
                    T.generate(pathlib.Path(tmp) / "out", per_body=2)
            finally:
                T.BINARY = saved


class ModelTests(unittest.TestCase):
    def test_keys_only_when_flag_is_exactly_one(self):
        # four names are written by the body; "data" is passed to the keyed writer, which writes it itself
        for flag, keys in ((0, 0), (1, 4), (2, 0), (0xff, 0)):
            calls, res = T.model(case_for(0x22f2a20, flag))
            self.assertEqual(sum(1 for r in calls if r[0] == "str"), keys)
            self.assertEqual(calls[0][0], "hdr_map" if flag else "hdr_seq")
            self.assertEqual(res, (T.OK_TAG,))

    def test_legacy_chain_id_presence(self):
        for w0, n in ((0, 6), (1, 7), (2, 7), (1 << 63, 7)):
            st = bytearray(T.ST_SIZE)
            st[0:8] = w0.to_bytes(8, "little")
            calls, _ = T.model(case_for(0x2331bf0, 1, st=bytes(st)))
            self.assertEqual(calls[0][3], n)
            self.assertEqual(any(r[0] == "opt_chain" for r in calls), n == 7)

    def test_block_header_count_adds_raw_tags(self):
        st = bytearray(T.ST_SIZE)
        self.assertEqual(T.header_count(st), 15)
        st[0] = 1
        self.assertEqual(T.header_count(st), 16)
        st[0x27c] = 2          # not a canonical bool: counted as 2, field skipped (presence wants == 1)
        st[0x10:0x18] = (1 << 32).to_bytes(8, "little")  # low 32 bits 0: count +0, field present (!= 0)
        self.assertEqual(T.header_count(st), 18)
        c = case_for(0x22daf00, 1, st=bytes(st))
        calls, _ = T.model(c)
        roles = [r[0] for r in calls]
        self.assertNotIn("kf_opt_b256", roles)
        self.assertIn("if_opt_blob_gas_used", roles)
        self.assertEqual(T.header_count(st, frozenset(["count-presence-only"])), 17)

    def test_block_header_count_wraps_at_32_bits(self):
        st = bytearray(T.ST_SIZE)
        st[0x30:0x38] = 0xffffffff.to_bytes(8, "little")
        self.assertEqual(T.header_count(st), 14)

    def test_error_shapes(self):
        c = case_for(0x22f2a20, 1, fault=0)
        self.assertEqual(T.model(c)[1], (T.ERR_TAG, 0x0bad1, 0x0bad2))     # header: slot writer, wrapped
        c = case_for(0x22f2a20, 1, fault=1)
        self.assertEqual(T.model(c)[1], (T.ERR_TAG, 0x0bad1, 0x0bad2))     # name: rax writer, wrapped
        c = case_for(0x22f2a20, 1, fault=2)
        self.assertEqual(T.model(c)[1], (0x0bad1, 0x0bad2, 0x0bad3))       # nested: copied whole
        self.assertEqual(len(T.model(c)[0]), 3)                           # nothing after the failing call

    def test_family_b_copies_u128_to_the_stack(self):
        st = bytes(range(256)) * 3
        a = T.model(case_for(0x2331bf0, 0, st=st))[0]
        b = T.model(case_for(0x44ec9f0, 0, st=st))[0]
        ua = [r for r in a if r[0] == "u128"][0]
        ub = [r for r in b if r[0] == "u128"][0]
        self.assertEqual(ua[2], ("S", 0x30))
        self.assertEqual(ub[2], ("copy", st[0x30:0x40]))


class EvaluationTests(unittest.TestCase):
    def test_sample_matches_the_original_bytes(self):
        _, bad, m = T.evaluate(IMAGE, EXT, CASES)
        self.assertEqual(bad, [])
        self.assertEqual(len(CASES), 13 * 40)

    def test_every_fault_position_is_exercised(self):
        for va in T.BODIES:
            faults = {c["fault"] for c in T.all_cases(200) if c["body"] == va}
            self.assertIn(-1, faults)
            self.assertIn(0, faults)
            self.assertGreaterEqual(len(faults), 8)

    def test_model_mutants_are_detected(self):
        for mut in T.MODEL_MUTANTS:
            _, bad, _ = T.evaluate(IMAGE, EXT, CASES, frozenset([mut]), stop_on_first=True)
            self.assertTrue(bad, mut)

    def test_byte_flips_are_detected(self):
        sites = T.byte_sites(IMAGE, EXT)
        self.assertGreaterEqual(len(sites), 60)
        for s in sites[::5]:
            override = {s["at"]: s["old"] ^ s["xor"]}
            _, bad, _ = T.evaluate(IMAGE, EXT, by_body(CASES, s["body"]), override=override, stop_on_first=True)
            self.assertTrue(bad, s)

    def test_unmodified_override_is_not_a_detection(self):
        s = T.byte_sites(IMAGE, EXT)[0]
        _, bad, _ = T.evaluate(IMAGE, EXT, by_body(CASES, s["body"]), override={s["at"]: s["old"]})
        self.assertEqual(bad, [])

    def test_stub_rejects_a_result_slot_off_the_stack(self):
        c = case_for(0x22f2a20, 1)
        m = T.machine(IMAGE, EXT)
        m.reset()
        T.install(m, c)
        m.calls = []
        m.regs[7] = T.ST_AT
        with self.assertRaises(T.ToolError):
            m.stubs[0x25e7670](m)


class InlineTests(unittest.TestCase):
    def test_static_rows(self):
        for va in T.INLINE_BODIES:
            r = T.inline_row(IMAGE, EXT, va)
            self.assertEqual((r["insns"], r["calls"]), (206, 13))

    def test_header_byte_recipe(self):
        self.assertEqual([T.inline_header_byte(f) for f in (0, 1, 2, 3, 0xff)], [0x95, 0x85, 0xb5, 0xa5, 0xe5])

    def test_sample_matches(self):
        cases = T.inline_cases(60)
        _, bad, _ = T.inline_evaluate(IMAGE, EXT, cases)
        self.assertEqual(bad, [])

    def test_reserve_threshold_is_spare_below_name_length(self):
        st = bytes(T.ST_SIZE)
        ser = bytearray(0x20)
        ser[T.VFLAG_AT] = 1
        base = {"body": 0x22f2c20, "family": "a", "k": 0, "st": st, "ser": ser, "flag": 1, "prefix": b"",
                "extra": 0, "fault": -1, "plan": [], "okplan": []}
        # after the header byte and the 0xb5 marker the spare room is slack - 2; 21 bytes fit only if spare >= 21
        c = dict(base, cap=23)
        self.assertNotIn(("vec_reserve", 2, 21), T.inline_model(c)[0])
        c = dict(base, cap=22)
        self.assertIn(("vec_reserve", 2, 21), T.inline_model(c)[0])
        c = dict(base, cap=0)
        self.assertEqual(T.inline_model(c)[0][0], ("vec_reserve", 0, 1))

    def test_inline_mutants_are_detected(self):
        cases = T.inline_cases(200)
        for mut in T.INLINE_MUTANTS:
            _, bad, _ = T.inline_evaluate(IMAGE, EXT, cases, frozenset([mut]), stop_on_first=True)
            self.assertTrue(bad, mut)

    def test_reserve_outside_contract_is_rejected(self):
        c = T.inline_cases(1)[0]
        m = T.machine(IMAGE, EXT)
        m.reset()
        T.inline_install(m, c)
        m.add_region(T.VEC_AT, 0x20, bytes(0x20))
        m.regs[7], m.regs[6], m.regs[2], m.regs[1], m.regs[8] = T.VEC_AT, 5, 1, 1, 1
        with self.assertRaises(T.ToolError):
            m.stubs[0x231e050](m)


class EvidenceTests(unittest.TestCase):
    def test_regenerated_evidence_is_byte_identical(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = pathlib.Path(tmp) / "out"
            summary = T.generate(out)
            self.assertEqual(summary["cases"], 15000)
            self.assertEqual(summary["inline_cases"], 2000)
            self.assertEqual(summary["body_instructions_reached"], summary["body_instructions"])
            self.assertEqual(summary["mismatches"], 0)
            self.assertEqual(summary["controls_detected"], summary["controls"])
            for name in FILES:
                self.assertEqual((out / name).read_bytes(), (FOLDER / name).read_bytes(), name)

    def test_manifest_lists_every_file(self):
        rows = {}
        for line in (FOLDER / "MANIFEST.sha256").read_text().splitlines():
            digest, name = line.split("  ", 1)
            rows[name] = digest
        self.assertEqual(sorted(rows), sorted(FILES + ("README.md",)))
        for name, digest in rows.items():
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest, name)


if __name__ == "__main__":
    unittest.main()
