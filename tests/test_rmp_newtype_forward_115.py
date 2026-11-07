"""Tests for tools/rmp_newtype_forward_115.py (node #115 forwarding rmp newtype serializers)."""
import hashlib
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import rmp_newtype_forward_115 as T  # noqa: E402

FOLDER = ROOT / "research" / "work-items" / "serialization-rmp-newtype-forward-115"


class Shared:
    image = ext = msgs = None

    @classmethod
    def load(cls):
        if cls.image is None:
            cls.image = T.Image(T.BINARY.read_bytes())
            cls.ext = T.extents(cls.image)
            cls.msgs = {r["va"]: r["msg"] for r in T.static_rows(cls.image, cls.ext)}
        return cls


class RingRecordTest(unittest.TestCase):
    """Hand-computed VecDeque::iter() splits; these do not need the binary."""

    def test_empty_ring_points_every_slice_at_the_buffer(self):
        self.assertEqual(T.ring_record(8, 0x1000, 5, 0, 0x20), [2, 0x1000] * 1 + [0x1000] * 3)

    def test_contiguous_ring(self):
        # cap 8, head 2, len 3: [2, 5) then an empty second slice at the buffer start
        self.assertEqual(T.ring_record(8, 0x1000, 2, 3, 0x20), [2, 0x1040, 0x10a0, 0x1000, 0x1000])

    def test_wrapped_ring(self):
        # cap 8, head 6, len 5: [6, 8) then [0, 3)
        self.assertEqual(T.ring_record(8, 0x1000, 6, 5, 0x10), [2, 0x1060, 0x1080, 0x1000, 0x1030])

    def test_exact_fit_does_not_split(self):
        self.assertEqual(T.ring_record(8, 0x1000, 6, 2, 0x10), [2, 0x1060, 0x1080, 0x1000, 0x1000])

    def test_head_at_capacity_is_reduced_once(self):
        # head == cap means physical index 0
        self.assertEqual(T.ring_record(4, 0x1000, 4, 2, 0x30), [2, 0x1000, 0x1060, 0x1000, 0x1000])

    def test_addresses_wrap_modulo_2_64(self):
        rec = T.ring_record(3, T.M64 - 0xf, 1, 1, 0x68)
        self.assertEqual(rec[1], (T.M64 - 0xf + 0x68) & T.M64)

    def test_tree_record_with_and_without_root(self):
        self.assertEqual(T.tree_record(0x5000, 3, 9), [1, 0, 0x5000, 3, 1, 0, 0x5000, 3, 9])
        self.assertEqual(T.tree_record(0, 3, 9), [0, 0, 0, 3, 0, 0, 0, 3, 0])

    def test_niche_selects_the_tree(self):
        self.assertEqual(T.seq_record((T.ERR_TAG, 0x5000, 1, 2), 0x20)[0], 1)
        self.assertEqual(T.seq_record((T.ERR_TAG + 1, 0x5000, 1, 0), 0x20)[0], 2)

    def test_ext_name_is_exact(self):
        self.assertTrue(T.is_ext(b"_ExtStruct"))
        for near in (b"_ExtStruc", b"_ExtStructs", b"_extstruct", b"_ExtStruct\x00"[:10] + b"x"):
            self.assertFalse(T.is_ext(near))


class BinaryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        s = Shared.load()
        cls.image, cls.ext, cls.msgs = s.image, s.ext, s.msgs

    def test_rejects_wrong_digest(self):
        data = bytearray(T.BINARY.read_bytes())
        data[0x1000] ^= 1
        with self.assertRaises(T.ToolError):
            T.Image(bytes(data))

    def test_static_rows_cover_every_body(self):
        rows = T.static_rows(self.image, self.ext)
        self.assertEqual([r["va"] for r in rows], sorted(T.BODIES))
        self.assertEqual(sum(1 for s in T.BODIES.values() if s[0] == "seq"), 29)
        self.assertEqual(sum(1 for s in T.BODIES.values() if s[0] == "tuple"), 30)
        for r in rows:
            self.assertIn(r["text"].encode(), T.EXT_MESSAGES)

    def test_seq_bodies_use_the_short_message_and_tuples_the_long_one(self):
        for r in T.static_rows(self.image, self.ext):
            want = b"expected tuple" if T.BODIES[r["va"]][0] == "seq" else b"expected i8 and bytes"
            self.assertEqual(r["text"].encode(), want, hex(r["va"]))

    def test_element_strides_come_from_the_bytes(self):
        for va, (family, _, arg, _) in T.BODIES.items():
            if family == "seq":
                self.assertEqual(T.elem_from_bytes(T.sweep(self.image, va, self.ext[va])), arg, hex(va))

    def test_wrong_declared_stride_fails_static_check(self):
        va = min(v for v, s in T.BODIES.items() if s[0] == "seq")
        saved = T.BODIES[va]
        try:
            T.BODIES[va] = (saved[0], saved[1], saved[2] + 0x10, saved[3])
            with self.assertRaises(T.ToolError):
                T.static_rows(self.image, self.ext)
        finally:
            T.BODIES[va] = saved

    def test_wrong_declared_inner_fails_static_check(self):
        va = min(v for v, s in T.BODIES.items() if s[0] == "tuple")
        saved = T.BODIES[va]
        try:
            T.BODIES[va] = (saved[0], saved[1], saved[2], saved[3] + 0x10)
            with self.assertRaises(T.ToolError):
                T.static_rows(self.image, self.ext)
        finally:
            T.BODIES[va] = saved

    def test_body_outside_any_fde_is_rejected(self):
        T.BODIES[0x226b571] = ("seq", "b", 0x30, 0x22402e0)
        try:
            with self.assertRaises(T.ToolError):
                T.extents(self.image)
        finally:
            del T.BODIES[0x226b571]

    def test_sample_of_cases_matches(self):
        cases = T.all_cases(24)
        _, bad = T.evaluate(self.image, self.ext, self.msgs, cases)
        self.assertEqual(bad, [])

    def test_model_mutants_are_detected(self):
        cases = T.all_cases(40)
        results, bad = T.evaluate(self.image, self.ext, self.msgs, cases)
        self.assertEqual(bad, [])
        for name in T.MODEL_MUTANTS:
            hit = any(T.compare(c, T.model(c, self.msgs[c["body"]], frozenset({name})), got)
                      for c, got, _ in results)
            self.assertTrue(hit, name)

    def test_flipped_element_stride_byte_is_detected(self):
        va = 0x2271df0
        site = [at for v, label, at in T.byte_sites(self.image, self.ext) if v == va and label == "elem"][0]
        cases = [c for c in T.all_cases(40) if c["body"] == va]
        _, bad = T.evaluate(self.image, self.ext, self.msgs, cases,
                            override={site: self.image.code(site, 1)[0] ^ 1}, stop_on_first=True)
        self.assertTrue(bad)

    def test_flipped_header_count_byte_is_detected(self):
        va = 0x226b990
        site = [at for v, label, at in T.byte_sites(self.image, self.ext) if v == va and label == "count"][0]
        cases = [c for c in T.all_cases(40) if c["body"] == va]
        _, bad = T.evaluate(self.image, self.ext, self.msgs, cases,
                            override={site: self.image.code(site, 1)[0] ^ 1}, stop_on_first=True)
        self.assertTrue(bad)

    def test_inner_out_of_range_target_is_an_error(self):
        va = 0x2273720
        site = [at for v, label, at in T.byte_sites(self.image, self.ext) if v == va and label == "inner-call"][0]
        cases = [c for c in T.all_cases(40) if c["body"] == va and not T.is_ext(c["name"])]
        _, bad = T.evaluate(self.image, self.ext, self.msgs, cases[:3],
                            override={site + 3: self.image.code(site + 3, 1)[0] ^ 0x40}, stop_on_first=True)
        self.assertTrue(bad)

    def test_layout_b_flag_is_inert(self):
        """Both arms of the layout-b flag test call the header writer with the same count."""
        va = 0x2273720
        base = [c for c in T.all_cases(30) if c["body"] == va and not T.is_ext(c["name"])][0]
        m = T.machine(self.image, self.ext)
        outs = set()
        for flag in (0, 2):
            c = dict(base, flag=flag, fault=None)
            got = T.run_case(m, c)
            outs.add((got["out"], got["result"], tuple(got["calls"])))
        self.assertEqual(len(outs), 1)

    def test_tree_arm_ignores_the_ring_fields(self):
        va = 0x2271df0
        m = T.machine(self.image, self.ext)
        base = [c for c in T.all_cases(30) if c["body"] == va and not T.is_ext(c["name"])][0]
        val = bytearray(base["val_bytes"])
        for i, w in enumerate((T.ERR_TAG, 0, 7, 9)):
            T.put(val, 8 * i, 8, w)
        c = dict(base, value=(T.ERR_TAG, 0, 7, 9), val_bytes=bytes(val))
        got = T.run_case(m, c)
        self.assertEqual(got["inners"][0][1], [0, 0, 0, 7, 0, 0, 0, 7, 0])

    def test_generate_is_deterministic_and_matches_the_folder(self):
        with tempfile.TemporaryDirectory() as tmp:
            T.generate(tmp)
            for name in ("bodies.tsv", "cases-sample.tsv", "controls.tsv", "coverage.tsv", "summary.json"):
                got = (pathlib.Path(tmp) / name).read_bytes()
                if FOLDER.exists():
                    self.assertEqual(got, (FOLDER / name).read_bytes(), name)
        if FOLDER.exists():
            for line in (FOLDER / "MANIFEST.sha256").read_text().splitlines():
                digest, name = line.split("  ", 1)
                self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest, name)


class FamilyTest(unittest.TestCase):
    """Per copy family and per arm checks against hand-built cases."""

    @classmethod
    def setUpClass(cls):
        s = Shared.load()
        cls.image, cls.ext, cls.msgs = s.image, s.ext, s.msgs
        cls.m = T.machine(cls.image, cls.ext)

    def base(self, va, k=4):
        stream = T.Stream("family-test/%x" % va)
        for i in range(64):
            c = T.make_case(stream, va, k + 8 * i)
            if not T.is_ext(c["name"]):
                return dict(c, fault=None)
        self.fail("no non-ext case")

    def with_value(self, c, words):
        val = bytearray(c["val_bytes"])
        for i, w in enumerate(words):
            T.put(val, 8 * i, 8, w)
        return dict(c, value=tuple(words), val_bytes=bytes(val))

    def check(self, c):
        got = T.run_case(self.m, c)
        why = T.compare(c, T.model(c, self.msgs[c["body"]]), got)
        self.assertIsNone(why, "%#x %s" % (c["body"], why))
        return got

    def test_every_copy_family_has_bodies_of_both_families(self):
        fams = {}
        for va, spec in T.BODIES.items():
            fams.setdefault(T.copy_family(va), set()).add(spec[0])
        self.assertEqual(fams, {"226": {"seq", "tuple"}, "419": {"seq", "tuple"}, "52f": {"seq", "tuple"}})

    def test_leaf_copies_start_fdes_and_are_distinct(self):
        seen = set()
        for key, leaf in T.LEAF_SETS.items():
            for role, va in leaf.items():
                self.assertIn(va, self.ext, (key, role))
                self.assertNotIn(va, seen)
                seen.add(va)

    def test_field_strides_come_from_the_bytes(self):
        for va, (family, _, _, _) in T.BODIES.items():
            if family == "tuple":
                got = T.field_stride_from_bytes(T.sweep(self.image, va, self.ext[va]))
                self.assertEqual(got, T.FIELD_ABI[va][1], hex(va))

    def test_wrong_declared_field_stride_fails_static_check(self):
        va = 0x2275a30
        saved = T.FIELD_ABI[va]
        try:
            T.FIELD_ABI[va] = (saved[0], 0x20)
            with self.assertRaises(T.ToolError):
                T.static_rows(self.image, self.ext)
        finally:
            T.FIELD_ABI[va] = saved

    def test_ring_modes_on_every_seq_stride(self):
        for va in (0x2271df0, 0x226b570, 0x226dc40, 0x419c490, 0x52f2810):
            c = self.base(va)
            for words in ((8, 0x10000, 2, 0), (8, 0x10000, 2, 3), (8, 0x10000, 6, 5), (8, 0x10000, 6, 2),
                          (8, 0x10000, 8, 3), (8, 0x10000, 11, 4), (0, 0x10000, 5, 7), (T.M64, 0x10000, 1, 2)):
                got = self.check(self.with_value(c, words))
                want = T.ring_record(words[0], words[1], words[2], words[3], T.BODIES[va][2])
                self.assertEqual(got["inners"][0][1][:T.RING_WORDS], want, (hex(va), words))

    def test_tree_arm_with_root_on_every_copy_family(self):
        for va in (0x2271df0, 0x419ddc0, 0x52f0ef0):
            c = self.with_value(self.base(va), (T.ERR_TAG, 0x7000, 4, 11))
            got = self.check(c)
            self.assertEqual(got["inners"][0][1], [1, 0, 0x7000, 4, 1, 0, 0x7000, 4, 11])

    def test_seq_result_is_whatever_the_inner_wrote(self):
        c = self.base(0x22724c0)
        c["inner_res"] = [(0x1234, 0x5678, 0x9abc)]
        got = self.check(c)
        self.assertEqual(got["result"], b"".join(x.to_bytes(8, "little") for x in (0x1234, 0x5678, 0x9abc)))

    def test_ext_arm_calls_nothing_and_writes_nothing(self):
        for va in sorted(T.BODIES):
            c = dict(self.base(va), name=T.EXT_NAME)
            got = self.check(c)
            self.assertEqual(got["calls"], [], hex(va))
            self.assertEqual(got["out"], c["prefix"], hex(va))

    def test_fault_at_every_position_of_tuple_bodies(self):
        for va in (0x226b990, 0x2273720, 0x419ed60, 0x419cb90, 0x52f9ed0):
            c = self.base(va)
            c["inner_res"] = [(T.OK_TRIPLE, 1, 2)] * T.BODIES[va][2]
            for k in range(T.fallible_count(c)):
                self.check(dict(c, fault=k))

    def test_first_failing_field_stops_the_tuple(self):
        for va in (0x226e4c0, 0x22725e0, 0x419ed60):
            c = self.base(va)
            c["inner_res"] = [(T.OK_TRIPLE, 0, 0), (T.ERR_TAG | 1, 7, 8), (T.OK_TRIPLE, 0, 0)]
            got = self.check(c)
            self.assertEqual(len(got["inners"]), 2, hex(va))
            self.assertEqual(got["result"][:8], (T.ERR_TAG | 1).to_bytes(8, "little"))

    def test_layout_a_inline_header_with_full_buffer_reserves_one_byte(self):
        for va in (0x226b990, 0x419c310, 0x52f4cc0):
            c = dict(self.base(va), flag=0, room=0)
            c["inner_res"] = [(T.OK_TRIPLE, 0, 0)] * T.BODIES[va][2]
            got = self.check(c)
            self.assertEqual(got["reserves"], [(len(c["prefix"]), 1)], hex(va))
            self.assertEqual(got["out"], c["prefix"] + bytes([0x90 | T.BODIES[va][2]]))

    def test_layout_a_flag_two_calls_the_header_writer(self):
        for va in (0x226b990, 0x419c310, 0x52f4cc0):
            c = dict(self.base(va), flag=2, room=0x40)
            c["inner_res"] = [(T.OK_TRIPLE, 0, 0)] * T.BODIES[va][2]
            got = self.check(c)
            self.assertEqual(got["calls"][0], T.leaves(va)["hdr"], hex(va))

    def test_ser_first_bodies_pass_the_serializer_in_rsi(self):
        for va in (0x22703e0, 0x2273dc0):
            c = self.base(va)
            c["inner_res"] = [(T.OK_TRIPLE, 0, 0)] * 2
            got = self.check(c)
            self.assertEqual(got["inners"], [("field", "ser,value", 0), ("field", "ser,value", 0x18)], hex(va))

    def test_value_first_bodies_with_short_stride(self):
        for va in (0x2275a30, 0x226eda0, 0x419aaa0, 0x41a3c90, 0x52f4cc0):
            c = self.base(va)
            c["inner_res"] = [(T.OK_TRIPLE, 0, 0)] * 2
            got = self.check(c)
            self.assertEqual(got["inners"], [("field", "value,ser", 0), ("field", "value,ser", 0x10)], hex(va))

    def test_folder_summary_counts(self):
        import json
        self.assertTrue(FOLDER.exists())
        summary = json.loads((FOLDER / "summary.json").read_text())
        self.assertEqual(summary["bodies"], 59)
        self.assertEqual(summary["bodies_by_copy_family"], {"226": 24, "419": 19, "52f": 16})
        self.assertEqual(summary["cases"], 59 * T.PER_BODY)
        self.assertEqual(summary["controls"], summary["controls_detected"])
        self.assertEqual(summary["body_instructions"], summary["body_instructions_executed"])
        self.assertEqual(summary["mismatches"], 0)

    def test_controls_for_one_body_per_copy_family(self):
        sites = T.byte_sites(self.image, self.ext)
        for va in (0x2275ba0, 0x41a5770, 0x52fda50):
            cases = [c for c in T.all_cases(40) if c["body"] == va]
            results, bad = T.evaluate(self.image, self.ext, self.msgs, cases)
            self.assertEqual(bad, [])
            mine = [x for x in sites if x[0] == va]
            self.assertGreaterEqual(len(mine), 5)
            for row in T.controls(self.image, self.ext, self.msgs, results, mine):
                if row[0] == "bytes":
                    self.assertIsNotNone(row[2], row)


if __name__ == "__main__":
    unittest.main()
