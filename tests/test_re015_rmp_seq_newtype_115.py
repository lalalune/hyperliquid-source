"""Tests for tools/re015_rmp_seq_newtype_115.py (node #115 rmp newtype(Vec<T>) serializers)."""
import hashlib
import json
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import re015_rmp_seq_newtype_115 as tool  # noqa: E402

PACKET = ROOT / "research" / "work-items" / "RE-015-rmp-seq-newtype-115"
IMAGE = None
EXT = None
ROWS = None


def setUpModule():
    global IMAGE, EXT, ROWS
    IMAGE = tool.Image(tool.BINARY.read_bytes())
    EXT = tool.extents(IMAGE)
    ROWS = tool.static_rows(IMAGE, EXT)


def some_cases(per_body=24, bodies=None):
    out = []
    for index, va in enumerate(sorted(tool.BODIES)):
        stream = tool.Stream(f"rmp-seq-newtype/{va:#x}")
        cases = [tool.make_case(stream, va, k, index) for k in range(per_body)]
        if bodies is None or va in bodies:
            out.extend(c for c in cases if c.get("limit") is None)
    return out


def buffered_cases(va, count=12):
    index = sorted(tool.BODIES).index(va)
    stream = tool.Stream(f"rmp-seq-newtype/{va:#x}")
    cases = [tool.make_case(stream, va, k, index) for k in range(200)]
    return [c for c in cases if tool.buffered(c["n"]) and not tool.is_ext(c["name"])][:count]


class ModelRules(unittest.TestCase):
    def test_array_header_bounds(self):
        self.assertEqual(tool.mp_array(0), b"\x90")
        self.assertEqual(tool.mp_array(15), b"\x9f")
        self.assertEqual(tool.mp_array(16), b"\xdc\x00\x10")
        self.assertEqual(tool.mp_array(0xffff), b"\xdc\xff\xff")
        self.assertEqual(tool.mp_array(0x10000), b"\xdd\x00\x01\x00\x00")
        self.assertEqual(tool.mp_array(0xffffffff), b"\xdd\xff\xff\xff\xff")

    def test_array_header_takes_u32(self):
        self.assertEqual(tool.mp_array(0x1_0000_0003), b"\x93")

    def test_ext_name_is_exact(self):
        self.assertTrue(tool.is_ext(b"_ExtStruct"))
        self.assertFalse(tool.is_ext(b"_ExtStruct!"))
        self.assertFalse(tool.is_ext(b"_ExtStruc"))
        self.assertFalse(tool.is_ext(b"_extstruct"))
        self.assertTrue(tool.is_ext(b"_ExtStruct!", {"ext-prefix"}))

    def test_config_word_mask(self):
        cfg = bytes([0x34, 0x12, 0xff, 0xff, 0xff])
        self.assertEqual(tool.config_word(cfg), 0x1234 | (0xff0101 << 16))
        self.assertEqual(tool.config_word(bytes(5)), 0)
        self.assertEqual(tool.config_word(bytes([0, 0, 2, 2, 7])), (0x070000) << 16)

    def test_buffered_split(self):
        self.assertFalse(tool.buffered(0xffffffff))
        self.assertTrue(tool.buffered(0x100000000))
        self.assertTrue(tool.buffered(0x80000000, {"split-31"}))

    def test_wrap_lengths_walk_m_elements(self):
        for _, _, stride in tool.BODIES.values():
            for m in (1, 2, 17, 40):
                for k in (0, 5, 77):
                    n = tool.wrap_len(stride, m, k)
                    self.assertTrue(tool.buffered(n))
                    self.assertLess(n, 1 << 64)
                    self.assertEqual(tool.iterations(n, stride), m)

    def test_unbounded_walk(self):
        self.assertIsNone(tool.iterations(tool.M64, 0x30))
        self.assertEqual(tool.iterations(tool.M64, 0x200), (1 << 64) // 0x200 - 1)

    def test_ext_model(self):
        c = {"body": 0x2273370, "name": b"_ExtStruct", "msg": (0x5e90a1, 14), "n": 3}
        p = tool.model(c)
        self.assertEqual(p["result"], (tool.EXT_TAG, 0x5e90a1, 14))
        self.assertEqual(p["events"], [])
        self.assertEqual(p["out"], b"")

    def test_direct_model(self):
        c = {"body": 0x2273370, "name": b"x", "msg": (0, 0), "n": 3, "fault": None, "oom": False, "cfg": bytes(5)}
        p = tool.model(c)
        self.assertEqual(p["out"], b"\x93" + bytes([0, 7, 14]))
        self.assertEqual(p["events"], [("hdr", 3), ("direct", 0), ("direct", 0x120), ("direct", 0x240)])
        self.assertIsNone(p["result"])

    def test_direct_model_element_error(self):
        c = {"body": 0x2273370, "name": b"x", "msg": (0, 0), "n": 5, "fault": 2, "oom": False, "cfg": bytes(5),
             "errw": 1}
        p = tool.model(c)
        self.assertEqual(p["result"], (1, tool.FAULT[0], tool.FAULT[1]))
        self.assertEqual(len(p["events"]), 3)

    def test_buffered_model(self):
        n = tool.wrap_len(0x120, 2, 0)
        c = {"body": 0x2273370, "name": b"x", "msg": (0, 0), "n": n, "fault": None, "oom": False,
             "cfg": bytes([1, 0, 1, 1, 1])}
        p = tool.model(c)
        cfg = tool.config_word(c["cfg"])
        self.assertEqual(p["events"], [("malloc", 0x80), ("compound", 0, 0, 0, cfg), ("compound", 0x120, 1, 1, cfg),
                                       ("hdr", 2), ("free", 0x80)])
        self.assertEqual(p["out"], b"\x92" + bytes([0x40, 0x47]))

    def test_buffered_model_oom(self):
        c = {"body": 0x2273370, "name": b"x", "msg": (0, 0), "n": 1 << 40, "fault": None, "oom": True,
             "cfg": bytes(5)}
        p = tool.model(c)
        self.assertEqual(p["boundary"], ("alloc-error", 1, 0x80))
        self.assertEqual(p["events"], [("malloc", 0x80)])


class StaticFacts(unittest.TestCase):
    def test_digest_pinned(self):
        self.assertEqual(hashlib.sha256(IMAGE.data).hexdigest(), tool.SHA256)

    def test_wrong_digest_rejected(self):
        with self.assertRaises(tool.ToolError):
            tool.Image(IMAGE.data[:-1] + bytes([IMAGE.data[-1] ^ 1]))

    def test_every_body_is_an_fde_start(self):
        for va in tool.BODIES:
            self.assertIn(va, EXT)

    def test_rows_cover_all_bodies(self):
        self.assertEqual(sorted(r["va"] for r in ROWS), sorted(tool.BODIES))
        self.assertEqual(len(ROWS), 54)

    def test_layout_rules(self):
        for r in ROWS:
            fam, layout, stride = tool.BODIES[r["va"]]
            self.assertEqual(r["flag"], tool.FLAG_AT[layout])
            self.assertEqual(r["end_fn"], tool.FAMILIES[fam]["end_" + layout])
            self.assertEqual(r["direct"] == r["compound"], layout == "a")
            self.assertEqual(r["msg"][1], len(tool.EXT_TEXT))

    def test_compound_serializer_is_a_layout_monomorph(self):
        """The compound element serializer of a layout-b body is the element serializer of a layout-a body."""
        a_elems = {r["direct"] for r in ROWS if tool.BODIES[r["va"]][1] == "a"}
        b_comp = {r["compound"] for r in ROWS if tool.BODIES[r["va"]][1] == "b"}
        self.assertTrue(a_elems & b_comp)

    def test_one_header_writer_per_family_and_layout(self):
        seen = {}
        for r in ROWS:
            fam, layout, _ = tool.BODIES[r["va"]]
            seen.setdefault((fam, layout), set()).add(r["hdr"])
        self.assertTrue(all(len(v) == 1 for v in seen.values()))
        self.assertEqual(len(seen), 6)

    def test_wrong_stride_rejected(self):
        saved = tool.BODIES[0x2273370]
        try:
            tool.BODIES[0x2273370] = ("226", "b", 0x128)
            with self.assertRaises(tool.ToolError):
                tool.body_facts(IMAGE, EXT, 0x2273370)
        finally:
            tool.BODIES[0x2273370] = saved

    def test_wrong_family_rejected(self):
        saved = tool.BODIES[0x41a0430]
        try:
            tool.BODIES[0x41a0430] = ("52f", "b", 0x120)
            with self.assertRaises(tool.ToolError):
                tool.body_facts(IMAGE, EXT, 0x41a0430)
        finally:
            tool.BODIES[0x41a0430] = saved

    def test_non_fde_start_rejected(self):
        tool.BODIES[0x2273371] = ("226", "b", 0x120)
        try:
            with self.assertRaises(tool.ToolError):
                tool.extents(IMAGE)
        finally:
            del tool.BODIES[0x2273371]

    def test_family_scan_covers_the_model(self):
        scan = tool.family_scan(IMAGE, EXT)
        modelled = {r[0] for r in scan if r[4] == "modelled"}
        self.assertEqual(modelled, set(tool.BODIES))
        excluded = {r[0] for r in scan if r[4].startswith("excluded")}
        self.assertEqual(excluded, set(tool.EXCLUDED))
        for va, size, fams, n, status in scan:
            self.assertTrue(any(lo <= va < hi for lo, hi in tool.SCAN_RANGES))
            self.assertGreaterEqual(n, 1)

    def test_excluded_share_the_pattern(self):
        """The two left-out bodies have the same six-call shape; they are excluded only for ownership."""
        for va, (fam, layout, stride) in ((0x41a3070, ("419", "b", 0x30)), (0x419d8a0, ("419", "b", 0x16))):
            tool.BODIES[va] = (fam, layout, stride)
            try:
                facts = tool.body_facts(IMAGE, EXT, va)
                self.assertEqual(facts["end_fn"], 0x41acea0)
            finally:
                del tool.BODIES[va]

    def test_family_scan_fails_on_unknown_member(self):
        tool.BODIES[0x2273371] = ("226", "b", 0x120)  # not an FDE start, so never a scanned member
        try:
            with self.assertRaises(tool.ToolError):
                tool.family_scan(IMAGE, EXT)
        finally:
            del tool.BODIES[0x2273371]

    def test_excluded_bodies_stay_out(self):
        self.assertNotIn(0x41a3070, tool.BODIES)
        self.assertNotIn(0x419d8a0, tool.BODIES)


class Evaluation(unittest.TestCase):
    def test_subset_matches(self):
        cases = some_cases(24)
        results, bad = tool.evaluate(IMAGE, EXT, ROWS, cases)
        self.assertEqual(bad, [])
        self.assertEqual(len(results), len(cases))

    def test_buffered_cases_match(self):
        for va in (0x2273370, 0x22776c0, 0x41a0430, 0x52f7840):
            cases = buffered_cases(va)
            self.assertTrue(cases)
            _, bad = tool.evaluate(IMAGE, EXT, ROWS, cases)
            self.assertEqual(bad, [], hex(va))

    def test_model_mutants_detected_on_buffered(self):
        cases = buffered_cases(0x2273370, 40) + some_cases(24, {0x2273370})
        results, bad = tool.evaluate(IMAGE, EXT, ROWS, cases)
        self.assertEqual(bad, [])
        by = {r["va"]: r for r in ROWS}
        for mut in ("cfg-nomask", "iter-minus1", "count-plus1", "end-no-copy", "err-no-free", "stride-plus8",
                    "ext-tag", "msg-len", "arr-fix17", "err-retag"):
            hit = any(tool.compare(tool.with_msg(c, by), tool.model(tool.with_msg(c, by), {mut}), got)
                      for c, got, _ in results)
            self.assertTrue(hit, mut)

    def test_byte_flips_detected(self):
        sites = [s for s in tool.byte_sites(IMAGE, EXT) if s[0] in (0x2273370, 0x52f7840)]
        self.assertGreaterEqual(len(sites), 8)
        for va, label, at, bit in sites:
            cases = buffered_cases(va, 30) + some_cases(24, {va})
            if label == "shr32":
                index = sorted(tool.BODIES).index(va)
                stream = tool.Stream(f"rmp-seq-newtype/{va:#x}")
                cases += [c for c in (tool.make_case(stream, va, k, index) for k in range(64)) if c["n"] >> 32 == 1]
            _, bad = tool.evaluate(IMAGE, EXT, ROWS, cases, override={at: IMAGE.code(at, 1)[0] ^ bit},
                                   stop_on_first=True)
            self.assertTrue(bad, f"{label}@{at:#x}")

    def test_unflipped_override_is_clean(self):
        site = tool.byte_sites(IMAGE, EXT)[0]
        cases = some_cases(16, {site[0]})
        _, bad = tool.evaluate(IMAGE, EXT, ROWS, cases, override={site[2]: IMAGE.code(site[2], 1)[0]})
        self.assertEqual(bad, [])

    def test_corrupted_result_is_detected(self):
        cases = some_cases(8, {0x2273370})
        m = tool.machine(IMAGE, EXT, ROWS)
        by = {r["va"]: r for r in ROWS}
        c = next(c for c in cases if not tool.is_ext(c["name"]))
        got = tool.run_case(m, c)
        self.assertIsNone(tool.compare(tool.with_msg(c, by), tool.model(tool.with_msg(c, by)), got))
        broken = dict(got, result=bytes([got["result"][0] ^ 1]) + got["result"][1:])
        self.assertIsNotNone(tool.compare(tool.with_msg(c, by), tool.model(tool.with_msg(c, by)), broken))
        broken = dict(got, events=got["events"][:-1])
        self.assertIsNotNone(tool.compare(tool.with_msg(c, by), tool.model(tool.with_msg(c, by)), broken))

    def test_deterministic_cases(self):
        a = some_cases(6, {0x226bd40})
        b = some_cases(6, {0x226bd40})
        self.assertEqual(a, b)


class CompoundEnd(unittest.TestCase):
    def test_end_model_rules(self):
        base = {"cap": tool.DIRECT_MARK, "blen": 0, "count": 3, "buf": bytes(range(0x80)), "fault": None}
        self.assertEqual(tool.end_model(base)["events"], [])
        p = tool.end_model(dict(base, cap=0x80, blen=2))
        self.assertEqual(p["out"], b"\x93\x00\x01")
        self.assertEqual(p["events"], [("hdr", 3), ("free", 0x80)])
        self.assertEqual(tool.end_model(dict(base, cap=0))["events"], [("hdr", 3)])
        p = tool.end_model(dict(base, cap=0x80, fault=0))
        self.assertEqual(p["result"], (tool.ERR_TAG, tool.FAULT[0], tool.FAULT[1]))
        self.assertEqual(p["events"], [("hdr", 3), ("free", 0x80)])

    def test_end_cases_match(self):
        cases = tool.end_cases(36)
        results, bad = tool.evaluate_end(IMAGE, EXT, ROWS, cases)
        self.assertEqual(bad, [])
        self.assertEqual({c["end"] for c in cases}, {f["end_" + lay] for f in tool.FAMILIES.values() for lay in "ab"})
        for name in tool.END_MUTANTS[:3]:
            self.assertTrue(any(tool.compare(c, tool.end_model(c, {name}), got) for c, got, _ in results), name)

    def test_end_byte_flips_detected(self):
        cases = tool.end_cases(36)
        sites = tool.end_byte_sites(IMAGE, EXT)
        self.assertGreaterEqual(len(sites), 6)
        self.assertEqual({s[0] for s in sites}, {f["end_" + lay] for f in tool.FAMILIES.values() for lay in "ab"})
        for va, label, at, bit in sites[:4]:
            mine = [c for c in cases if c["end"] == va]
            _, bad = tool.evaluate_end(IMAGE, EXT, ROWS, mine, override={at: IMAGE.code(at, 1)[0] ^ bit},
                                       stop_on_first=True)
            self.assertTrue(bad, f"{label}@{at:#x}")


class Evidence(unittest.TestCase):
    def test_manifest(self):
        lines = (PACKET / "MANIFEST.sha256").read_text().splitlines()
        names = set()
        for line in lines:
            digest, name = line.split("  ", 1)
            names.add(name)
            self.assertEqual(hashlib.sha256((PACKET / name).read_bytes()).hexdigest(), digest, name)
        on_disk = {p.name for p in PACKET.iterdir() if p.name != "MANIFEST.sha256"}
        self.assertEqual(names, on_disk)

    def test_summary_numbers(self):
        s = json.loads((PACKET / "summary.json").read_text())
        self.assertEqual(s["binary_sha256"], tool.SHA256)
        self.assertEqual(s["bodies"], len(tool.BODIES))
        self.assertEqual(s["mismatches"], 0)
        self.assertGreaterEqual(s["cases"], 10000)
        self.assertEqual(s["controls"], s["controls_detected"])
        self.assertGreaterEqual(s["controls"], 30)

    def test_bodies_table_regenerates(self):
        text = (PACKET / "bodies.tsv").read_text().splitlines()
        self.assertEqual(len(text), len(tool.BODIES) + 1)
        by = {r["va"]: r for r in ROWS}
        for line in text[1:]:
            cols = line.split("\t")
            r = by[int(cols[0], 16)]
            self.assertEqual(int(cols[1], 16), r["end"])
            self.assertEqual(int(cols[2]), r["insns"])
            self.assertEqual(int(cols[8], 16), r["hdr"])
            self.assertEqual(int(cols[9], 16), r["direct"])
            self.assertEqual(int(cols[10], 16), r["compound"])

    def test_family_scan_file(self):
        rows = (PACKET / "family-scan.tsv").read_text().splitlines()[1:]
        status = [r.split("\t")[4] for r in rows]
        self.assertEqual(status.count("modelled"), len(tool.BODIES))
        self.assertEqual(sum(1 for s in status if s.startswith("excluded")), len(tool.EXCLUDED))

    def test_controls_all_detected(self):
        rows = (PACKET / "controls.tsv").read_text().splitlines()[1:]
        self.assertGreaterEqual(len(rows), 30)
        self.assertTrue(all(r.split("\t")[2] == "yes" for r in rows))
        families = {r.split("\t")[0] for r in rows}
        self.assertEqual(families, {"model", "bytes", "range"})


if __name__ == "__main__":
    unittest.main()
