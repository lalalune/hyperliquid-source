"""Tests for tools/re015_rmp_write_uint_b_115.py (node #115 layout-b rmp write_uint copies and RawVec growth)."""
import hashlib
import json
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import re015_rmp_write_uint_b_115 as tool  # noqa: E402

PACKET = ROOT / "research" / "work-items" / "RE-015-rmp-write-uint-b-115"
IMAGE = EXT = CASES = None


def setUpModule():
    global IMAGE, EXT, CASES
    IMAGE = tool.Image(tool.BINARY.read_bytes())
    EXT = tool.extents(IMAGE)
    CASES = tool.all_cases()


def sample(per=90):
    """A spread over every family, role and case shape."""
    groups = {}
    for c in CASES:
        groups.setdefault((c["fam"], c["role"], c["kind"], bool(c.get("wrap")), bool(c.get("exhaustive"))), []).append(c)
    out = []
    for key in sorted(groups):
        g = groups[key]
        out.extend(g[::max(1, len(g) // per)])
    return out


def model_run(cap, ln, v, fail_at=None, fam="226", mut=frozenset()):
    st = tool.VecModel(cap, ln, {i: 0x11 for i in range(ln)}, fail_at, mut)
    st.family_byte_tag = fam in tool.BYTE_TAG_FAMILIES
    res = tool.write_uint_b(st, v)
    return st, res


class ModelRules(unittest.TestCase):
    def test_forms_and_payload_order(self):
        for v, tag, payload in ((0x80, 0xcc, b"\x80"), (0xff, 0xcc, b"\xff"), (0x100, 0xcd, b"\x01\x00"),
                                (0xffff, 0xcd, b"\xff\xff"), (0x10000, 0xce, b"\x00\x01\x00\x00"),
                                (0xffffffff, 0xce, b"\xff\xff\xff\xff"),
                                (0x100000000, 0xcf, b"\x00\x00\x00\x01\x00\x00\x00\x00")):
            st, res = model_run(64, 0, v)
            self.assertEqual(res, (2, tag))
            got = bytes(st.bufs[0][i] for i in range(st.len))
            self.assertEqual(got, bytes([tag]) + payload)

    def test_fixint_marker_and_byte(self):
        st, res = model_run(4, 0, 0x7f)
        self.assertEqual(res[0], 2)
        self.assertEqual(res[1].to_bytes(8, "little")[:2], b"\x00\x7f")
        self.assertEqual(st.bufs[0][0], 0x7f)

    def test_first_growth_failure_is_code_zero(self):
        st, res = model_run(0, 0, 5, fail_at=0)
        self.assertEqual(res, (0, tool.ERR_WORD))
        self.assertEqual(st.events, [("malloc", 8)])

    def test_second_growth_failure_is_code_one_after_tag(self):
        st, res = model_run(2, 1, 0x100, fail_at=0)
        self.assertEqual(res, (1, tool.ERR_WORD))
        self.assertEqual(st.len, 2)                     # the tag byte stays written
        self.assertEqual(st.bufs[0][1], 0xcd)

    def test_doubling_and_minimum(self):
        st, _ = model_run(0, 0, 1)
        self.assertEqual(st.cap, 8)
        st, _ = model_run(8, 8, 1)
        self.assertEqual(st.cap, 16)
        st, _ = model_run(5, 5, 1)
        self.assertEqual(st.cap, 10)
        st, _ = model_run(3, 3, 1)
        self.assertEqual(st.cap, 8)

    def test_finish_grow_contract(self):
        st = tool.VecModel(0, 0, {}, None)
        self.assertEqual(tool.finish_grow(st, 0, 0, 8, 1), (True, (0, 8, 0)))
        self.assertEqual(st.events, [])
        ok, _ = tool.finish_grow(st, 0, 1 << 63, 1, 1)
        self.assertFalse(ok)
        self.assertEqual(st.events, [])                 # refused before any allocator call
        ok, out = tool.finish_grow(st, 4, 16, 32, 1)
        self.assertTrue(ok)
        self.assertEqual(st.events, [("arealloc", 16, 4, 5)])
        self.assertEqual(tool.tzcnt(0), 64)

    def test_reserve_minimum_capacity_by_element_size(self):
        for elem, want in ((1, 8), (2, 4), (0x400, 4), (0x401, 1)):
            st = tool.VecModel(0, 0, {}, None)
            self.assertIsNone(tool.reserve_model(st, 0, 1, elem))
            self.assertEqual(st.cap, want)
        st = tool.VecModel(0, 0, {}, None)
        self.assertEqual(tool.reserve_model(st, 0, 1, 0), (0, 0))


class StaticFacts(unittest.TestCase):
    def test_three_families_read_from_bytes(self):
        rows = tool.facts(IMAGE, EXT)
        self.assertEqual([r[0] for r in rows], ["226", "419", "52f"])

    def test_only_52f_has_a_u8_helper(self):
        self.assertIsNone(tool.FAMILIES["226"]["u8"])
        self.assertIsNone(tool.FAMILIES["419"]["u8"])
        self.assertIsNotNone(tool.FAMILIES["52f"]["u8"])

    def test_allocator_slots_are_relative_relocations(self):
        for slot in list(tool.ALLOC_GOTS.values()) + [tool.ALLOC_ERROR_GOT]:
            self.assertIn(slot, IMAGE.relative)
            self.assertNotIn(slot, IMAGE.imports)

    def test_wrong_digest_is_rejected(self):
        with self.assertRaises(tool.ToolError):
            tool.Image(IMAGE.data[:-1] + bytes([IMAGE.data[-1] ^ 1]))

    def test_wrong_helper_address_is_rejected(self):
        saved = tool.FAMILIES["419"]["u32"]
        tool.FAMILIES["419"]["u32"] = saved + 1
        try:
            with self.assertRaises((tool.ToolError, KeyError)):
                tool.facts(IMAGE, tool.extents(IMAGE))
        finally:
            tool.FAMILIES["419"]["u32"] = saved

    def test_wrong_tag_is_rejected(self):
        tool.TAGS["u32"] = 0xcd
        try:
            with self.assertRaises(tool.ToolError):
                tool.facts(IMAGE, EXT)
        finally:
            tool.TAGS["u32"] = 0xce


class RealBytes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = sample()

    def test_bytes_match_model(self):
        _, bad = tool.evaluate(IMAGE, self.cases)
        self.assertEqual([(c["fam"], c["role"], c["k"], why) for c, why in bad[:3]], [])

    def test_every_model_mutant_is_caught(self):
        results, bad = tool.evaluate(IMAGE, CASES[::3])
        self.assertFalse(bad)
        for name, hit in ((n, h) for _, n, h in tool.model_controls(CASES, [(c, g, None) for c, g, _ in results])):
            self.assertIsNotNone(hit, name)

    def test_byte_flips_are_caught(self):
        pool = [c for c in CASES if c["fam"] == "226" and c["role"] == "wu" and not c.get("big")][::40]
        site_value = None
        for v, f in tool.sweep(IMAGE, tool.FAMILIES["226"]["wu"], EXT[tool.FAMILIES["226"]["wu"]]):
            if f["op"] == 0x81 and f.get("imm") == 0x100:
                site_value = v + f["len"] - 3        # the 0x01 byte of the 0x100 immediate
                break
        self.assertIsNotNone(site_value)
        self.assertEqual(IMAGE.code(site_value, 1)[0], 0x01)
        _, bad = tool.evaluate(IMAGE, pool, override={site_value: 0x02}, stop_on_first=True)
        self.assertTrue(bad)

    def test_tag_flip_is_caught(self):
        va = tool.FAMILIES["419"]["u32"]
        site = next(v + f["len"] - 1 for v, f in tool.sweep(IMAGE, va, EXT[va])
                    if f["op"] == 0xc6 and f["rm"][0] == "m" and (f["imm"] & 0xff) == 0xce)
        pool = [c for c in CASES if c["fam"] == "419" and c["role"] == "u32"][:50]
        _, bad = tool.evaluate(IMAGE, pool, override={site: 0xcf}, stop_on_first=True)
        self.assertTrue(bad)

    def test_wrong_expectation_is_a_mismatch(self):
        c = next(c for c in CASES if c["fam"] == "226" and c["role"] == "wu" and c["cap"] == 5 and c["len"] == 2
                 and c["v"] == 0x100 and c["fail_at"] is None)
        m = tool.machine(IMAGE)
        got = tool.run_case(m, c)
        want = tool.expect(c)
        self.assertIsNone(tool.compare(c, want, got))
        want = dict(want, len=want["len"] + 1)
        self.assertEqual(tool.compare(c, want, got), "vector")
        want = tool.expect(c)
        want["events"] = want["events"] + [("malloc", 1)]
        self.assertEqual(tool.compare(c, want, got), "events")

    def test_failed_growth_leaves_old_buffer(self):
        c = next(c for c in CASES if c["fam"] == "52f" and c["role"] == "wu" and c["cap"] == 4 and c["len"] == 3
                 and c["v"] == 0x10000 and c["fail_at"] == 0)
        m = tool.machine(IMAGE)
        got = tool.run_case(m, c)
        self.assertEqual(got["cap"], 4)
        self.assertEqual(int.from_bytes(got["result"][:8], "little"), 1)
        self.assertEqual(got["len"], 4)
        self.assertEqual(got["ptr"], tool.BUF_AT)


class MoreRealBytes(unittest.TestCase):
    def run_one(self, fam, role, **want):
        stream = tool.Stream("unit")
        fail_at = want.get("fail_at")
        if role == "grow":
            c = {"kind": "grow", "fam": fam, "role": role, "k": 0, "cap": want["cap"], "newcap": want["newcap"],
                 "align": want["align"], "elem": want["elem"], "fail_at": fail_at}
        elif role == "reserve":
            c = {"kind": "reserve", "fam": fam, "role": role, "k": 0, "cap": want["cap"], "len": want["len"],
                 "add": want["add"], "elem": want["elem"], "fail_at": fail_at, "buf": b""}
        else:
            c = tool.state_case(stream, fam, role, 0, want["cap"], want["len"], want.get("v", 1), fail_at)
        got = tool.run_case(tool.machine(IMAGE), c)
        self.assertIsNone(tool.compare(c, tool.expect(c), got), (fam, role, want))
        return c, got

    def test_marker_width_differs_by_family(self):
        for fam, full in (("226", True), ("419", False), ("52f", True)):
            c, got = self.run_one(fam, "wu", cap=64, len=0, v=0x10000, fail_at=None)
            word = int.from_bytes(got["result"][8:16], "little")
            self.assertEqual(word & 0xff, 0xce)
            self.assertEqual(word >> 8 == 0, full, fam)

    def test_fixint_result_bytes_in_every_family(self):
        for fam in sorted(tool.FAMILIES):
            c, got = self.run_one(fam, "wu", cap=64, len=0, v=0x7f, fail_at=None)
            self.assertEqual(got["result"][:10], (2).to_bytes(8, "little") + b"\x00\x7f")
            self.assertEqual(got["len"], 1)

    def test_full_buffer_doubles_in_every_family(self):
        for fam in sorted(tool.FAMILIES):
            c, got = self.run_one(fam, "wu", cap=8, len=8, v=1, fail_at=None)
            self.assertEqual(got["cap"], 16)
            self.assertEqual(got["events"], [("realloc", 16, 8)])

    def test_empty_vector_mallocs_eight(self):
        for fam in sorted(tool.FAMILIES):
            c, got = self.run_one(fam, "wu", cap=0, len=0, v=1, fail_at=None)
            self.assertEqual(got["events"], [("malloc", 8)])

    def test_first_growth_failure_reports_zero(self):
        for fam in sorted(tool.FAMILIES):
            c, got = self.run_one(fam, "wu", cap=0, len=0, v=0x100, fail_at=0)
            self.assertEqual(int.from_bytes(got["result"][:8], "little"), 0)
            self.assertEqual(int.from_bytes(got["result"][8:16], "little"), tool.ERR_WORD)
            self.assertEqual(got["len"], 0)

    def test_second_growth_failure_reports_one(self):
        for fam in sorted(tool.FAMILIES):
            c, got = self.run_one(fam, "wu", cap=3, len=2, v=0x10000, fail_at=0)
            self.assertEqual(int.from_bytes(got["result"][:8], "little"), 1)
            self.assertEqual(got["len"], 3)

    def test_helper_direct_return_codes(self):
        for fam in sorted(tool.FAMILIES):
            for role in ("u16", "u32", "u64"):
                c, got = self.run_one(fam, role, cap=0, len=0, fail_at=0)
                self.assertEqual(got["rax"], 0)
                c, got = self.run_one(fam, role, cap=0, len=0, fail_at=None)
                self.assertEqual(got["rax"], 2)

    def test_wrapped_length_reaches_carry_check(self):
        c = next(c for c in CASES if c["fam"] == "226" and c.get("wrapcase") and c["v"] == 0x100
                 and c["len"] == (1 << 64) - 3 and c["cap"] == ((1 << 64) - 3 + 2) % (1 << 64))
        self.assertTrue(c["wrap"])
        got = tool.run_case(tool.machine(IMAGE), c)
        self.assertIsNone(tool.compare(c, tool.expect(c), got))
        self.assertEqual(int.from_bytes(got["result"][:8], "little"), 1)
        self.assertEqual(got["events"], [])

    def test_finish_grow_refusal_has_no_allocator_call(self):
        c, got = self.run_one("419", "grow", cap=0, newcap=1 << 63, align=1, elem=1)
        self.assertEqual(got["events"], [])
        self.assertEqual(int.from_bytes(got["result"][:8], "little"), 1)

    def test_reserve_zero_element_calls_alloc_error(self):
        c, got = self.run_one("52f", "reserve", elem=0, cap=0, len=0, add=1)
        self.assertEqual(got["boundary"][0], "alloc-error")
        self.assertEqual(got["boundary"][1], 0)

    def test_case_set_is_deterministic(self):
        again = tool.all_cases()
        self.assertEqual(len(again), len(CASES))
        self.assertEqual([(c["fam"], c["k"], c["cap"], c["v"] if "v" in c else 0) for c in again[::97]],
                         [(c["fam"], c["k"], c["cap"], c["v"] if "v" in c else 0) for c in CASES[::97]])


class Packet(unittest.TestCase):
    def test_measure_matches_summary_and_manifest(self):
        if not PACKET.exists():
            self.fail("packet folder missing")
        measure = json.loads((PACKET / "measure.json").read_text())
        summary = json.loads((PACKET / "summary.json").read_text())
        self.assertEqual(measure["cases"], summary["cases"])
        self.assertEqual(measure["negative_controls"], summary["controls"])
        self.assertEqual(measure["negative_detected"], summary["controls_detected"])
        self.assertEqual(summary["mismatches"], 0)
        self.assertGreaterEqual(summary["cases"], 10000)
        self.assertGreaterEqual(summary["controls"], 30)
        for line in (PACKET / "MANIFEST.sha256").read_text().splitlines():
            digest, name = line.split("  ", 1)
            self.assertEqual(hashlib.sha256((PACKET / name).read_bytes()).hexdigest(), digest, name)

    def test_summary_binary_digest(self):
        summary = json.loads((PACKET / "summary.json").read_text())
        self.assertEqual(summary["binary_sha256"], tool.SHA256)


if __name__ == "__main__":
    unittest.main()
