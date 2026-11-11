"""Tests for tools/re015_rmp_vecdeque_u64_115.py (node #115 rmp newtype(VecDeque<u64>) serializers)."""
import hashlib
import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import re015_rmp_vecdeque_u64_115 as tool  # noqa: E402

PACKET = ROOT / "research" / "work-items" / "RE-015-rmp-vecdeque-u64-115"
IMAGE = EXT = ROWS = CROWS = ROLES = LOCS = None


def setUpModule():
    global IMAGE, EXT, ROWS, CROWS, ROLES, LOCS
    IMAGE = tool.Image(tool.BINARY.read_bytes())
    EXT = tool.extents(IMAGE)
    ROWS, CROWS = tool.static_rows(IMAGE, EXT)
    ROLES = tool.roles_for(ROWS, CROWS)
    LOCS = {va: ch["loc"] for va, ch in CROWS.items()}


def small_cases(per_body=48, per_chain=36):
    return [c for c in tool.all_cases(per_body, per_chain, LOCS) if not c.get("big")]


def run(cases, mut=frozenset(), override=None, stop=False):
    return tool.evaluate(IMAGE, EXT, ROWS, ROLES, cases, mut, override, stop)


class ModelRules(unittest.TestCase):
    def test_array_header_bounds(self):
        self.assertEqual(tool.mp_array(0), b"\x90")
        self.assertEqual(tool.mp_array(15), b"\x9f")
        self.assertEqual(tool.mp_array(16), b"\xdc\x00\x10")
        self.assertEqual(tool.mp_array(0xffff), b"\xdc\xff\xff")
        self.assertEqual(tool.mp_array(0x10000), b"\xdd\x00\x01\x00\x00")
        self.assertEqual(tool.mp_array(0x1_0000_0003), b"\x93")

    def test_write_uint_forms(self):
        def enc(v, **kw):
            vec = tool.VecSim(64, 0, [])
            tool.write_uint(vec, v, **kw)
            return bytes(vec.out)
        self.assertEqual(enc(0x7f), b"\x7f")
        self.assertEqual(enc(0x80), b"\xcc\x80")
        self.assertEqual(enc(0xff), b"\xcc\xff")
        self.assertEqual(enc(0x100), b"\xcd\x01\x00")
        self.assertEqual(enc(0xffff), b"\xcd\xff\xff")
        self.assertEqual(enc(0x10000), b"\xce\x00\x01\x00\x00")
        self.assertEqual(enc(0xffffffff), b"\xce\xff\xff\xff\xff")
        self.assertEqual(enc(0x100000000), b"\xcf\x00\x00\x00\x01\x00\x00\x00\x00")
        self.assertEqual(enc(0x80, mut={"uint-80"}), b"\x80")

    def test_write_uint_reserve_contract(self):
        ev = []
        vec = tool.VecSim(1, 0, ev)
        tool.write_uint(vec, 0x10000, frozenset())
        self.assertEqual(bytes(vec.out), b"\xce\x00\x01\x00\x00")
        self.assertEqual(ev, [("res", 1, 4)])

    def test_ext_name_is_exact(self):
        self.assertTrue(tool.is_ext(b"_ExtStruct"))
        self.assertFalse(tool.is_ext(b"_ExtStruct!"))
        self.assertFalse(tool.is_ext(b"_extstruct"))
        self.assertTrue(tool.is_ext(b"_ExtStruct!", {"ext-prefix"}))

    def test_config_word_mask(self):
        cfg = bytes([0x34, 0x12, 0xff, 0xff, 0xff])
        self.assertEqual(tool.config_word(cfg), 0x1234 | (0xff0101 << 16))
        self.assertEqual(tool.config_word(bytes(5)), 0)

    def test_deque_slices(self):
        self.assertEqual(tool.deque_slices(8, 3, 4), (3, 7, 0, 4))      # contiguous
        self.assertEqual(tool.deque_slices(8, 6, 4), (6, 8, 2, 4))      # wrapped: 2 + 2
        self.assertEqual(tool.deque_slices(8, 8, 3), (0, 3, 0, 3))      # head == cap folds to 0
        self.assertEqual(tool.deque_slices(8, 11, 3), (3, 6, 0, 3))
        self.assertEqual(tool.deque_slices(8, 5, 0), (0, 0, 0, 0))      # empty ignores head
        self.assertEqual(tool.deque_slices(8, 8, 3, {"dq-no-subcap"})[0], 8)

    def test_wrap_length_is_finite_walk(self):
        s, e, back, total = tool.deque_slices(6, 4, (6 - 4) + (3 << 61) + 5)
        self.assertEqual((s, e), (4, 6))
        self.assertEqual((back * 8) & tool.M64, 40)
        self.assertGreaterEqual(total, 1 << 32)

    def test_walk_order_and_cursor(self):
        words = list(range(300))
        ev, vec = [], tool.VecSim(64, 0, [])
        res, counter, cur, panic = tool.walk_model(words, 8, 24, 0, 16, "direct", 0, vec, None, [0], ev, 0)
        self.assertIsNone(res)
        self.assertEqual([e[1] for e in ev], [1, 2, 0, 1])
        self.assertEqual(ev[0][3:5], (16, 0))               # cursor advanced before the write
        self.assertEqual(cur, [24, 16])

    def test_counter_panics_at_u32_max(self):
        ev, vec = [], tool.VecSim(64, 0, [])
        res, counter, cur, panic = tool.walk_model([5] * 4, 0, 16, 0, 0, "buffered", 0xfffffffe, vec, None, [0], ev, 0)
        self.assertTrue(panic)
        self.assertEqual(len(ev), 2)
        self.assertEqual(counter, 0xffffffff)

    def test_ext_model(self):
        c = {"kind": "body", "name": b"_ExtStruct", "msg": (0x5e90a1, 14)}
        p = tool.model(c)
        self.assertEqual(p["result"], (tool.EXT_TAG, 0x5e90a1, 14))
        self.assertEqual(p["events"], [])

    def test_direct_model(self):
        c = {"kind": "body", "name": b"x", "msg": (0, 0), "cap": 4, "head": 2, "len": 3, "fault": None, "oom": False,
             "cfg": bytes(5), "prefix": b"", "room": 16, "words": [0, 1, 2, 0x80, 4, 5, 6, 7]}
        p = tool.model(c)
        self.assertEqual(p["out"], b"\x93\x02\xcc\x80\x00")
        self.assertEqual(p["events"][0], ("hdr", 3))
        self.assertEqual([e[1] for e in p["events"][1:]], [2, 0x80, 0])


class RealBytes(unittest.TestCase):
    def test_static_facts(self):
        self.assertEqual(len(ROWS), 6)
        self.assertEqual(len(CROWS), 6)
        for va, r in ROWS.items():
            self.assertEqual(r["end"] - va, 556)
            self.assertEqual(r["insns"], 138)
            self.assertEqual(r["msg"][1], 14)
        for va, ch in CROWS.items():
            self.assertEqual(ch["wu_direct"] == ch["wu_buffered"], tool.CHAINS[va][1] == "a")

    def test_cases_match_model(self):
        results, bad = run(small_cases())
        self.assertEqual(bad, [])
        self.assertGreater(len(results), 500)

    def test_big_case_straddles_header_form(self):
        va = 0x226c0f0
        c = tool.big_case(va, 0x10000, tool.Stream("t"))
        results, bad = run([c])
        self.assertEqual(bad, [])
        self.assertEqual(results[0][1]["out"][:5], b"\xdd\x00\x01\x00\x00")
        c = tool.big_case(va, 0xffff, tool.Stream("t"))
        results, bad = run([c])
        self.assertEqual(bad, [])
        self.assertEqual(results[0][1]["out"][:3], b"\xdc\xff\xff")

    def test_every_case_kind_occurs(self):
        results, _ = run(small_cases(160, 80))
        kinds = set()
        for c, got, _ in results:
            if c["kind"] == "chain":
                p = tool.chain_model(c)
                kinds.add("panic" if p["boundary"] else "fault" if p["result"] else "ok-" + c["mode"])
            elif tool.is_ext(c["name"]):
                kinds.add("ext")
            else:
                p = tool.model(tool.with_msg(c, ROWS))
                kinds.add("oom" if p["boundary"] else "fault" if p["result"] else "ok")
        self.assertTrue({"panic", "fault", "ok-direct", "ok-buffered", "ext", "oom", "ok"} <= kinds, kinds)

    def test_model_mutants_are_caught(self):
        results, _ = run(small_cases(300, 120))
        caught = set()
        for name in tool.MODEL_MUTANTS:
            for c, got, _ in results:
                if tool.compare(c, tool.expected(c, ROWS, frozenset({name})), got):
                    caught.add(name)
                    break
        self.assertEqual(caught, set(tool.MODEL_MUTANTS) - {"hdr-u16", "arr16-limit"})

    def test_byte_flips_are_caught(self):
        cases = small_cases(200, 80)
        sites = tool.byte_sites(IMAGE, EXT)
        labels = {s[1] for s in sites}
        self.assertTrue({"ja-wrap", "cmovae-head", "cfgmask", "counter-cmp", "inc-counter", "wu-ok-cmp"} <= labels)
        picked = [s for s in sites if s[0] in (0x226c0f0, 0x2518da0, 0x41a4c70, 0x450bb10)]
        self.assertGreaterEqual(len(picked), 10)
        for va, label, at, bit in picked:
            mine = [c for c in cases if (c.get("body") or c.get("chain")) == va]
            wide = [c for c in mine if c.get("counter", 0) >= 0xfffffffd or (
                c["kind"] == "body" and not tool.is_ext(c["name"]) and tool.deque_slices(c["cap"], c["head"], c["len"])[3] >> 32)]
            mine = mine[::3] + wide[:40]
            _, bad = run(mine, override={at: IMAGE.code(at, 1)[0] ^ bit}, stop=True)
            self.assertTrue(bad, f"{va:#x} {label}@{at:#x} flip not detected")

    def test_unflipped_override_is_clean(self):
        cases = small_cases(24, 16)[:40]
        _, bad = run(cases, override={0x226c0f0: IMAGE.code(0x226c0f0, 1)[0]}, stop=True)
        self.assertEqual(bad, [])

    def test_corrupted_output_is_detected(self):
        results, _ = run(small_cases(24, 16))
        c, got, _ = next(r for r in results if r[0]["kind"] == "body" and r[1]["out"] and not tool.is_ext(r[0]["name"]))
        bad = dict(got, out=got["out"][:-1] + bytes([got["out"][-1] ^ 1]))
        self.assertEqual(tool.compare(c, tool.expected(c, ROWS, frozenset()), bad), "bytes")
        bad = dict(got, events=got["events"][:-1])
        self.assertIn(tool.compare(c, tool.expected(c, ROWS, frozenset()), bad), ("events", "boundary"))

    def test_range_controls(self):
        out = tool.range_controls(IMAGE, EXT)
        self.assertEqual(len(out), 5)
        self.assertTrue(all(hit == 0 for _, _, hit in out), out)

    def test_wrong_family_fails_static_check(self):
        saved = dict(tool.BODIES)
        try:
            tool.BODIES[0x41a3a60] = ("226", "a")
            with self.assertRaises(tool.ToolError):
                tool.facts(IMAGE, EXT, 0x41a3a60)
        finally:
            tool.BODIES.clear()
            tool.BODIES.update(saved)

    def test_wrong_digest_fails(self):
        with self.assertRaises(tool.ToolError):
            tool.Image(IMAGE.data[:-1] + bytes([IMAGE.data[-1] ^ 1]))


class LogicalOrder(unittest.TestCase):
    """Independent of the reconstruction's own slice code: a list-based ring gives the expected element order."""

    def test_slices_concatenate_to_logical_order(self):
        for cap in range(1, 13):
            for head in range(cap):
                for ln in range(cap + 1):
                    s, e, back, total = tool.deque_slices(cap, head, ln)
                    ring = list(range(100, 100 + cap))
                    got = ring[s:e] + ring[0:back]
                    self.assertEqual(got, [ring[(head + i) % cap] for i in range(ln)], (cap, head, ln))
                    self.assertEqual(total, ln)

    def test_head_fold_is_exactly_one_cap(self):
        for cap in range(1, 10):
            for head in range(cap):
                for ln in range(cap + 1):
                    self.assertEqual(tool.deque_slices(cap, head + cap, ln), tool.deque_slices(cap, head, ln))

    def test_real_bodies_write_logical_order(self):
        cases = [c for c in tool.exhaustive_cases() if c["head"] < c["cap"]]
        self.assertGreater(len(cases), 1000)
        checked = 0
        for c in cases[::7]:
            results, bad = run([c])
            self.assertEqual(bad, [])
            got = results[0][1]["out"][len(c["prefix"]):]
            ring = c["words"][:c["cap"]]
            vec = tool.VecSim(1 << 20, 0, [])
            for i in range(c["len"]):
                tool.write_uint(vec, ring[(c["head"] + i) % c["cap"]])
            self.assertEqual(got, tool.mp_array(c["len"]) + bytes(vec.out))
            checked += 1
        self.assertGreater(checked, 100)

    def test_real_bodies_for_head_ge_cap_match_folded_head(self):
        by = {}
        for c in tool.exhaustive_cases():
            if c["body"] in (0x226c0f0, 0x52fcf20):
                by[(c["body"], c["cap"], c["head"], c["len"])] = c
        for (va, cap, head, ln), c in list(by.items())[::5]:
            if head < cap:
                continue
            twin = dict(by[(va, cap, head - cap, ln)], words=c["words"], prefix=c["prefix"], cfg=c["cfg"],
                        ser_tail=c["ser_tail"], room=c["room"])
            r1, b1 = run([c])
            r2, b2 = run([twin])
            self.assertEqual((b1, b2), ([], []))
            self.assertEqual(r1[0][1]["out"], r2[0][1]["out"])
            self.assertEqual(r1[0][1]["events"], r2[0][1]["events"])

    def test_chain_cursors_end_at_slice_ends(self):
        for c in small_cases(24, 60):
            if c["kind"] != "chain" or c["fault"] is not None:
                continue
            p = tool.chain_model(c)
            if p["boundary"]:
                continue
            self.assertEqual(p["cursors"], (c["e1"], c["e2"]))
            walked = ((c["e1"] - c["c1"]) + (c["e2"] - c["c2"])) // 8
            self.assertEqual(sum(1 for e in p["events"] if e[0] == "wu"), walked)


class Packet(unittest.TestCase):
    def test_small_generation_runs_and_detects_all_controls(self):
        with tempfile.TemporaryDirectory() as tmp:
            summary = tool.generate(tmp, 320, 60)
            self.assertEqual(summary["mismatches"], 0)
            self.assertEqual(summary["controls"], summary["controls_detected"])
            measure = json.loads((pathlib.Path(tmp) / "measure.json").read_text())
            self.assertEqual(measure["negative_controls"], measure["negative_detected"])

    def test_manifest_matches_files(self):
        manifest = PACKET / "MANIFEST.sha256"
        rows = [line.split("  ") for line in manifest.read_text().splitlines()]
        self.assertGreaterEqual(len(rows), 9)
        for digest, name in rows:
            self.assertEqual(hashlib.sha256((PACKET / name).read_bytes()).hexdigest(), digest, name)

    def test_summary_agrees_with_measure(self):
        summary = json.loads((PACKET / "summary.json").read_text())
        measure = json.loads((PACKET / "measure.json").read_text())
        self.assertEqual(summary["cases"], measure["cases"])
        self.assertEqual(summary["controls"], measure["negative_controls"])
        self.assertEqual(summary["controls_detected"], measure["negative_detected"])
        self.assertEqual(summary["mismatches"], 0)
        self.assertEqual(summary["binary_sha256"], tool.SHA256)

    def test_committed_tables_are_consistent_with_static_scan(self):
        lines = (PACKET / "bodies.tsv").read_text().splitlines()[1:]
        self.assertEqual(sorted(int(l.split("\t")[0], 16) for l in lines), sorted(tool.BODIES))
        for line in lines:
            f = line.split("\t")
            self.assertEqual(int(f[6], 16), ROWS[int(f[0], 16)]["chain"])
        lines = (PACKET / "chains.tsv").read_text().splitlines()[1:]
        self.assertEqual(sorted(int(l.split("\t")[0], 16) for l in lines), sorted(tool.CHAINS))


if __name__ == "__main__":
    unittest.main()
