"""Tests for tools/re015_btreeset_u32_115.py (node #115 rmp newtype(BTreeSet<u32>) serializers and Iter::next)."""
import hashlib
import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import re015_btreeset_u32_115 as tool  # noqa: E402

PACKET = ROOT / "research" / "work-items" / "RE-015-rmp-btreeset-u32-115"
IMAGE = EXT = ROWS = NROWS = CASES = RESULTS = None


def setUpModule():
    global IMAGE, EXT, ROWS, NROWS, CASES, RESULTS
    IMAGE = tool.Image(tool.BINARY.read_bytes())
    EXT = tool.extents(IMAGE)
    ROWS, NROWS = tool.static_rows(IMAGE, EXT)
    CASES = tool.all_cases(160, 110)
    RESULTS, _ = run(CASES)


def run(cases, mut=frozenset(), override=None, stop=False):
    return tool.evaluate(IMAGE, EXT, ROWS, cases, mut, override, stop)


def hand_tree():
    """Height 1: root keys [30, 60]; leaves [10, 20], [40, 50], [70, 80, 90]."""
    nodes = [
        {"keys": [30, 60], "edges": [1, 2, 3], "parent": None, "pidx": 0},
        {"keys": [10, 20], "edges": None, "parent": 0, "pidx": 0},
        {"keys": [40, 50], "edges": None, "parent": 0, "pidx": 1},
        {"keys": [70, 80, 90], "edges": None, "parent": 0, "pidx": 2},
    ]
    return tool.Tree(nodes, 0, 1)


def deep_tree():
    """Height 2: a root with one key and two internal children, each with two leaves."""
    nodes = [
        {"keys": [500], "edges": [1, 4], "parent": None, "pidx": 0},
        {"keys": [200], "edges": [2, 3], "parent": 0, "pidx": 0},
        {"keys": [100, 150], "edges": None, "parent": 1, "pidx": 0},
        {"keys": [300], "edges": None, "parent": 1, "pidx": 1},
        {"keys": [800], "edges": [5, 6], "parent": 0, "pidx": 1},
        {"keys": [600, 700], "edges": None, "parent": 4, "pidx": 0},
        {"keys": [900, 0x10000, 0xffffffff], "edges": None, "parent": 4, "pidx": 1},
    ]
    return tool.Tree(nodes, 0, 2)


def body_case(va, tree, length=None, **kw):
    c = {"kind": "body", "body": va, "k": 0, "prefix": b"", "ser_tail": bytes(8), "cfg": bytes(5), "fault": None,
         "oom": False, "name": b"set", "msg": (0, 0), "tree": tree, "len": tree.count() if length is None else length,
         "height": tree.height, "room": 400, "valid": False}
    c.update(kw)
    return c


class ModelRules(unittest.TestCase):
    def test_array_header_bounds(self):
        self.assertEqual(tool.mp_array(0), b"\x90")
        self.assertEqual(tool.mp_array(15), b"\x9f")
        self.assertEqual(tool.mp_array(16), b"\xdc\x00\x10")
        self.assertEqual(tool.mp_array(0xffff), b"\xdc\xff\xff")
        self.assertEqual(tool.mp_array(0x10000), b"\xdd\x00\x01\x00\x00")

    def test_array_header_reserves_tag_then_payload(self):
        ev = []
        vec = tool.VecSim(1, 0, ev)
        tool.write_array_len(vec, 0x1234)
        self.assertEqual(bytes(vec.out), b"\xdc\x12\x34")
        self.assertEqual(ev, [("res", 1, 2)])

    def test_uint_forms(self):
        for v, want in ((0x7f, b"\x7f"), (0x80, b"\xcc\x80"), (0x100, b"\xcd\x01\x00"), (0x10000, b"\xce\x00\x01\x00\x00"),
                        (0xffffffff, b"\xce\xff\xff\xff\xff")):
            vec = tool.VecSim(64, 0, [])
            tool.write_uint(vec, v)
            self.assertEqual(bytes(vec.out), want)

    def test_ext_name_is_exact(self):
        self.assertTrue(tool.is_ext(b"_ExtStruct"))
        self.assertFalse(tool.is_ext(b"_ExtStruct!"))
        self.assertTrue(tool.is_ext(b"_ExtStruct!", {"ext-prefix"}))

    def test_walk_is_in_order_for_hand_trees(self):
        self.assertEqual(list(tool.walk_keys(hand_tree(), 9)), [10, 20, 30, 40, 50, 60, 70, 80, 90])
        t = deep_tree()
        self.assertEqual(list(tool.walk_keys(t, t.count())), [100, 150, 200, 300, 500, 600, 700, 800, 900, 0x10000, 0xffffffff])

    def test_walk_stops_at_remaining_length(self):
        self.assertEqual(list(tool.walk_keys(hand_tree(), 4)), [10, 20, 30, 40])
        self.assertEqual(list(tool.walk_keys(hand_tree(), 0)), [])

    def test_walk_past_the_last_key_panics_at_the_root(self):
        gen = tool.walk_keys(hand_tree(), 10)
        got = []
        with self.assertRaises(tool.Panic) as cm:
            for v in gen:
                got.append(v)
        self.assertEqual(got, [10, 20, 30, 40, 50, 60, 70, 80, 90])
        self.assertEqual(cm.exception.loc, tool.LOC_ASCEND)

    def test_empty_root_leaf_panics_on_first_call(self):
        t = tool.Tree([{"keys": [], "edges": None, "parent": None, "pidx": 0}], 0, 0)
        with self.assertRaises(tool.Panic):
            list(tool.walk_keys(t, 1))

    def test_lazy_state_after_first_call(self):
        t = hand_tree()
        w = tool.iter_words(t, 9)
        key = tool.next_model(w, t)
        self.assertEqual(key, (tool.addr(1), 0))
        self.assertEqual(w[:4], [1, tool.addr(1), 0, 1])
        self.assertEqual(w[8], 8)

    def test_state_after_internal_key_descends_to_the_next_leaf(self):
        t = hand_tree()
        w = tool.iter_words(t, 9)
        for _ in range(3):
            key = tool.next_model(w, t)
        self.assertEqual(tool.key_value(t, key), 30)
        self.assertEqual(w[1:4], [tool.addr(2), 0, 0])   # edge idx+1, then first edges down to the leaf

    def test_tag_other_than_one_panics_with_the_tag_location(self):
        t = hand_tree()
        w = tool.iter_words(t, 3)
        w[0] = 2
        with self.assertRaises(tool.Panic) as cm:
            tool.next_model(w, t)
        self.assertEqual(cm.exception.loc, tool.LOC_TAG)
        w = tool.iter_words(t, 0)
        w[0] = 2
        self.assertIsNone(tool.next_model(w, t))          # the length test comes first

    def test_every_next_mutant_changes_the_walk(self):
        t = deep_tree()
        base = list(tool.walk_keys(t, t.count()))
        for name in ("lazy-short", "desc-short", "edge-idx", "pidx-plus1", "len-off1"):
            try:
                alt = list(tool.walk_keys(t, t.count(), frozenset({name})))
            except (tool.Panic, tool.Wild, KeyError, IndexError):
                continue
            self.assertNotEqual(alt, base, name)

    def test_reference_encoding(self):
        self.assertEqual(tool.reference_bytes([]), b"\x90")
        self.assertEqual(tool.reference_bytes([1, 0x80, 0x100, 0x10000]), b"\x94\x01\xcc\x80\xcd\x01\x00\xce\x00\x01\x00\x00")

    def test_ext_model(self):
        c = body_case(0x2270e30, hand_tree(), name=b"_ExtStruct", msg=(0x5e90a1, 14), locs=tool.NEXT_LOCS[0x23885b0])
        p = tool.body_model(c)
        self.assertEqual(p["result"], (tool.EXT_TAG, 0x5e90a1, 14))
        self.assertEqual(p["events"], [])

    def test_direct_model_matches_oracle(self):
        c = body_case(0x2270e30, deep_tree(), locs=tool.NEXT_LOCS[0x23885b0])
        p = tool.body_model(c)
        self.assertEqual(p["out"], tool.reference_bytes(sorted(k for n in c["tree"].nodes for k in n["keys"])))
        self.assertIsNone(p["result"])
        self.assertEqual(p["events"][0], ("hdr", 11))

    def test_record_without_root_ignores_its_length(self):
        t = tool.Tree([], None, 3)
        c = body_case(0x2270e30, t, length=1 << 40, locs=tool.NEXT_LOCS[0x23885b0])
        p = tool.body_model(c)
        self.assertEqual(p["out"], b"\x90")
        self.assertEqual(p["events"], [("hdr", 0)])

    def test_wide_length_takes_the_counting_path_and_ends_in_a_panic(self):
        c = body_case(0x2270e30, hand_tree(), length=(1 << 32) + 3, locs=tool.NEXT_LOCS[0x23885b0], cfg=b"\x01\x01\x01\x01\x01")
        p = tool.body_model(c)
        self.assertEqual(p["events"][0], ("malloc", 0x80))
        self.assertEqual(p["events"][1][2:], ("cmp", 0, tool.config_word(c["cfg"])))
        self.assertEqual(p["boundary"], ("unwrap-none", tool.LOC_ASCEND))
        self.assertEqual(sum(1 for e in p["events"] if e[0] == "wu"), 9)


class RealBytes(unittest.TestCase):
    def test_static_facts(self):
        self.assertEqual(len(ROWS), 6)
        self.assertEqual(len(NROWS), 3)
        for va, r in ROWS.items():
            self.assertEqual(r["end"] - va, 0x292)
            self.assertEqual(r["insns"], 156)
            self.assertEqual(r["msg"][1], 14)
        for va, r in NROWS.items():
            self.assertEqual(r["end"] - va, 0x1d7)
            self.assertEqual(r["insns"], 125)
            self.assertEqual(tuple(r["locs"]), tool.NEXT_LOCS[va])

    def test_generated_cases_match_the_model(self):
        self.assertGreater(len(RESULTS), 1200)
        self.assertTrue(all(why is None for _, _, why in RESULTS))

    def test_every_case_kind_occurs(self):
        kinds = {tool.case_kind(c, ROWS) for c, _, _ in RESULTS}
        want = {"ext_error", "direct_ok", "direct_ok_valid", "direct_fault", "direct_panic", "buffered_panic",
                "buffered_fault", "alloc_error", "empty_set", "next_bad_tag", "next_empty", "next_mid"}
        self.assertTrue(want <= kinds, want - kinds)

    def test_hand_trees_through_every_real_body(self):
        for tree in (hand_tree(), deep_tree()):
            want = tool.reference_bytes(sorted(k for n in tree.nodes for k in n["keys"]))
            for va in sorted(tool.BODIES):
                results, bad = run([body_case(va, tree)])
                self.assertEqual(bad, [], hex(va))
                self.assertEqual(results[0][1]["out"], want, hex(va))

    def test_hand_trees_through_every_real_next(self):
        for tree in (hand_tree(), deep_tree()):
            for fn in sorted(tool.NEXTS):
                w = tool.iter_words(tree, tree.count())
                cases = []
                for _ in range(tree.count() + 1):
                    cases.append({"kind": "next", "fn": fn, "k": 0, "tree": tree, "words": list(w)})
                    if tool.next_model(w, tree) is None:
                        break
                results, bad = run(cases)
                self.assertEqual(bad, [], hex(fn))
                self.assertEqual([r[1]["ret"] != 0 for r in results], [True] * tree.count() + [False][:len(results) - tree.count()])

    def test_header_boundaries_with_a_short_tree(self):
        for length, head in ((0xf, b"\x9f"), (0x10, b"\xdc\x00\x10"), (0xffff, b"\xdc\xff\xff"), (0x10000, b"\xdd\x00\x01\x00\x00")):
            for va in (0x2270e30, 0x226d220, 0x52f4f00):
                c = body_case(va, hand_tree(), length=length)
                results, bad = run([c])
                self.assertEqual(bad, [], (hex(va), length))
                self.assertTrue(results[0][1]["out"].startswith(head))
                self.assertEqual(results[0][1]["boundary"][0], "unwrap-none")

    def test_wide_length_allocates_and_panics_in_the_real_bodies(self):
        for va in sorted(tool.BODIES):
            c = body_case(va, hand_tree(), length=1 << 32)
            results, bad = run([c])
            self.assertEqual(bad, [], hex(va))
            got = results[0][1]
            self.assertEqual(got["events"][0], ("malloc", 0x80))
            self.assertEqual(got["boundary"][0], "unwrap-none")
            self.assertEqual(got["out"], b"")

    def test_allocation_failure_is_reported_with_size_and_align(self):
        c = body_case(0x419d250, hand_tree(), length=1 << 33, oom=True)
        results, bad = run([c])
        self.assertEqual(bad, [])
        self.assertEqual(results[0][1]["boundary"], ("alloc-error", 1, 0x80))

    def test_model_mutants_are_caught(self):
        caught = set()
        for name in tool.MODEL_MUTANTS:
            for c, got, _ in RESULTS:
                if tool.compare(c, tool.expected(c, ROWS, frozenset({name})), got):
                    caught.add(name)
                    break
        missing = set(tool.MODEL_MUTANTS) - caught
        self.assertEqual(missing, set())

    def test_byte_flips_are_caught(self):
        picked = []
        for va in (0x2270e30, 0x41a3420, 0x23885b0, 0x513b420):
            for v, f in tool.sweep(IMAGE, va, EXT[va]):
                imm = f.get("imm")
                if f["op"] == 0x83 and imm == 10:
                    picked.append((va, v + f["len"] - 1, 0x01))                 # name length
                elif f["op"] == 0xc1 and imm == 0x20:
                    picked.append((va, v + f["len"] - 1, 0x20))                 # u32 test
                elif f["op"] == 0x83 and imm == 1 and f["rm"][0] == "m" and f["rm"][1] == 7:
                    picked.append((va, v + f["len"] - 1, 0x02))                 # Some tag
                elif f["op"] == 0x0fb7 and f["rm"][0] == "m" and f["rm"][4] == tool.LEN_AT:
                    picked.append((va, v + f["len"] - 1, 0x01))                 # node length offset
        self.assertGreaterEqual(len(picked), 8)
        for va, at, bit in picked:
            mine = tool.cases_using(RESULTS, va)
            wide = [c for c in mine if c["kind"] == "body" and c["len"] >> 32 and c["tree"].root is not None]
            sample = mine[::3] + wide[:30]
            _, bad = run(sample, override={at: IMAGE.code(at, 1)[0] ^ bit}, stop=True)
            self.assertTrue(bad, f"{va:#x}@{at:#x} flip not detected")

    def test_unflipped_override_is_clean(self):
        cases = CASES[:60]
        _, bad = run(cases, override={0x2270e30: IMAGE.code(0x2270e30, 1)[0]}, stop=True)
        self.assertEqual(bad, [])

    def test_corrupted_output_is_detected(self):
        c, got, _ = next(r for r in RESULTS if r[0]["kind"] == "body" and r[1]["out"] and not tool.is_ext(r[0]["name"]))
        bad = dict(got, out=got["out"][:-1] + bytes([got["out"][-1] ^ 1]))
        self.assertEqual(tool.compare(c, tool.expected(c, ROWS, frozenset()), bad), "bytes")
        bad = dict(got, events=got["events"][:-1])
        self.assertIn(tool.compare(c, tool.expected(c, ROWS, frozenset()), bad), ("events", "boundary"))

    def test_corrupted_iterator_record_is_detected(self):
        c, got, _ = next(r for r in RESULTS if r[0]["kind"] == "next" and r[1]["ret"])
        bad = dict(got, words=got["words"][:1] + [got["words"][1] ^ 0x100] + got["words"][2:])
        self.assertEqual(tool.compare(c, tool.next_expect(c), bad), "iterator")
        bad = dict(got, ret=got["ret"] + 4)
        self.assertEqual(tool.compare(c, tool.next_expect(c), bad), "return")

    def test_range_controls(self):
        out = tool.range_controls(IMAGE, EXT)
        self.assertEqual(len(out), 6)
        self.assertTrue(all(hit == 0 for _, _, hit in out), out)

    def test_wrong_role_fails_static_check(self):
        saved = {va: dict(r) for va, r in tool.BODIES.items()}
        try:
            tool.BODIES[0x419d250]["fam"] = "226"
            tool.BODIES[0x419d250]["nxt"] = 0x23885b0
            with self.assertRaises(tool.ToolError):
                tool.facts(IMAGE, EXT, 0x419d250)
        finally:
            tool.BODIES.clear()
            tool.BODIES.update(saved)

    def test_wrong_digest_fails(self):
        with self.assertRaises(tool.ToolError):
            tool.Image(IMAGE.data[:-1] + bytes([IMAGE.data[-1] ^ 1]))


class StructuralOracle(unittest.TestCase):
    """Independent of the reconstruction's own walk: a recursive in-order listing of the same tree."""

    def test_walk_equals_recursive_inorder_for_generated_trees(self):
        stream = tool.Stream("oracle")
        checked = 0
        for shape in (0, 1, 2, 3) * 40:
            t = tool.make_tree(stream, shape)
            tool.sort_keys(stream, t)
            want = [t.nodes[i]["keys"][j] for i, j in tool.inorder(t)]
            self.assertEqual(want, sorted(want))
            self.assertEqual(len(set(want)), len(want))
            self.assertEqual(list(tool.walk_keys(t, len(want))), want)
            checked += 1
        self.assertEqual(checked, 160)

    def test_valid_cases_equal_sorted_reference_through_the_real_bytes(self):
        valid = [r for r in RESULTS if r[0]["kind"] == "body" and tool.oracle_applies(r[0])]
        self.assertGreater(len(valid), 100)
        for c, got, _ in valid[::5]:
            keys = sorted(k for n in c["tree"].nodes for k in n["keys"])
            self.assertEqual(got["out"][len(c["prefix"]):], tool.reference_bytes(keys))

    def test_generated_nodes_respect_the_b_tree_shape(self):
        stream = tool.Stream("shape")
        for shape in (0, 1, 2, 3) * 30:
            t = tool.make_tree(stream, shape)
            self.assertLessEqual(len(t.nodes), 60)
            for i, n in enumerate(t.nodes):
                self.assertLessEqual(len(n["keys"]), 11)
                if n["edges"] is not None:
                    self.assertEqual(len(n["edges"]), len(n["keys"]) + 1)
                    for e, child in enumerate(n["edges"]):
                        self.assertEqual((t.nodes[child]["parent"], t.nodes[child]["pidx"]), (i, e))


class Packet(unittest.TestCase):
    def test_small_generation_runs_and_detects_all_controls(self):
        with tempfile.TemporaryDirectory() as tmp:
            summary = tool.generate(tmp, 400, 60)
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
            self.assertEqual(int(f[6], 16), tool.BODIES[int(f[0], 16)]["nxt"])
            self.assertEqual(int(f[2]), ROWS[int(f[0], 16)]["insns"])
        lines = (PACKET / "iter-next.tsv").read_text().splitlines()[1:]
        self.assertEqual(sorted(int(l.split("\t")[0], 16) for l in lines), sorted(tool.NEXTS))


if __name__ == "__main__":
    unittest.main()
