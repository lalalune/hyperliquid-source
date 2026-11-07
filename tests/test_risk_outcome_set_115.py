"""Tests for tools/risk_outcome_set_115.py (node #115 rmp newtype(BTreeSet<OutcomeRecord>) serializers, record writer, Iter::next)."""
import hashlib
import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import risk_outcome_set_115 as tool  # noqa: E402

PACKET = ROOT / "research" / "work-items" / "risk-outcome-record-set-115"
IMAGE = EXT = ROWS = RECS = NROWS = CASES = RESULTS = None


def setUpModule():
    global IMAGE, EXT, ROWS, RECS, NROWS, CASES, RESULTS
    IMAGE = tool.Image(tool.BINARY.read_bytes())
    EXT = tool.extents(IMAGE)
    ROWS, RECS, NROWS = tool.static_rows(IMAGE, EXT)
    CASES = tool.all_cases(200, 400, 120)
    RESULTS, _ = run(CASES)


def run(cases, mut=frozenset(), override=None, stop=False):
    return tool.evaluate(IMAGE, EXT, ROWS, cases, mut, override, stop)


def rec(outcome=1, settle=b"s", details=b"d", name=b"n", desc=b"x", s1=b"a", s2=b"b"):
    return dict(outcome=outcome, settle=settle, details=details, name=name, desc=desc, s1=s1, s2=s2)


def hand_tree():
    """Height 1: root records [R30, R60]; leaves [R10, R20], [R40, R50], [R70, R80, R90]."""
    def k(*xs):
        return [rec(outcome=x, settle=b"s%d" % x) for x in xs]
    nodes = [
        {"keys": k(30, 60), "edges": [1, 2, 3], "parent": None, "pidx": 0},
        {"keys": k(10, 20), "edges": None, "parent": 0, "pidx": 0},
        {"keys": k(40, 50), "edges": None, "parent": 0, "pidx": 1},
        {"keys": k(70, 80, 90), "edges": None, "parent": 0, "pidx": 2},
    ]
    return tool.Tree(nodes, 0, 1)


def deep_tree():
    """Height 2: root with one record and two internal children, each with two leaves."""
    def k(*xs):
        return [rec(outcome=x) for x in xs]
    nodes = [
        {"keys": k(500), "edges": [1, 4], "parent": None, "pidx": 0},
        {"keys": k(200), "edges": [2, 3], "parent": 0, "pidx": 0},
        {"keys": k(100, 150), "edges": None, "parent": 1, "pidx": 0},
        {"keys": k(300), "edges": None, "parent": 1, "pidx": 1},
        {"keys": k(800), "edges": [5, 6], "parent": 0, "pidx": 1},
        {"keys": k(600, 700), "edges": None, "parent": 4, "pidx": 0},
        {"keys": k(900, 0x10000, 0xffffffff), "edges": None, "parent": 4, "pidx": 1},
    ]
    return tool.Tree(nodes, 0, 2)


def walk(tree, rem, mut=frozenset(), locs=(1, 2)):
    w = tool.iter_words(tree, rem)
    while True:
        key = tool.next_model(w, tree, mut, locs)
        if key is None:
            return
        yield tool.key_record(tree, key)["outcome"]


def body_case(va, tree, length=None, **kw):
    c = {"kind": "body", "body": va, "k": 0, "prefix": b"", "ser_tail": bytes(8), "cfg": bytes(5), "fault": None,
         "oom": False, "name": b"set", "msg": (0, 0), "tree": tree, "len": tree.count() if length is None else length,
         "height": tree.height, "room": 4000}
    c.update(kw)
    return c


def rec_case(fam, record, cfg=bytes(5), **kw):
    c = {"kind": "rec", "fam": fam, "k": 0, "prefix": b"", "ser_tail": bytes(8), "cfg": cfg, "fault": None, "rec": record,
         "room": 1000}
    c.update(kw)
    return c


def with_locs(c):
    return dict(c, locs=tool.NEXT_LOCS[tool.FAMS[tool.BODIES[c["body"]]["fam"]]["nxt"]])


class ModelRules(unittest.TestCase):
    def test_array_header_bounds(self):
        self.assertEqual(tool.mp_array(0), b"\x90")
        self.assertEqual(tool.mp_array(15), b"\x9f")
        self.assertEqual(tool.mp_array(16), b"\xdc\x00\x10")
        self.assertEqual(tool.mp_array(0x10000), b"\xdd\x00\x01\x00\x00")

    def test_uint_and_str_forms(self):
        for v, want in ((0x7f, b"\x7f"), (0x80, b"\xcc\x80"), (0x100, b"\xcd\x01\x00"), (0x10000, b"\xce\x00\x01\x00\x00"),
                        (1 << 32, b"\xcf\x00\x00\x00\x01\x00\x00\x00\x00")):
            vec = tool.VecSim(64, 0, [])
            tool.write_uint(vec, v)
            self.assertEqual(bytes(vec.out), want)
        for n, head in ((0, b"\xa0"), (31, b"\xbf"), (32, b"\xd9\x20"), (255, b"\xd9\xff"), (256, b"\xda\x01\x00")):
            vec = tool.VecSim(1000, 0, [])
            tool.write_str(vec, b"z" * n)
            self.assertEqual(bytes(vec.out[:len(head)]), head)
            self.assertEqual(len(vec.out), len(head) + n)

    def test_string_writer_reserves_marker_then_length_then_payload(self):
        ev = []
        vec = tool.VecSim(0, 0, ev)
        tool.write_str(vec, b"y" * 40)
        self.assertEqual(ev, [("res", 0, 1), ("res", 1, 1), ("res", 2, 40)])

    def test_ext_name_is_exact(self):
        self.assertTrue(tool.is_ext(b"_ExtStruct"))
        self.assertFalse(tool.is_ext(b"_ExtStruct!"))
        self.assertTrue(tool.is_ext(b"_ExtStruct!", {"ext-prefix"}))

    def test_walk_is_in_order_for_hand_trees(self):
        self.assertEqual(list(walk(hand_tree(), 9)), [10, 20, 30, 40, 50, 60, 70, 80, 90])
        t = deep_tree()
        self.assertEqual(list(walk(t, t.count())), [100, 150, 200, 300, 500, 600, 700, 800, 900, 0x10000, 0xffffffff])

    def test_walk_stops_at_remaining_length_and_panics_past_the_root(self):
        self.assertEqual(list(walk(hand_tree(), 4)), [10, 20, 30, 40])
        self.assertEqual(list(walk(hand_tree(), 0)), [])
        got = []
        with self.assertRaises(tool.Panic) as cm:
            for v in walk(hand_tree(), 10):
                got.append(v)
        self.assertEqual(got, [10, 20, 30, 40, 50, 60, 70, 80, 90])
        self.assertEqual(cm.exception.loc, 1)

    def test_tag_other_than_one_panics_with_the_tag_location(self):
        t = hand_tree()
        w = tool.iter_words(t, 3)
        w[0] = 2
        with self.assertRaises(tool.Panic) as cm:
            tool.next_model(w, t, frozenset(), (1, 2))
        self.assertEqual(cm.exception.loc, 2)
        w = tool.iter_words(t, 0)
        w[0] = 2
        self.assertIsNone(tool.next_model(w, t))

    def test_every_next_mutant_changes_the_walk(self):
        t = deep_tree()
        base = list(walk(t, t.count()))
        for name in ("lazy-short", "desc-short", "edge-idx", "pidx-plus1", "len-off1"):
            try:
                alt = list(walk(t, t.count(), frozenset({name})))
            except (tool.Panic, tool.Wild, KeyError, IndexError):
                continue
            self.assertNotEqual(alt, base, name)

    def test_record_bytes_named_and_positional(self):
        r = rec(outcome=0x80, settle=b"", details=b"dd", name=b"nn", desc=b"", s1=b"q", s2=b"w")
        for fam in tool.FAMS:
            ev = []
            vec = tool.VecSim(400, 0, ev)
            self.assertTrue(tool.record_model(tool.Run(None, ev), vec, r, b"\x00\x00\x00\x00\x00", fam))
            self.assertEqual(bytes(vec.out), tool.reference_bytes([r], 0, 0, fam)[1:])
            self.assertEqual(bytes(vec.out)[:4], b"\x95\xcc\x80\xa0")
        vec = tool.VecSim(400, 0, [])
        tool.record_model(tool.Run(None, []), vec, r, b"\x00\x00\x00\x01\x00", "226")
        self.assertEqual(bytes(vec.out)[:9], b"\x85\xa7outcome")
        self.assertIn(b"\xaesettleFraction", bytes(vec.out))
        self.assertIn(b"\xa7details", bytes(vec.out))
        self.assertIn(b"\xb2nameAndDescription", bytes(vec.out))
        self.assertIn(b"\xa9sideNames", bytes(vec.out))

    def test_unusual_flag_values_change_the_map_marker_only(self):
        r = rec()
        for flag, head in ((0, 0x95), (1, 0x85), (2, 0xb5), (3, 0xa5), (0xff, 0xe5)):
            vec = tool.VecSim(400, 0, [])
            tool.record_model(tool.Run(None, []), vec, r, bytes([0, 0, 0, flag, 0]), "226")
            self.assertEqual(vec.out[0], head, flag)

    def test_52f_writes_the_description_key_for_any_non_zero_flag(self):
        r = rec()
        for fam, expect in (("226", False), ("419", False), ("52f", True)):
            vec = tool.VecSim(400, 0, [])
            tool.record_model(tool.Run(None, []), vec, r, bytes([0, 0, 0, 2, 0]), fam)
            self.assertEqual(b"nameAndDescription" in bytes(vec.out), expect, fam)

    def test_fault_order_matches_call_order(self):
        r = rec()
        ev = []
        tool.record_model(tool.Run(None, ev), tool.VecSim(400, 0, []), r, bytes(5), "226")
        names = [e[0] for e in ev]
        self.assertEqual(names, ["wu", "ws", "ws", "nd", "ws", "ws", "nt", "ws", "ws", "tend"])
        for k in range(len(ev)):
            ev2 = []
            ok = tool.record_model(tool.Run(k, ev2), tool.VecSim(400, 0, []), r, bytes(5), "226")
            self.assertFalse(ok)
            self.assertEqual(len(ev2), k + 1)

    def test_ext_model(self):
        c = with_locs(body_case(0x226c320, hand_tree(), name=b"_ExtStruct", msg=(0x5e90a1, 14)))
        p = tool.body_model(c)
        self.assertEqual(p["result"], (tool.EXT_TAG, 0x5e90a1, 14))
        self.assertEqual(p["events"], [])

    def test_direct_model_matches_oracle(self):
        c = with_locs(body_case(0x226c320, deep_tree()))
        p = tool.body_model(c)
        recs = [tool.key_record(c["tree"], k) for k in tool.inorder_keys(c["tree"])]
        self.assertEqual(p["out"], tool.reference_bytes(recs, 0, 0, "226"))
        self.assertIsNone(p["result"])
        self.assertEqual(p["events"][0], ("hdr", 11))

    def test_wide_length_takes_the_counting_path_and_ends_in_a_panic(self):
        c = with_locs(body_case(0x226c320, hand_tree(), length=(1 << 32) + 3, cfg=b"\x01\x01\x01\x01\x01"))
        p = tool.body_model(c)
        self.assertEqual(p["events"][0], ("malloc", 0x80))
        self.assertEqual(p["boundary"][0], "unwrap-none")
        self.assertEqual(sum(1 for e in p["events"] if e[0] == "rec"), 9)


class RealBytes(unittest.TestCase):
    def test_static_facts(self):
        self.assertEqual(len(ROWS), 3)
        self.assertEqual(len(RECS), 3)
        self.assertEqual(len(NROWS), 3)
        for va, r in ROWS.items():
            self.assertEqual(r["end"] - va, 727)
            self.assertEqual(r["msg"][1], 14)
        for fam, r in RECS.items():
            self.assertEqual(r["cmps"], tool.FLAG_CMPS[fam])
        for va, r in NROWS.items():
            self.assertEqual(r["end"] - va, 536)
            self.assertEqual(len(r["locs"]), 2)

    def test_generated_cases_match_the_model(self):
        self.assertGreater(len(RESULTS), 1000)
        self.assertTrue(all(why is None for _, _, why in RESULTS))

    def test_every_case_kind_occurs(self):
        kinds = {tool.case_kind(c, ROWS) for c, _, _ in RESULTS}
        want = {"ext_error", "direct_ok", "direct_fault", "buffered_panic", "alloc_error", "empty_set", "next_bad_tag",
                "next_empty", "next_mid", "record_fault", "record_named", "record_array", "record_flag_other"}
        self.assertTrue(want <= kinds, want - kinds)

    def test_hand_trees_through_every_real_body(self):
        for tree in (hand_tree(), deep_tree()):
            for va in sorted(tool.BODIES):
                fam = tool.BODIES[va]["fam"]
                recs = [tool.key_record(tree, k) for k in tool.inorder_keys(tree)]
                want = tool.reference_bytes(recs, 0, 0, fam)
                results, bad = run([body_case(va, tree)])
                self.assertEqual(bad, [], hex(va))
                self.assertEqual(results[0][1]["out"], want, hex(va))

    def test_hand_record_through_every_real_writer_with_names(self):
        r = rec(outcome=0x1234567890, settle=b"1/2", details=b"x" * 40, name=b"N", desc=b"D" * 300, s1=b"yes", s2=b"no")
        for fam in tool.FAMS:
            for cfg in (bytes(5), bytes([0, 0, 0, 1, 0]), bytes([0, 0, 0, 1, 2]), bytes([0, 0, 0, 2, 2])):
                results, bad = run([rec_case(fam, r, cfg)])
                self.assertEqual(bad, [], (fam, cfg))
                self.assertEqual(results[0][1]["out"], tool.reference_bytes([r], cfg[3], cfg[4], fam)[1:])

    def test_52f_description_key_is_real(self):
        r = rec()
        outs = {}
        for fam in tool.FAMS:
            results, bad = run([rec_case(fam, r, bytes([0, 0, 0, 2, 0]))])
            self.assertEqual(bad, [])
            outs[fam] = b"nameAndDescription" in results[0][1]["out"]
        self.assertEqual(outs, {"226": False, "419": False, "52f": True})

    def test_hand_trees_through_every_real_next(self):
        for tree in (hand_tree(), deep_tree()):
            for fn in sorted(tool.NEXTS):
                w = tool.iter_words(tree, tree.count())
                cases = []
                for _ in range(tree.count() + 1):
                    cases.append({"kind": "next", "fn": fn, "k": 0, "tree": tree, "words": list(w), "locs": tool.NEXT_LOCS[fn]})
                    if tool.next_model(w, tree) is None:
                        break
                results, bad = run(cases)
                self.assertEqual(bad, [], hex(fn))
                self.assertEqual([r[1]["ret"] != 0 for r in results], [True] * tree.count() + [False][:len(results) - tree.count()])

    def test_header_boundaries_with_a_short_tree(self):
        for length, head in ((0xf, b"\x9f"), (0x10, b"\xdc\x00\x10"), (0xffff, b"\xdc\xff\xff"), (0x10000, b"\xdd\x00\x01\x00\x00")):
            for va in sorted(tool.BODIES):
                results, bad = run([body_case(va, hand_tree(), length=length)])
                self.assertEqual(bad, [], (hex(va), length))
                self.assertTrue(results[0][1]["out"].startswith(head))
                self.assertEqual(results[0][1]["boundary"][0], "unwrap-none")

    def test_wide_length_allocates_and_panics_in_the_real_bodies(self):
        for va in sorted(tool.BODIES):
            results, bad = run([body_case(va, hand_tree(), length=1 << 32)])
            self.assertEqual(bad, [], hex(va))
            got = results[0][1]
            self.assertEqual(got["events"][0], ("malloc", 0x80))
            self.assertEqual(got["boundary"][0], "unwrap-none")
            self.assertEqual(got["out"], b"")

    def test_allocation_failure_is_reported_with_size_and_align(self):
        results, bad = run([body_case(0x41a70c0, hand_tree(), length=1 << 33, oom=True)])
        self.assertEqual(bad, [])
        self.assertEqual(results[0][1]["boundary"], ("alloc-error", 1, 0x80))

    def test_model_mutants_are_caught(self):
        caught = set()
        for name in tool.MODEL_MUTANTS:
            for c, got, _ in RESULTS:
                if tool.compare(c, tool.expected(c, ROWS, frozenset({name})), got):
                    caught.add(name)
                    break
        self.assertEqual(set(tool.MODEL_MUTANTS) - caught, set())

    def test_byte_flips_are_caught(self):
        picked = []
        for va in (0x226c320, 0x41a70c0, 0x238a340, 0x5133fb0, 0x28ff740, 0x50c01d0):
            for v, f in tool.sweep(IMAGE, va, EXT[va]):
                imm = f.get("imm")
                if f["op"] == 0x83 and imm == 10:
                    picked.append((va, v + f["len"] - 1, 0x01))
                elif f["op"] == 0xc1 and imm == 0x20:
                    picked.append((va, v + f["len"] - 1, 0x20))
                elif f["op"] == 0x80 and imm in (0, 1) and f["rm"][0] == "m" and f["rm"][4] == 0x1b:
                    picked.append((va, v + f["len"] - 1, 0x02))
                elif f["op"] == 0x69 and imm == tool.KEY_BYTES:
                    picked.append((va, v + f["len"] - 4, 0x04))
        self.assertGreaterEqual(len(picked), 10)
        for va, at, bit in picked:
            mine = tool.cases_using(RESULTS, va)
            sample = mine[::3] + [c for c in mine if c["kind"] == "rec" and c["cfg"][3] in (1, 2)][:30]
            _, bad = run(sample, override={at: IMAGE.code(at, 1)[0] ^ bit}, stop=True)
            self.assertTrue(bad, f"{va:#x}@{at:#x} flip not detected")

    def test_unflipped_override_is_clean(self):
        _, bad = run(CASES[:60], override={0x226c320: IMAGE.code(0x226c320, 1)[0]}, stop=True)
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
        self.assertEqual(len(out), 7)
        self.assertTrue(all(hit == 0 for _, _, hit in out), out)

    def test_wrong_role_fails_static_check(self):
        saved = {va: dict(r) for va, r in tool.BODIES.items()}
        try:
            tool.BODIES[0x41a70c0]["fam"] = "226"
            with self.assertRaises(tool.ToolError):
                tool.facts(IMAGE, EXT, 0x41a70c0)
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
        for shape in (0, 1, 2) * 40:
            t = tool.make_tree(stream, shape)
            want = [t.nodes[(a - tool.TREE_AT) // tool.NODE_STRIDE]["keys"][j]["outcome"] for a, j in tool.inorder_keys(t)]
            self.assertEqual(list(walk(t, len(want))), want)

    def test_valid_cases_equal_reference_through_the_real_bytes(self):
        valid = [r for r in RESULTS if r[0]["kind"] == "body" and tool.oracle_applies(r[0])]
        self.assertGreater(len(valid), 20)
        for c, got, _ in valid:
            recs = [tool.key_record(c["tree"], k) for k in tool.inorder_keys(c["tree"])]
            self.assertEqual(got["out"][len(c["prefix"]):],
                             tool.reference_bytes(recs, c["cfg"][3], c["cfg"][4], tool.BODIES[c["body"]]["fam"]))

    def test_generated_nodes_respect_the_b_tree_shape(self):
        stream = tool.Stream("shape")
        for shape in (0, 1, 2) * 30:
            t = tool.make_tree(stream, shape)
            self.assertLessEqual(len(t.nodes), 24)
            for i, n in enumerate(t.nodes):
                self.assertLessEqual(len(n["keys"]), 11)
                if n["edges"] is not None:
                    self.assertEqual(len(n["edges"]), len(n["keys"]) + 1)
                    for e, child in enumerate(n["edges"]):
                        self.assertEqual((t.nodes[child]["parent"], t.nodes[child]["pidx"]), (i, e))


class Packet(unittest.TestCase):
    def test_small_generation_runs_and_detects_all_controls(self):
        with tempfile.TemporaryDirectory() as tmp:
            summary = tool.generate(tmp, 300, 60, 60)
            self.assertEqual(summary["mismatches"], 0)
            self.assertEqual(summary["controls"], summary["controls_detected"])
            measure = json.loads((pathlib.Path(tmp) / "measure.json").read_text())
            self.assertEqual(measure["negative_controls"], measure["negative_detected"])

    def test_manifest_matches_files(self):
        rows = [line.split("  ") for line in (PACKET / "MANIFEST.sha256").read_text().splitlines()]
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
            self.assertEqual(int(f[2]), ROWS[int(f[0], 16)]["insns"])
        lines = (PACKET / "records.tsv").read_text().splitlines()[1:]
        self.assertEqual(sorted(l.split("\t")[0] for l in lines), sorted(tool.FAMS))
        for line in lines:
            f = line.split("\t")
            self.assertEqual(f[5], ",".join(str(x) for x in tool.FLAG_CMPS[f[0]]))
        lines = (PACKET / "iter-next.tsv").read_text().splitlines()[1:]
        self.assertEqual(sorted(int(l.split("\t")[0], 16) for l in lines), sorted(tool.NEXTS))


if __name__ == "__main__":
    unittest.main()
