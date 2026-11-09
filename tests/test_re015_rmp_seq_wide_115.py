"""Tests for tools/re015_rmp_seq_wide_115.py (node #115 rmp newtype(Vec<T>) serializers, bodies the first packet left out)."""
import hashlib
import json
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import re015_rmp_seq_wide_115 as tool  # noqa: E402

seq = tool.seq
vd = tool.vd
PACKET = ROOT / "research" / "work-items" / "RE-015-rmp-seq-wide-115"
DATA = IMAGE = VIMAGE = EXT = None
MERGED = WIDE = SKIPPED = SCAN = ROWS = UB = A_BODIES = None


class bodies:
    """Context: swap the first packet's body table for `table`, restore it on exit."""

    def __init__(self, table):
        self.table = table

    def __enter__(self):
        self.saved = dict(seq.BODIES)
        seq.BODIES.clear()
        seq.BODIES.update(self.table)

    def __exit__(self, *exc):
        seq.BODIES.clear()
        seq.BODIES.update(self.saved)
        return False


def setUpModule():
    global DATA, IMAGE, VIMAGE, EXT, MERGED, WIDE, SKIPPED, SCAN, ROWS, UB, A_BODIES
    DATA = tool.BINARY.read_bytes()
    IMAGE = seq.Image(DATA)
    VIMAGE = vd.Image(DATA)
    EXT = seq.extents(IMAGE)
    MERGED, WIDE, SKIPPED, SCAN = tool.discover(IMAGE, EXT)
    with bodies(WIDE):
        ROWS = {r["va"]: r for r in seq.static_rows(IMAGE, EXT)}
    UB = {va: ROWS[va] for va in sorted(WIDE) if WIDE[va][2] == 8 and ROWS[va]["direct"] in tool.UINT_WRITERS
          and ROWS[va]["compound"] in tool.UINT_WRITERS}
    ABI = tool.split_abi(IMAGE, EXT, WIDE, ROWS, UB)
    for va in ABI:
        SKIPPED[va] = ABI[va]
        del WIDE[va]
    A_BODIES = {va: d for va, d in WIDE.items() if va not in UB}


def uint_cases(per_body=60, only=None):
    layouts = {va: WIDE[va][1] for va in UB}
    rows = {va: r for va, r in UB.items() if only is None or va in only}
    return tool.all_cases_b(rows, layouts, per_body)


def uint_case(**kw):
    base = {"body": 0x226ff00, "layout": "b", "k": 1, "kind": "body", "prefix": b"", "ser_tail": bytes(8),
            "cfg": bytes(5), "fault": None, "oom": False, "name": b"x", "vcap": 0, "room": 200, "words": [1], "n": 1,
            "errw": 0}
    base.update(kw)
    return base


ROW0 = {"msg": (0x5e90a1, 14)}


class UintModel(unittest.TestCase):
    def test_smallest_form_boundaries(self):
        for value, want in ((0, b"\x00"), (0x7f, b"\x7f"), (0x80, b"\xcc\x80"), (0xff, b"\xcc\xff"),
                            (0x100, b"\xcd\x01\x00"), (0xffff, b"\xcd\xff\xff"), (0x10000, b"\xce\x00\x01\x00\x00"),
                            (0xffffffff, b"\xce\xff\xff\xff\xff"), (0x100000000, b"\xcf" + (1 << 32).to_bytes(8, "big")),
                            (tool.M64, b"\xcf" + b"\xff" * 8)):
            p = tool.model_b(uint_case(words=[value]), ROW0)
            self.assertEqual(p["out"], b"\x91" + want)

    def test_ext_name_rejected_before_any_work(self):
        p = tool.model_b(uint_case(name=b"_ExtStruct"), ROW0)
        self.assertEqual(p["result"], (vd.EXT_TAG, 0x5e90a1, 14))
        self.assertEqual((p["events"], p["out"]), ([], b""))

    def test_direct_events_and_bytes(self):
        p = tool.model_b(uint_case(n=3, words=[1, 0x80, 0x1234]), ROW0)
        self.assertEqual(p["events"], [("hdr", 3), ("wu", 1, "ser"), ("wu", 0x80, "ser"), ("wu", 0x1234, "ser")])
        self.assertEqual(p["out"], b"\x93\x01\xcc\x80\xcd\x12\x34")

    def test_wide_header_for_long_arrays(self):
        c = uint_case(n=16, words=[0] * 16, room=300)
        self.assertEqual(tool.model_b(c, ROW0)["out"][:3], b"\xdc\x00\x10")

    def test_element_error_keeps_written_prefix(self):
        p = tool.model_b(uint_case(n=4, words=[5, 6, 7, 8], fault=3), ROW0)
        self.assertEqual(p["out"], b"\x94\x05\x06")
        self.assertEqual(p["result"], (vd.ERR_TAG, vd.FAULT[0], vd.FAULT[1]))

    def test_header_error_writes_nothing(self):
        p = tool.model_b(uint_case(fault=0), ROW0)
        self.assertEqual((p["out"], p["events"]), (b"", [("hdr", 1)]))

    def test_buffered_counts_and_copies(self):
        n = seq.wrap_len(8, 3, 0)
        c = uint_case(n=n, words=[1, 0x100, 3], cfg=bytes([1, 0, 1, 1, 1]))
        p = tool.model_b(c, ROW0)
        cfg = vd.config_word(c["cfg"])
        self.assertEqual(p["events"], [("malloc", 0x80), ("wu", 1, "cmp", 0, 0, cfg), ("wu", 0x100, "cmp", 1, 1, cfg),
                                       ("wu", 3, "cmp", 2, 4, cfg), ("hdr", 3), ("free", 0x80)])
        self.assertEqual(p["out"], b"\x93\x01\xcd\x01\x00\x03")

    def test_buffered_error_releases_buffer(self):
        n = seq.wrap_len(8, 3, 0)
        p = tool.model_b(uint_case(n=n, words=[1, 2, 3], fault=1), ROW0)
        self.assertEqual(p["events"][-1], ("free", 0x80))
        self.assertEqual(p["out"], b"")

    def test_buffered_growth_follows_the_reserve_contract(self):
        n = seq.wrap_len(8, 20, 0)
        p = tool.model_b(uint_case(n=n, words=[tool.M64] * 20), ROW0)
        self.assertTrue(any(e[0] == "res" for e in p["events"]))
        self.assertEqual(p["events"][-1][0], "free")
        self.assertGreater(p["events"][-1][1], 0x80)

    def test_oom_is_a_boundary(self):
        p = tool.model_b(uint_case(n=seq.wrap_len(8, 2, 0), oom=True), ROW0)
        self.assertEqual(p["boundary"], ("alloc-error", 1, 0x80))


class Discovery(unittest.TestCase):
    def test_first_packet_set_is_untouched(self):
        self.assertEqual(len(MERGED), 54)
        self.assertEqual(set(MERGED), set(seq.BODIES))
        self.assertFalse(set(WIDE) & set(MERGED))

    def test_every_scan_member_is_classified_once(self):
        members = [r[0] for r in SCAN]
        self.assertEqual(len(members), len(set(members)))
        for va in members:
            self.assertEqual(sum(1 for s in (MERGED, WIDE, SKIPPED) if va in s) + (va in seq.EXCLUDED), 1, hex(va))

    def test_wide_bodies_pass_the_six_call_facts(self):
        self.assertGreaterEqual(len(WIDE), 25)
        with bodies(WIDE):
            for va in WIDE:
                facts = seq.body_facts(IMAGE, EXT, va)
                self.assertEqual(facts["end_fn"], seq.FAMILIES[WIDE[va][0]]["end_" + WIDE[va][1]])

    def test_stride_8_bodies_call_the_unsigned_writers(self):
        self.assertEqual(sorted(UB), [0x226d4c0, 0x226ff00, 0x419dee0, 0x41a6360, 0x52f2d00, 0x52f81d0])
        writers = {r["direct"] for r in UB.values()} | {r["compound"] for r in UB.values()}
        self.assertEqual(sorted(writers), sorted(tool.UINT_WRITERS))

    def test_skipped_members_keep_their_reason(self):
        self.assertIn(0x419a670, SKIPPED)
        self.assertIn("direct calls", SKIPPED[0x419a670])
        self.assertIn(0x2270910, SKIPPED)
        self.assertIn(".got", SKIPPED[0x2270910])


class RealBytes(unittest.TestCase):
    def test_stub_bodies_match_the_model(self):
        pick = [va for va in sorted(A_BODIES)][::3]
        with bodies({va: A_BODIES[va] for va in pick}):
            rows = [ROWS[va] for va in pick]
            cases = []
            for index, va in enumerate(pick):
                stream = seq.Stream(f"rmp-seq-newtype/{va:#x}")
                cases += [c for c in (seq.make_case(stream, va, k, index) for k in range(100)) if c.get("limit") is None]
            results, bad = seq.evaluate(IMAGE, EXT, rows, cases)
            self.assertEqual(bad, [])
            self.assertTrue(any(seq.buffered(c["n"]) for c, _, _ in results))

    def test_unsigned_writer_bodies_match_the_model(self):
        cases = uint_cases(100)
        results, bad = tool.evaluate_b(VIMAGE, EXT, UB, cases)
        self.assertEqual(bad, [])
        kinds = {tool.seq.buffered(c["n"]) for c, _, _ in results}
        self.assertEqual(kinds, {False, True})
        self.assertTrue(any(c["fault"] is not None for c, _, _ in results))
        self.assertTrue(any(c["oom"] for c, _, _ in results))

    def test_output_is_a_decodable_msgpack_array(self):
        cases = [c for c in uint_cases(60) if not vd.is_ext(c["name"]) and c["fault"] is None and not c["oom"]
                 and c["n"] < 400 and c["n"] > 0 and len(c["words"]) == c["n"]][:60]
        results, bad = tool.evaluate_b(VIMAGE, EXT, UB, cases)
        self.assertEqual(bad, [])
        for c, got, _ in results:
            body = got["out"][len(c["prefix"]):]
            hdr = 1 if body[0] & 0xf0 == 0x90 else 3
            count = body[0] & 0xf if hdr == 1 else int.from_bytes(body[1:3], "big")
            vals, at = [], hdr
            while at < len(body):
                t = body[at]
                size = {0xcc: 1, 0xcd: 2, 0xce: 4, 0xcf: 8}.get(t)
                if size is None:
                    vals.append(t)
                    at += 1
                else:
                    vals.append(int.from_bytes(body[at + 1:at + 1 + size], "big"))
                    at += 1 + size
            self.assertEqual(count, c["n"])
            self.assertEqual(vals, c["words"][:c["n"]])


class NegativeControls(unittest.TestCase):
    def test_model_mutants_are_all_caught(self):
        cases = uint_cases(120)
        results, bad = tool.evaluate_b(VIMAGE, EXT, UB, cases)
        self.assertEqual(bad, [])
        for name in tool.B_MUTANTS:
            hit = [c for c, got, _ in results if tool.compare_b(c, tool.model_b(c, UB[c["body"]], frozenset({name})), got)]
            self.assertTrue(hit, name)

    def test_writer_byte_flips_are_caught(self):
        writers = sorted({r["direct"] for r in UB.values()} | {r["compound"] for r in UB.values()})
        sites = tool.writer_sites(VIMAGE, EXT, writers)
        self.assertGreaterEqual(len(sites), 12)
        cases = uint_cases(100)
        caught = 0
        for va, label, at, bit in sites[:12]:
            use = [c for c in cases if UB[c["body"]]["direct"] == va or UB[c["body"]]["compound"] == va]
            _, bad = tool.evaluate_b(VIMAGE, EXT, UB, use, override={at: VIMAGE.code(at, 1)[0] ^ bit}, stop_on_first=True)
            caught += 1 if bad else 0
        self.assertGreaterEqual(caught, 6)

    def test_body_byte_flip_in_the_name_length_is_caught(self):
        va = 0x226ff00
        at = None
        for v, f in seq.sweep(IMAGE, va, EXT[va]):
            if f["op"] == 0x83 and f.get("imm") == 10:
                at = v + f["len"] - 1
                break
        self.assertIsNotNone(at)
        cases = [c for c in uint_cases(60, {va})]
        _, bad = tool.evaluate_b(VIMAGE, EXT, UB, cases, override={at: VIMAGE.code(at, 1)[0] ^ 1}, stop_on_first=True)
        self.assertTrue(bad)

    def test_bad_declarations_and_a_damaged_binary_are_refused(self):
        rows = tool.range_controls(IMAGE, EXT, WIDE, MERGED)
        self.assertGreaterEqual(len(rows), 6)
        for _, name, hit in rows:
            self.assertIsNotNone(hit, name)
        self.assertEqual(set(seq.BODIES), set(MERGED))

    def test_a_flipped_binary_byte_changes_the_digest_check(self):
        bad = DATA[:-1] + bytes([DATA[-1] ^ 1])
        with self.assertRaises(seq.ToolError):
            seq.Image(bad)
        with self.assertRaises(vd.ToolError):
            vd.Image(bad)

    def test_a_case_that_reads_past_its_words_is_refused(self):
        with self.assertRaises(seq.ToolError):
            tool.model_b(uint_case(n=5, words=[1, 2]), ROW0)

    def test_corrupted_expectation_is_reported(self):
        c = uint_case(words=[0x80], body=0x226ff00)
        results, bad = tool.evaluate_b(VIMAGE, EXT, UB, [c])
        self.assertEqual(bad, [])
        got = results[0][1]
        want = tool.model_b(c, UB[0x226ff00])
        want["out"] = want["out"][:-1] + bytes([want["out"][-1] ^ 1])
        self.assertEqual(tool.compare_b(c, want, got), "bytes")
        want = tool.model_b(c, UB[0x226ff00])
        want["events"] = want["events"][:-1]
        self.assertEqual(tool.compare_b(c, want, got), "events")


class PacketFiles(unittest.TestCase):
    def setUp(self):
        if not PACKET.exists():
            self.skipTest("packet not generated yet")

    def test_manifest_matches_files(self):
        lines = (PACKET / "MANIFEST.sha256").read_text().splitlines()
        names = set()
        for line in lines:
            digest, name = line.split("  ")
            names.add(name)
            self.assertEqual(hashlib.sha256((PACKET / name).read_bytes()).hexdigest(), digest, name)
        listed = {p.name for p in PACKET.iterdir() if p.name != "MANIFEST.sha256"}
        self.assertEqual(names, listed)

    def test_summary_and_measure_agree(self):
        s = json.loads((PACKET / "summary.json").read_text())
        m = json.loads((PACKET / "measure.json").read_text())
        self.assertEqual(s["binary_sha256"], tool.SHA256)
        self.assertEqual(s["mismatches"], 0)
        self.assertEqual(m["cases"], s["stub_cases"] + s["uint_cases"])
        self.assertEqual(m["negative_controls"], s["controls"])
        self.assertEqual(m["negative_detected"], s["controls_detected"])
        self.assertEqual(s["controls"], s["controls_detected"])
        self.assertEqual(s["wide_bodies"], len(WIDE))
        self.assertEqual(s["uint_real_bodies"], len(UB))

    def test_controls_table_has_no_miss(self):
        rows = (PACKET / "controls.tsv").read_text().splitlines()[1:]
        self.assertTrue(rows)
        self.assertTrue(all(r.split("\t")[2] == "yes" for r in rows))

    def test_scan_table_matches_discovery(self):
        rows = [r.split("\t") for r in (PACKET / "scan.tsv").read_text().splitlines()[1:]]
        self.assertEqual({int(r[0], 16) for r in rows if r[4] == "wide"}, set(WIDE))
        self.assertEqual({int(r[0], 16) for r in rows if r[4] == "first-packet"}, set(MERGED))

    def test_coverage_of_the_unsigned_bodies_and_writers(self):
        rows = [r.split("\t") for r in (PACKET / "coverage.tsv").read_text().splitlines()[1:]]
        seen = {"uint-body": 0, "uint-writer": 0}
        for fn, role, total, hit in rows:
            if role in seen:
                seen[role] += 1
                # the layout-b direct writers keep an inlined finish_grow arm that ample room never reaches
                floor = 80 if role == "uint-body" else 40
                self.assertGreaterEqual(int(hit) * 100, int(total) * floor, fn)
        self.assertEqual(seen, {"uint-body": 6, "uint-writer": 6})


if __name__ == "__main__":
    unittest.main()
