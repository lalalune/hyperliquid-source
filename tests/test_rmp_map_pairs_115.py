import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import rmp_map_pairs_115 as T  # noqa: E402

FOLDER = ROOT / "research" / "work-items" / "serialization-rmp-map-pairs-115"


class Shared:
    image = None
    cases = None
    results = None

    @classmethod
    def load(cls):
        if cls.image is None:
            cls.image = T.Image(T.BINARY.read_bytes())
            cls.cases = T.all_cases(160)
            cls.results, misses = T.evaluate(cls.image, cls.cases)
            cls.misses = misses
        return cls


def leaf(keys, vals, parent=0, pidx=0):
    return {"parent": parent, "pidx": pidx, "keys": keys, "vals": vals, "edges": []}


class EncoderTests(unittest.TestCase):
    def test_array_header_boundaries(self):
        self.assertEqual(T.array_header(0), b"\x90")
        self.assertEqual(T.array_header(15), b"\x9f")
        self.assertEqual(T.array_header(16), b"\xdc\x00\x10")
        self.assertEqual(T.array_header(0xffff), b"\xdc\xff\xff")
        self.assertEqual(T.array_header(0x10000), b"\xdd\x00\x01\x00\x00")

    def test_uint_boundaries(self):
        self.assertEqual(T.write_uint(0x7f), b"\x7f")
        self.assertEqual(T.write_uint(0x80), b"\xcc\x80")
        self.assertEqual(T.write_uint(0x100), b"\xcd\x01\x00")
        self.assertEqual(T.write_uint(0x10000), b"\xce\x00\x01\x00\x00")
        self.assertEqual(T.write_uint(1 << 32), b"\xcf" + (1 << 32).to_bytes(8, "big"))

    def test_key_text_is_str8_with_prefix(self):
        text = T.address_text(bytes(19) + b"\xab")
        self.assertEqual(len(text), T.HEX_CHARS)
        self.assertEqual(text, b"0x" + b"00" * 19 + b"ab")
        self.assertEqual(T.write_str(text)[:2], b"\xd9\x2a")
        self.assertEqual(T.write_str(b"x" * 31)[:1], b"\xbf")


class IteratorTests(unittest.TestCase):
    def tree(self):
        root = T.NODE_AT
        a, b = T.NODE_AT + T.NODE_SPAN, T.NODE_AT + 2 * T.NODE_SPAN
        k = [bytes([i]) * 20 for i in range(4)]
        nodes = {root: {"parent": 0, "pidx": 0, "keys": [k[1]], "vals": [11], "edges": [a, b]},
                 a: leaf([k[0]], [10], root, 0), b: leaf([k[2], k[3]], [12, 13], root, 1)}
        return nodes, root

    def test_in_order_walk(self):
        nodes, root = self.tree()
        got = list(T.tree_iter([1, 0, root, 1, 0, 0, 0, 0, 4], nodes))
        want_nodes = [root + T.NODE_SPAN, root, root + 2 * T.NODE_SPAN, root + 2 * T.NODE_SPAN]
        self.assertEqual([k for k, _ in got],
                         [n + T.NODE_KEYS + 20 * i for n, i in zip(want_nodes, (0, 0, 0, 1))])

    def test_length_past_end_panics(self):
        nodes, root = self.tree()
        with self.assertRaises(T.IterPanic):
            list(T.tree_iter([1, 0, root, 1, 0, 0, 0, 0, 5], nodes))

    def test_tag_low_32_bits(self):
        nodes, root = self.tree()
        self.assertEqual(len(list(T.tree_iter([0x100000001, 0, root, 1, 0, 0, 0, 0, 2], nodes))), 2)
        with self.assertRaises(T.IterPanic):
            list(T.tree_iter([0x100000000, 0, root, 1, 0, 0, 0, 0, 1], nodes))

    def test_slices_and_length(self):
        at = lambda i: T.ELEM_AT + T.ELEM * i  # noqa: E731
        rec = [2, at(0), at(2), at(5), at(6)]
        self.assertEqual(T.length_of(rec), 3)
        self.assertEqual([k for k, _ in T.slice_iter(rec)], [at(0), at(1), at(5)])


class BinaryTests(unittest.TestCase):
    def test_hash_mismatch_rejected(self):
        data = bytearray(T.BINARY.read_bytes())
        data[0x1000] ^= 1
        with self.assertRaises(T.ToolError):
            T.Image(bytes(data))

    def test_static_templates(self):
        s = Shared.load()
        rows, ext = T.static_rows(s.image)
        self.assertEqual(len(rows), 14)
        self.assertEqual({r["role"] for r in rows}, set(T.BODY_ROLES))

    def test_corrupted_call_target_rejected(self):
        data = bytearray(T.BINARY.read_bytes())
        img = T.Image(bytes(data))
        text = img.text
        off = 0x222a837 - text["address"] + text["offset"]   # call hdr in the 0x226 collect body
        self.assertEqual(data[off], 0xe8)
        data[off + 1] ^= 0x10
        bad = T.Image(bytes(data), check=False)
        with self.assertRaises(T.ToolError):
            T.static_rows(bad)

    def test_cases_match(self):
        s = Shared.load()
        self.assertEqual(s.misses, [])
        modes = {c["mode"] for c in s.cases}
        self.assertEqual(modes, set(T.MODES))
        self.assertTrue(any(r["panic"] for r in s.results))
        self.assertTrue(any(c["fault"] >= 0 for c in s.cases))

    def test_model_mutants_detected(self):
        s = Shared.load()
        rows = T.model_controls(s.cases, s.results)
        caught = {m for _, m, hit in rows if hit is not None}
        for mut in ("hex-upper", "fixint-128", "no-pair-header", "value-first", "end-err-tag", "preorder",
                    "remaining-ignored", "no-free-on-error", "slices-swapped", "bufend-skipped"):
            self.assertIn(mut, caught)

    def test_inverted_branch_detected(self):
        s = Shared.load()
        subset = [c for c in s.cases if c["copy"] == "226"]
        # jne after `cmp $0x2,(%rdx)`: the slice-length arm of the 0x226 collect body
        insn = 0x222a7be
        _, misses = T.evaluate(s.image, subset, {insn: T.Image.code(s.image, insn, 1)[0] ^ 1}, stop_on_first=True)
        self.assertTrue(misses)

    def test_model_read_outside_case_memory(self):
        mem = T.reader({T.ELEM_AT: bytes(0x20)})
        with self.assertRaises(T.ToolError):
            mem(T.ELEM_AT + 0x18, 16)

    def test_generation_is_deterministic(self):
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            T.generate(pathlib.Path(a), 40, controls=False)
            T.generate(pathlib.Path(b), 40, controls=False)
            for name in ("bodies.tsv", "coverage.tsv", "cases-sample.tsv", "summary.json"):
                self.assertEqual((pathlib.Path(a) / name).read_bytes(), (pathlib.Path(b) / name).read_bytes())

    def test_committed_evidence(self):
        s = Shared.load()
        summary = json.loads((FOLDER / "summary.json").read_text())
        self.assertEqual(summary["binary_sha256"], T.SHA256)
        self.assertEqual(summary["cases"], T.CASES)
        self.assertEqual(summary["mismatches"], 0)
        self.assertEqual(summary["controls"]["model"], [len(T.MODEL_MUTANTS), len(T.MODEL_MUTANTS)])
        lines = (FOLDER / "cases-sample.tsv").read_text().splitlines()[1:]
        want = [T.case_row(c, g) for c, g in zip(s.cases, s.results) if c["k"] % T.SAMPLE_EVERY == 0]
        self.assertEqual(lines[:len(want)], want)
        rows, _ = T.static_rows(s.image)
        bodies = (FOLDER / "bodies.tsv").read_text().splitlines()[1:]
        self.assertEqual(len(bodies), len(rows))
        for line, r in zip(bodies, rows):
            self.assertEqual(line.split("\t")[5], r["sha256"])


if __name__ == "__main__":
    unittest.main()
