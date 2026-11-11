import hashlib
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import re009_vec_writer_serializers_115 as tool  # noqa: E402

PACKET = ROOT / "research" / "work-items" / "RE-009-vec-writer-serializers-115"


def vec_spec(cap, data, **extra):
    spec = {"vec": {"cap": cap, "len": len(data), "data": data.ljust(cap, b"\0")}, "fail_after": None}
    spec.update(extra)
    return spec


class VecWriterSerializers115(unittest.TestCase):
    def test_movq_decode_preserves_target_bytes(self):
        raw = bytes.fromhex("660fd60424")
        form = tool.decode2(raw + b"\0" * 11, 0x477738a)
        self.assertEqual(form["bytes"], raw)
        self.assertEqual((form["op"], form["len"]), (0xfd6, len(raw)))

    @classmethod
    def setUpClass(cls):
        cls.image = tool.Image(tool.BINARY.read_bytes())
        cls.tables = tool.Tables(cls.image)

    def model(self, fn, spec, mut=frozenset()):
        spec = dict(spec, fn=fn)
        return tool.run_model(spec, self.tables, mut)

    def vec_bytes(self, res):
        st = res["mem"][2]
        cap = int.from_bytes(st[0:8], "little")
        ptr = int.from_bytes(st[8:16], "little")
        ln = int.from_bytes(st[16:24], "little")
        heap = res["mem"][0]
        off = ptr - tool.HEAP_AT
        return cap, ln, bytes(heap[off:off + ln])

    def test_regenerated_evidence_matches_packet(self):
        with tempfile.TemporaryDirectory() as tmp:
            summary = tool.generate(pathlib.Path(tmp))
            self.assertEqual(summary["mismatches"], 0)
            self.assertEqual(summary["cases"], 13000)
            self.assertEqual(summary["negative_controls"]["detected"], summary["negative_controls"]["total"])
            names = sorted(p.name for p in PACKET.iterdir() if p.suffix in (".tsv", ".json"))
            self.assertEqual(names, sorted(p.name for p in pathlib.Path(tmp).iterdir()))
            for name in names:
                self.assertEqual((pathlib.Path(tmp) / name).read_bytes(), (PACKET / name).read_bytes(), name)

    def test_manifest(self):
        listed = {}
        for row in (PACKET / "MANIFEST.sha256").read_text().splitlines():
            digest, name = row.split("  ", 1)
            listed[name] = digest
        self.assertEqual(sorted(listed), sorted(p.name for p in PACKET.iterdir() if p.name != "MANIFEST.sha256"))
        for name, digest in listed.items():
            self.assertEqual(hashlib.sha256((PACKET / name).read_bytes()).hexdigest(), digest, name)

    def test_model_matches_machine_code_for_every_function(self):
        for fn in tool.ORDER:
            rows, bad, total = tool.evaluate(self.image, self.tables, cases=tool.cases_for(fn, 120))
            self.assertEqual((fn, bad, total), (fn, 0, 120))

    def test_grow_policy(self):
        res = self.model("grow", dict(vec_spec(0, b""), len=0, add=1, align=1, elem=1))
        self.assertEqual(self.vec_bytes(res)[0], 8)
        res = self.model("grow", dict(vec_spec(8, b"abcdefgh"), len=8, add=1, align=1, elem=1))
        self.assertEqual(self.vec_bytes(res)[0], 16)
        res = self.model("grow", dict(vec_spec(8, b"abcdefgh"), len=8, add=100, align=1, elem=1))
        self.assertEqual(self.vec_bytes(res)[:2], (108, 8))
        res = self.model("grow", dict(vec_spec(4, b"ab"), len=2, add=1, align=1, elem=0))
        self.assertEqual(res["panic"], ("alloc_handler", 0, None, None))

    def test_grow_failures(self):
        res = self.model("grow", dict(vec_spec(4, b"ab"), len=2, add=1, align=1, elem=1, fail_after=0))
        self.assertEqual(res["panic"], ("alloc_handler", 1, 8, None))
        res = self.model("grow", dict(vec_spec(4, b"ab"), len=2, add=(1 << 64) - 1, align=1, elem=1))
        self.assertEqual(res["panic"][:2], ("alloc_handler", 0))

    def test_decimal_formatters(self):
        for fn in ("itoa_a", "itoa_b"):
            for v in (0, 7, 10, 12345, 10 ** 19, (1 << 64) - 1):
                res = self.model(fn, {"v": v, "st": {0xa0: bytes(24)}})
                start, n = res["ret"]
                self.assertEqual(n, len(str(v)))
                self.assertEqual(start, tool.BUF + 20 - n)

    def test_rmp_unsigned_markers(self):
        want = {5: b"\x05", 0x7f: b"\x7f", 0x80: b"\xcc\x80", 0xff: b"\xcc\xff", 0x100: b"\xcd\x01\x00",
                0xffff: b"\xcd\xff\xff", 0x10000: b"\xce\x00\x01\x00\x00", 0xffffffff: b"\xce\xff\xff\xff\xff",
                0x100000000: b"\xcf\x00\x00\x00\x01\x00\x00\x00\x00",
                (1 << 64) - 1: b"\xcf" + b"\xff" * 8}
        for v, blob in want.items():
            res = self.model("rmp_uint", dict(vec_spec(0, b""), v=v))
            cap, ln, data = self.vec_bytes(res)
            self.assertEqual(data, blob, hex(v))
            self.assertEqual(res["mem"][2][tool.OUT - tool.ST_AT], 2)

    def test_rmp_io_error_result(self):
        res = self.model("rmp_uint", dict(vec_spec(0, b""), v=0x1234, fail_after=0))
        self.assertEqual(res["mem"][2][tool.OUT - tool.ST_AT], 0)
        self.assertEqual(int.from_bytes(res["mem"][2][tool.OUT - tool.ST_AT + 8:tool.OUT - tool.ST_AT + 16], "little"),
                         tool.IOERR)
        res = self.model("rmp_uint", dict(vec_spec(2, b"x"), v=0x1234, fail_after=0))
        self.assertEqual(res["mem"][2][tool.OUT - tool.ST_AT], 1)
        self.assertEqual(self.vec_bytes(res)[2], b"x\xcd")

    def test_escape_table_and_output(self):
        res = self.model("escape", dict(vec_spec(64, b""), klen=8, **{"in": b'a"b\\c\n\x01\x7f'}))
        self.assertEqual(self.vec_bytes(res)[2], b'a\\"b\\\\c\\n\\u0001\x7f')

    def test_pretty_struct_output(self):
        spec = dict(vec_spec(128, b""), st={0x60: (12345).to_bytes(8, "little"),
                                            0x108: tool.INDENT.to_bytes(8, "little") + (2).to_bytes(8, "little")
                                            + (1).to_bytes(8, "little") + b"\0"},
                    **{"in": bytes(0x100) + b"  "})
        res = self.model("struct1", spec)
        key = self.tables.pretty_key.decode("latin-1")
        self.assertEqual(self.vec_bytes(res)[2], ("{\n    \"" + key + "\": 12345\n  }").encode())
        self.assertEqual(int.from_bytes(res["mem"][2][0x118:0x120], "little"), 1)

    def test_array_writer_with_non_finite_float(self):
        ent = b"Z" + bytes(7) + (3).to_bytes(8, "little") + (4).to_bytes(8, "little") + (0x7ff0000000000000).to_bytes(8, "little")
        spec = dict(vec_spec(64, b""), st={0xe0: (1).to_bytes(8, "little") + tool.ENTRIES.to_bytes(8, "little")
                                          + (1).to_bytes(8, "little")}, **{"in": bytes(0x200) + ent})
        res = self.model("array", spec)
        self.assertEqual(self.vec_bytes(res)[2], b'[["eZ",3,4,null]]')

    def test_wrong_models_are_detected(self):
        for fn, mut in tool.MODEL_MUTANTS[::3]:
            _, bad, _ = tool.evaluate(self.image, self.tables, mut=frozenset([mut]), stop_on_first=True,
                                      cases=tool.cases_for(fn, 900))
            self.assertGreater(bad, 0, mut)

    def test_corrupted_code_bytes_are_detected(self):
        for va, new in ((0x4787e9d, 0x74), (0x4777cd7, 0x85), (0x4783f37, 0x85), (0x47789d7, 0x72)):
            self.assertNotEqual(self.image.code(va, 1)[0], new)
            fn = {0x4787e9d: "grow", 0x4777cd7: "field", 0x4783f37: "struct1", 0x47789d7: "rmp_uint"}[va]
            _, bad, _ = tool.evaluate(self.image, self.tables, override={va: new}, stop_on_first=True,
                                      cases=tool.cases_for(fn, 300))
            self.assertGreater(bad, 0, hex(va))

    def test_input_and_range_controls(self):
        corrupt = bytearray(self.image.data)
        corrupt[self.image.text["offset"] + 7] ^= 1
        with self.assertRaises(tool.ToolError):
            tool.Image(bytes(corrupt))
        with self.assertRaises(tool.ToolError):
            self.image.code(self.image.text["address"] + self.image.text["size"] + 0x100, 4)
        with self.assertRaises(tool.ToolError):
            self.image.read(0x10, 4)

    def test_static_constants(self):
        consts = tool.static_evidence(self.image, self.tables, tool.function_rows(
            self.image, dict(tool.FUNCS, realloc_4787da0=0x4787da0)))
        self.assertTrue(all(consts["pair_tables"].values()))
        self.assertEqual(consts["hex_digits"], "0123456789abcdef")
        self.assertEqual(consts["escape_table_nonzero"]["0x22"], "0x22")
        self.assertEqual(consts["escape_table_nonzero"]["0x5c"], "0x5c")
        self.assertEqual(consts["escape_table_nonzero"]["0x0a"], "0x6e")
        self.assertEqual(consts["escape_table_nonzero"]["0x00"], "0x75")
        self.assertNotIn("0x2f", consts["escape_table_nonzero"])
        self.assertEqual(consts["functions"]["grow"]["bytes"], 142)

    def test_decoder_extensions(self):
        form = tool.decode2(bytes.fromhex("66c7042400010000"), 0x1000)  # mov WORD PTR [rsp],0x100 (+ next bytes)
        self.assertEqual((form["size"], form["imm"], form["len"]), (16, 0x100, 6))
        form = tool.decode2(bytes.fromhex("660fd6042400000000"), 0x1000)
        self.assertEqual((form["op"], form["len"]), (0xfd6, 5))


if __name__ == "__main__":
    unittest.main()
