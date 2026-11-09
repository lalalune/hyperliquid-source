import hashlib
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import re19_json_u64_115 as tool  # noqa: E402

PACKET = ROOT / "research" / "work-items" / "RE-019-json-u64-reader-115"
CACHE = {}


def image():
    if "image" not in CACHE:
        CACHE["image"] = tool.mat.Image(tool.BINARY.read_bytes())
        tool.constants_cache[0] = tool.constants(CACHE["image"])
        CACHE["cases"] = list(tool.all_cases(1500))
    return CACHE["image"]


def case(entry, data, idx=0, positive=1, pn=(1, 7), long=(0, 5)):
    return {"id": -1, "entry": entry, "mode": -1, "data": data, "idx": idx, "positive": positive, "pn": pn,
            "long": long}


class JsonU64Reader115(unittest.TestCase):
    def setUp(self):
        self.image = image()
        self.cases = CACHE["cases"]
        self.machine = tool.mat.Machine(self.image)

    def run_both(self, c, mut=frozenset()):
        return tool.run_case(self.machine, c), tool.expect(c, mut)

    def test_regenerated_evidence_matches_packet(self):
        with tempfile.TemporaryDirectory() as tmp:
            summary = tool.generate(pathlib.Path(tmp))
            self.assertEqual(summary["mismatches"], 0)
            self.assertEqual(summary["cases"], 12000)
            self.assertEqual(summary["negative_controls"], summary["negative_detected"])
            self.assertGreaterEqual(summary["negative_controls"], 30)
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

    def test_static_constants(self):
        k = tool.constants_cache[0]
        self.assertEqual(k["whitespace_bytes"], [9, 10, 13, 32])
        self.assertEqual(k["accumulator_limit_before_last_digit"], 1844674407370955160)
        self.assertEqual(k["last_digit_max_at_equal"], 5)
        self.assertEqual((k["eof_code"], k["number_eof_code"], k["bad_digit_code"], k["leading_zero_code"]),
                         (5, 5, 13, 13))
        self.assertEqual(k["vtable_peek"], k["vtable_signed"])
        self.assertNotEqual(k["vtable_peek"], k["vtable_float"])
        self.assertEqual((k["error_line_offset"], k["error_object_size"]), (0x18, 0x28))

    def test_hand_written_reader_outcomes(self):
        got, want = self.run_both(case("reader", b" \t\n42,", pn=(1, 42)))
        self.assertEqual((got["rax"], got["rdx"]), (0, 42))
        self.assertEqual(got, want)
        got, want = self.run_both(case("reader", b"   "))
        self.assertEqual(got["rax"], 1)
        self.assertEqual([t[0] for t in got["trace"]], ["pos", "make"])
        self.assertEqual(got, want)
        got, want = self.run_both(case("reader", b"-5", pn=(2, (1 << 64) - 5)))
        self.assertEqual(got["rax"], 1)
        self.assertEqual([t[0] for t in got["trace"]], ["number", "unexpected", "pos", "make", "free"])
        self.assertEqual(got, want)
        got, want = self.run_both(case("reader", b"x"))
        self.assertEqual([t[0] for t in got["trace"]], ["peek", "pos", "make", "free"])
        self.assertEqual(got, want)

    def test_digit_limit_boundary(self):
        for text, calls in ((b"18446744073709551615", "number"), (b"18446744073709551616", "long"),
                            (b"18446744073709551619", "long"), (b"1844674407370955160", "number")):
            got, want = self.run_both(case("number", text, pn=(1, 3)))
            self.assertEqual(got["trace"][0][0], calls, text)
            self.assertEqual(got, want)

    def test_leading_zero_and_end_of_input(self):
        got, want = self.run_both(case("number", b"01"))
        self.assertEqual((got["tag"], got["trace"][0][0]), (3, "pos"))
        self.assertEqual(got, want)
        got, want = self.run_both(case("number", b"0"))
        self.assertEqual(got["trace"], [("number", 1, 0, 1)])
        self.assertEqual(got, want)
        got, want = self.run_both(case("number", b"", idx=0))
        self.assertEqual(got["tag"], 3)
        self.assertEqual(got, want)

    def test_all_sampled_cases_match(self):
        for c in self.cases[:600]:
            got, want = self.run_both(c)
            self.assertEqual(got, want, c["id"])
            self.assertTrue(got["regs_ok"])

    def test_model_mutants_are_detected(self):
        for name in tool.MODEL_MUTANTS:
            at, _ = tool.first_mismatch(self.machine, self.cases, frozenset([name]))
            self.assertIsNotNone(at, name)

    def test_corrupted_code_bytes_are_detected(self):
        for va, old, new in tool.BYTE_MUTANTS:
            self.assertEqual(self.image.code(va, 1)[0], old, hex(va))
            mm = tool.mat.Machine(self.image, code_override={va: new})
            at, _ = tool.first_mismatch(mm, self.cases)
            self.assertIsNotNone(at, hex(va))

    def test_wrong_binary_digest_rejected(self):
        data = bytearray(self.image.data)
        data[self.image.text["offset"] + 0x10] ^= 0x40
        with self.assertRaises(tool.ToolError):
            tool.mat.Image(bytes(data))

    def test_address_outside_text_rejected(self):
        with self.assertRaises(tool.ToolError):
            self.image.code(self.image.text["address"] + self.image.text["size"], 4)

    def test_changed_expected_byte_rejected(self):
        va, old, _ = tool.BYTE_MUTANTS[0]
        self.assertNotEqual(self.image.code(va, 1)[0], old ^ 0xff)


if __name__ == "__main__":
    unittest.main()
