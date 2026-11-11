import hashlib
import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import re11_context_memory_log115 as t  # noqa: E402

FOLDER = ROOT / "research" / "work-items" / "RE-011-context-memory-log-115"


class PacketTest(unittest.TestCase):
    """One in-process regeneration: every case of every part, every negative control, every evidence byte."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.out = pathlib.Path(cls.tmp.name)
        cls.summary = t.generate(cls.out)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_all_parts_match_and_controls_detected(self):
        s = self.summary
        self.assertEqual(s["mismatches"], 0)
        self.assertEqual(s["negative_controls"]["detected"], s["negative_controls"]["total"])
        self.assertGreaterEqual(s["cases"], 10000)
        self.assertGreaterEqual(s["negative_controls"]["total"], 30)
        self.assertEqual(sorted(s["parts"]), ["context-reads", "log-emit", "memory-range"])
        for slug, p in s["parts"].items():
            with self.subTest(part=slug):
                self.assertEqual(p["mismatches"], 0)
                self.assertEqual(p["negative_controls"]["detected"], p["negative_controls"]["total"])

    def test_evidence_files_reproduce(self):
        made = sorted(p.name for p in self.out.iterdir())
        kept = sorted(p.name for p in FOLDER.iterdir() if p.name not in ("README.md", "MANIFEST.sha256"))
        self.assertEqual(made, kept)
        for name in made:
            with self.subTest(file=name):
                self.assertEqual((self.out / name).read_bytes(), (FOLDER / name).read_bytes())

    def test_manifest(self):
        rows = (FOLDER / "MANIFEST.sha256").read_text().splitlines()
        names = sorted(p.name for p in FOLDER.iterdir() if p.name != "MANIFEST.sha256")
        self.assertEqual(sorted(r.split("  ", 1)[1] for r in rows), names)
        for r in rows:
            digest, name = r.split("  ", 1)
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest, name)

    def test_sampled_listing_rows_come_from_the_full_listing(self):
        pins = self.summary["full_listings"]
        self.assertTrue(pins)
        for name, pin in pins.items():
            rows = (self.out / name).read_text().splitlines()
            self.assertEqual(len(rows) - 1, (pin["rows"] + t.SAMPLE_EVERY - 1) // t.SAMPLE_EVERY, name)
        summary = json.loads((FOLDER / "summary.json").read_text())
        self.assertEqual(summary["full_listings"], pins)

    def test_sampling_rejects_a_changed_row(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = pathlib.Path(tmp) / "x.tsv"
            p.write_text("h\na\nb\n")
            pin = t.sample_listing(p)
            p.write_text("h\na\nc\n")
            self.assertNotEqual(t.sample_listing(p)["sha256"], pin["sha256"])


class ContextReadsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = t.load_image()
        cls.cases = t.rd_all_cases()

    def test_rejects_wrong_binary(self):
        data = bytearray(self.image.data)
        data[self.image.text["offset"] + 3] ^= 0x40
        with self.assertRaises(t.ToolError):
            t.Image(bytes(data))

    def test_rejects_code_past_text(self):
        with self.assertRaises(t.ToolError):
            self.image.code(self.image.text["address"] + self.image.text["size"], 1)

    def test_static_evidence(self):
        consts, decoded = t.rd_static_evidence(self.image)
        funcs = consts["functions"]
        self.assertEqual(len(funcs), 19)
        self.assertNotIn("0x2b95670", funcs)
        self.assertEqual(funcs["0x2997a50"]["instructions"], 79)
        self.assertEqual(funcs["0x2997a50"]["calls"], 1)
        self.assertEqual(funcs["0x2995df0"]["instructions"], 9)
        self.assertEqual(funcs["0x2999780"]["instructions"], 41)
        self.assertEqual(sum(f["instructions"] for f in funcs.values()), 487)
        self.assertEqual(funcs["0x2b95920"]["spec_gate"], "0xe")
        self.assertEqual(len(consts["opcode_table_slots"]), 40)
        self.assertEqual(self.image.import_name(t.RD_MEMCPY_SLOT), "memcpy")

    def test_changed_checked_byte_fails(self):
        va = t.RD_CHECKED[0][0]
        data = bytearray(self.image.data)
        off = self.image.text["offset"] + va - self.image.text["address"]
        data[off] ^= 1
        bad = t.Image(bytes(data), check=False)
        with self.assertRaises(t.ToolError):
            t.rd_static_evidence(bad)

    def test_gas_price_reconstruction(self):
        x = bytearray(t.RD_CTX_SIZE)
        t.put(x, 0x130, 16, 100)
        t.put(x, 0x98, 8, 30)
        t.put(x, 0xf0, 16, 50)
        self.assertEqual(t.rd_gas_price(x), 100)
        x[0x1f1], x[0xe0] = 2, 1
        self.assertEqual(t.rd_gas_price(x), 80)
        t.put(x, 0x130, 16, t.M128)
        t.put(x, 0x98, 8, t.M64)
        t.put(x, 0xf0, 16, t.M128)
        self.assertEqual(t.rd_gas_price(x), t.M128)


class MemoryRangeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = t.load_image()
        cls.cases = t.mr_all_cases()
        per = {}
        cls.subset = []
        for c in cls.cases:
            per[c["op"]] = per.get(c["op"], 0) + 1
            if per[c["op"]] <= 140:
                cls.subset.append(c)

    def test_static_pins_and_tables(self):
        fdes, insns = t.mr_static_evidence(self.image)
        for op, va in t.MR_BODIES.items():
            self.assertIn(va, fdes)
            self.assertEqual(insns[op][0][0], va)
        self.assertEqual(t.mr_empty_hash_imm(self.image), int.from_bytes(t.MR_EMPTY_HASH, "big"))

    def test_keccak_reference(self):
        self.assertEqual(t.mr_keccak256(b"").hex(),
                         "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
        self.assertEqual(t.mr_keccak256(b"abc").hex(),
                         "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45")

    def test_corrupted_pin_fails(self):
        data = bytearray(self.image.data)
        off = 0x29971f1 - self.image.text["address"] + self.image.text["offset"]
        data[off] ^= 1
        bad = t.Image(bytes(data), check=False)
        with self.assertRaises(t.ToolError):
            t.mr_static_evidence(bad)

    def test_wrong_digest_rejected(self):
        data = bytearray(self.image.data)
        data[0x2000] ^= 0xff
        with self.assertRaises(t.ToolError):
            t.Image(bytes(data))

    def test_out_of_range_code_rejected(self):
        with self.assertRaises(t.ToolError):
            self.image.code(self.image.text["address"] + self.image.text["size"] - 2, 8)


class LogEmitTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = t.load_image()
        cls.cases = t.lg_all_cases(cls.image)

    def test_rejects_wrong_binary(self):
        data = bytearray(self.image.data)
        data[self.image.text["offset"] + 3] ^= 0x40
        with self.assertRaises(t.ToolError):
            t.Image(bytes(data))

    def test_rejects_code_past_text(self):
        with self.assertRaises(t.ToolError):
            self.image.code(self.image.text["address"] + self.image.text["size"], 1)

    def test_static_evidence(self):
        consts, _ = t.lg_static_evidence(self.image)
        funcs = consts["functions"]
        self.assertEqual(len(funcs), 5)
        self.assertEqual(sum(f["instructions"] for f in funcs.values()), 1209)
        self.assertEqual(funcs["0x29926f0"]["instructions"], 170)
        self.assertNotIn("vtable-drop", funcs["0x29926f0"]["call_roles"])
        self.assertNotIn("topic-cost-panic", funcs["0x2993350"]["call_roles"])
        for f in ("0x2992f00", "0x2993720", "0x29929d0"):
            self.assertEqual(funcs[f]["call_roles"]["topic-cost-panic"], 1)
            self.assertEqual(funcs[f]["call_roles"]["alloc"], 2)
        self.assertEqual(len(consts["opcode_table_slots"]), 10)
        self.assertEqual(consts["got_slots"]["0x64df508"]["target"], "import memcpy")
        self.assertEqual(consts["log_record"]["size"], 0x50)

    def test_changed_checked_byte_fails(self):
        va = t.LG_CHECKED[4][0]
        data = bytearray(self.image.data)
        data[self.image.text["offset"] + va - self.image.text["address"]] ^= 1
        with self.assertRaises(t.ToolError):
            t.lg_static_evidence(t.Image(bytes(data), check=False))

    def test_wrong_table_slot_fails(self):
        bad = t.Image(self.image.data)
        bad.relative = dict(bad.relative)
        bad.relative[t.LG_OP_TABLES[1] + 8 * 0xa3] = 0x29929d0
        with self.assertRaises(t.ToolError):
            t.lg_static_evidence(bad)

    def test_gas_cost(self):
        self.assertEqual(t.lg_gas_cost(0, 3, 8, 375), 24)
        self.assertEqual(t.lg_gas_cost(2, 3, 8, 375), 774)
        self.assertEqual(t.lg_gas_cost(0, 2, t.M64, 0), t.M64)
        self.assertEqual(t.lg_gas_cost(1, 2, t.M64, 5), t.M64)
        self.assertIsNone(t.lg_gas_cost(4, 0, 0, 1 << 62))
        self.assertEqual(t.lg_gas_cost(4, 0, 0, (1 << 62) - 1), 4 * ((1 << 62) - 1))
        self.assertIsNone(t.lg_gas_cost(3, 0, 0, t.M64 // 3 + 1))
        self.assertEqual(t.lg_gas_cost(1, 0, 0, t.M64), t.M64)

    def test_topics_big_endian(self):
        self.assertEqual(t.lg_topic_bytes(1), bytes(31) + b"\x01")
        self.assertEqual(t.lg_topic_bytes(1 << 255)[0], 0x80)


if __name__ == "__main__":
    unittest.main()
