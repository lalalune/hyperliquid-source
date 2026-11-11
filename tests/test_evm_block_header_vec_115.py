"""Tests for tools/evm_block_header_vec_115.py (node #115 inline-Vec EVM block header serializer + field writers).

The binary must be present; nothing here is skipped. The tool never executes the binary.
"""
import hashlib
import pathlib
import shutil
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import evm_block_header_vec_115 as t  # noqa: E402

PACKET = ROOT / "research" / "work-items" / "evm-block-header-vec-serializer-115"
GENERATED = ("bodies.tsv", "cases-sample.tsv", "controls.tsv", "fields.tsv", "stubs.tsv", "summary.json",
             "unreached.tsv")


def small_cases():
    return t.all_cases(per_body=40, head_cases=240)


class Shared:
    image = None
    ext = None
    cases = None

    @classmethod
    def load(cls):
        if cls.image is None:
            data = t.BINARY.read_bytes()
            assert hashlib.sha256(data).hexdigest() == t.SHA256
            cls.image = t.Image(data)
            cls.ext = t.extents(cls.image)
            cls.cases = small_cases()
        return cls


def run_one(c):
    s = Shared.load()
    m = t.machine(s.image)
    return t.run_case(m, c)


def head_case(flag, words=(0, 0, 0, 0), tags=(0, 0, 0, 0), cap_slack=200):
    """A fault-free block header case with chosen flag and option tags (word 0, +0x10, +0x20, +0x30 and bytes
    +0x27c, +0x29d, +0x2be, +0x2df)."""
    st = bytearray(range(256)) * 3
    for off, w in zip((0x0, 0x10, 0x20, 0x30), words):
        t.put(st, off, 8, w)
    for off, b in zip((0x27c, 0x29d, 0x2be, 0x2df), tags):
        st[off] = b
    ser = bytearray(0x20)
    ser[t.VFLAG_AT] = flag
    c = {"body": t.HEAD, "k": 1, "st": st, "ser": ser, "flag": flag, "prefix": b"", "cap": cap_slack, "extra": 0,
         "fault": -1, "plan": [], "okplan": []}
    s = t.Stream("test-head")
    for _ in range(200):
        calls = t.model(c)[0]
        if len(calls) <= len(c["plan"]):
            break
        for rec in calls[len(c["plan"]):]:
            ok, bad = t.plan_words(s, t.ROLE_KIND[rec[0]])
            c["okplan"].append(ok)
            c["plan"].append(bad)
    return c


class GeneratedFiles(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = pathlib.Path(tempfile.mkdtemp(prefix="evm-block-header-vec-"))
        cls.summary = t.generate(cls.tmp / "out")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_regenerated_files_equal_committed(self):
        for name in GENERATED:
            with self.subTest(name=name):
                self.assertEqual((self.tmp / "out" / name).read_bytes(), (PACKET / name).read_bytes())

    def test_manifest_lists_every_file(self):
        rows = {}
        for line in (PACKET / "MANIFEST.sha256").read_text().splitlines():
            digest, name = line.split("  ", 1)
            rows[name] = digest
        files = sorted(p.name for p in PACKET.iterdir() if p.name != "MANIFEST.sha256")
        self.assertEqual(sorted(rows), files)
        for name, digest in rows.items():
            self.assertEqual(hashlib.sha256((PACKET / name).read_bytes()).hexdigest(), digest, name)

    def test_summary_scale(self):
        s = self.summary
        self.assertEqual(s["binary_sha256"], t.SHA256)
        self.assertEqual(s["mismatches"], 0)
        self.assertGreaterEqual(s["cases"], 10000)
        self.assertEqual(s["cases"], 28000)
        self.assertEqual(s["head_cases"], 8000)
        self.assertGreaterEqual(s["controls"], 30)
        self.assertEqual(s["controls"], s["controls_detected"])
        self.assertEqual(s["body_instructions"], s["body_instructions_reached"])
        self.assertEqual(s["bodies"], 21)

    def test_every_body_has_ok_and_error_cases(self):
        for body, d in self.summary["per_body"].items():
            with self.subTest(body=body):
                self.assertGreater(d["ok"], 0)
                self.assertGreater(d["error"], 0)
                self.assertGreater(d["flag_one"], 0)
                self.assertGreater(d["flag_zero"], 0)
                self.assertGreater(d["flag_other"], 0)


class StaticChecks(unittest.TestCase):
    def setUp(self):
        Shared.load()

    def test_head_row(self):
        r = t.head_row(Shared.image, Shared.ext)
        self.assertEqual((r["va"], r["size"], r["insns"]), (0x22da880, 1661, 375))
        self.assertEqual(r["names"], 13)  # 3 inline markers + 10 lea/len name texts

    def test_writer_rows(self):
        tests = {}
        for va in sorted(t.WRITERS):
            r = t.writer_row(Shared.image, Shared.ext, va)
            tests.setdefault(r["test"], []).append(va)
        self.assertEqual(len(tests["==1"]), 11)
        self.assertEqual(len(tests["!=0"]), 9)

    def test_wrong_flag_test_rejected(self):
        va = 0x2339730
        saved = t.WRITERS[va]
        try:
            t.WRITERS[va] = (saved[0], saved[1], "one") + saved[3:]
            with self.assertRaises(t.ToolError):
                t.writer_row(Shared.image, Shared.ext, va)
        finally:
            t.WRITERS[va] = saved

    def test_wrong_inline_name_length_rejected(self):
        va = 0x23399c0
        saved = t.WRITERS[va]
        try:
            t.WRITERS[va] = ("nonces",) + saved[1:]
            with self.assertRaises(t.ToolError):
                t.writer_row(Shared.image, Shared.ext, va)
        finally:
            t.WRITERS[va] = saved

    def test_wrong_head_field_order_rejected(self):
        saved = t.HEAD_FIELDS
        try:
            rows = list(saved)
            rows[8], rows[9] = rows[9], rows[8]
            t.HEAD_FIELDS = tuple(rows)
            with self.assertRaises(t.ToolError):
                t.head_row(Shared.image, Shared.ext)
        finally:
            t.HEAD_FIELDS = saved

    def test_body_without_fde_rejected(self):
        saved = dict(t.WRITERS)
        try:
            t.WRITERS[0x2339731] = saved[0x2339730]
            t.BODIES = (t.HEAD,) + tuple(sorted(t.WRITERS))
            with self.assertRaises(t.ToolError):
                t.extents(Shared.image)
        finally:
            t.WRITERS.clear()
            t.WRITERS.update(saved)
            t.BODIES = (t.HEAD,) + tuple(sorted(t.WRITERS))

    def test_digest_mismatch_rejected(self):
        tmp = pathlib.Path(tempfile.mkdtemp(prefix="evm-block-header-bin-"))
        saved = t.BINARY
        try:
            data = bytearray(saved.read_bytes()[:4096])
            data[100] ^= 1
            bad = tmp / "hl-node"
            bad.write_bytes(bytes(data))
            t.BINARY = bad
            with self.assertRaises(t.ToolError):
                t.generate(tmp / "out", per_body=1, head_cases=1)
            self.assertFalse((tmp / "out").exists())
        finally:
            t.BINARY = saved
            shutil.rmtree(tmp, ignore_errors=True)


class Behaviour(unittest.TestCase):
    def setUp(self):
        Shared.load()

    def test_small_set_matches(self):
        _, bad, _ = t.evaluate(Shared.image, Shared.cases)
        self.assertEqual(bad, [])

    def test_every_model_mutant_detected(self):
        for mut in t.MODEL_MUTANTS:
            with self.subTest(mut=mut):
                _, bad, _ = t.evaluate(Shared.image, Shared.cases, frozenset([mut]), stop_on_first=True)
                self.assertTrue(bad, mut)

    def test_byte_flips_detected(self):
        sites = t.byte_sites(Shared.image, Shared.ext)
        self.assertGreaterEqual(len(sites), 90)
        by = {}
        for c in t.all_cases():  # the full default set: some spare-capacity flips need exact boundary cases
            by.setdefault(c["body"], []).append(c)
        for s in sites[::7]:
            with self.subTest(site=hex(s["at"])):
                _, bad, _ = t.evaluate(Shared.image, by[s["body"]], override={s["at"]: s["old"] ^ s["xor"]},
                                       stop_on_first=True)
                self.assertTrue(bad)

    def test_flag_two_gives_map_with_partial_names(self):
        c = head_case(2)
        got = run_one(c)
        self.assertIsNone(t.compare(c, t.model(c), got))
        appended = got["buf"]
        self.assertEqual(got["calls"][0][0], "hdr_map")
        for absent in (b"parentHash", b"sha3Uncles", b"miner", b"logsBloom", b"number", b"gasLimit", b"nonce"):
            self.assertNotIn(absent, appended)
        names = [r[2] for r in got["calls"] if r[0] == "vec_str"]
        self.assertEqual(names, [b"receiptsRoot", b"difficulty", b"mixHash"])
        self.assertNotIn(b"stateRoot", names)

    def test_flag_one_writes_every_name(self):
        c = head_case(1, words=(1, 1, 1, 1), tags=(1, 1, 1, 1))
        got = run_one(c)
        self.assertIsNone(t.compare(c, t.model(c), got))
        text = got["buf"] + b"".join(r[2] for r in got["calls"] if r[0] == "vec_str")
        for name in (b"parentHash", b"sha3Uncles", b"miner", b"stateRoot", b"transactionsRoot", b"receiptsRoot",
                     b"logsBloom", b"difficulty", b"number", b"gasLimit", b"gasUsed", b"timestamp", b"mixHash",
                     b"nonce", b"baseFeePerGas", b"withdrawalsRoot", b"blobGasUsed", b"excessBlobGas",
                     b"parentBeaconBlockRoot", b"requestsHash", b"blockAccessListHash", b"slotNumber"):
            self.assertIn(name, text)
        self.assertEqual(got["calls"][0][3], 16 + 4 + 3)

    def test_flag_zero_array_without_names(self):
        c = head_case(0, words=(1, 0, 0, 0))
        got = run_one(c)
        self.assertIsNone(t.compare(c, t.model(c), got))
        self.assertEqual(got["calls"][0][:2], ("hdr_seq", "stk"))
        self.assertFalse([r for r in got["calls"] if r[0] == "vec_str"])
        self.assertNotIn(b"baseFeePerGas", got["buf"])

    def test_non_canonical_option_word_counted_and_nil(self):
        # word 0 = 2: present for the head (!= 0), counted as 16 + 0 (no -1), but the writer's dword test (== 1)
        # fails, so the field is serialized as nil 0xc0 right after its name
        c = head_case(2, words=(2, 0, 0, 0))
        got = run_one(c)
        self.assertIsNone(t.compare(c, t.model(c), got))
        self.assertEqual(got["calls"][0][3], 16)
        self.assertIn(b"\xadbaseFeePerGas\xc0", got["buf"])

    def test_header_count_uses_raw_tags_and_wraps(self):
        st = bytearray(0x300)
        t.put(st, 0x10, 8, 0xffffffff)
        st[0x27c] = 0xff
        self.assertEqual(t.header_count(st), (16 - 1 + 0xffffffff + 0xff) & 0xffffffff)
        t.put(st, 0x10, 8, 1 << 32)
        self.assertEqual(t.header_count(st), 16 - 1 + 0xff)

    def test_header_error_returns_slot_words(self):
        c = head_case(1)
        c["fault"] = 0
        got = run_one(c)
        self.assertIsNone(t.compare(c, t.model(c), got))
        self.assertEqual(got["result"][:8], t.ERR_TAG.to_bytes(8, "little"))
        self.assertEqual(got["result"][8:16], c["plan"][0][0].to_bytes(8, "little"))

    def test_reserve_rule(self):
        # spare capacity 0 before the first inline marker: reserve(1) then reserve(10) for "parentHash"
        c = head_case(1, cap_slack=0)
        c["cap"] = 0
        got = run_one(c)
        self.assertIsNone(t.compare(c, t.model(c), got))
        reserves = [r for r in got["calls"] if r[0] == "vec_reserve"]
        self.assertEqual(reserves[:2], [("vec_reserve", 0, 1), ("vec_reserve", 1, 10)])

    def test_access_list_passes_newtype_name(self):
        va = 0x233b630
        c = t.writer_case(t.Stream("test-access-list"), va, 1)
        got = run_one(c)
        self.assertIsNone(t.compare(c, t.model(c), got))
        self.assertEqual(got["calls"][-1][3], b"AccessList")

    def writer_case(self, va, flag, tag, name=None):
        """A fault-free direct writer case: flag byte, option tag at the field (dword/qword word or byte)."""
        st = bytearray(range(256)) * 3
        key, how, test, shape, role = t.WRITERS[va]
        if shape in ("opt_dword", "opt_qword"):
            t.put(st, t.WRITER_OFF, 8, tag)
        elif shape == "opt_byte":
            st[t.WRITER_OFF] = tag
        ser = bytearray(0x20)
        ser[t.VFLAG_AT] = flag
        c = {"body": va, "k": 1, "st": st, "ser": ser, "flag": flag, "prefix": b"\x01\x02", "cap": 64, "extra": 0,
             "fault": -1, "plan": [], "okplan": [], "off": t.WRITER_OFF}
        if how == "str":
            c["name"] = name or "mixHash"
        s = t.Stream("test-writer")
        calls = t.model(c)[0]
        for rec in calls:
            ok, bad = t.plan_words(s, t.ROLE_KIND[rec[0]])
            c["okplan"].append(ok)
            c["plan"].append(bad)
        return c

    def test_each_writer_flag_rule(self):
        # flag 2: `!= 0` writers write their key, `== 1` writers do not; flag 1: all do; flag 0: none do
        for va, (key, how, test, shape, role) in sorted(t.WRITERS.items()):
            for flag in (0, 1, 2):
                with self.subTest(writer=hex(va), flag=flag):
                    c = self.writer_case(va, flag, 1)
                    got = run_one(c)
                    self.assertIsNone(t.compare(c, t.model(c), got))
                    keyed = (got["buf"][2:3] == bytes([0xa0 | len(key)]) if how == "inline"
                             else any(r[0] == "vec_str" for r in got["calls"]))
                    self.assertEqual(keyed, flag == 1 or (flag == 2 and test == "nz"))

    def test_option_writers_nil_for_every_tag_but_one(self):
        for va, (key, how, test, shape, role) in sorted(t.WRITERS.items()):
            if not shape.startswith("opt"):
                continue
            for tag in (0, 1, 2, 0x100000001):
                if shape == "opt_byte" and tag > 0xff:
                    continue
                with self.subTest(writer=hex(va), tag=tag):
                    c = self.writer_case(va, 0, tag)
                    got = run_one(c)
                    self.assertIsNone(t.compare(c, t.model(c), got))
                    present = tag != 0 if shape == "opt_qword" else (tag & 0xffffffff) == 1
                    self.assertEqual(got["buf"][2:] == b"\xc0", not present)

    def test_out_of_range_offset_is_not_silently_accepted(self):
        # a writer pointed outside the struct region reads unmapped memory: the evaluator must raise
        va = 0x2339730
        c = t.writer_case(t.Stream("test-range"), va, 2)
        c["off"] = t.ST_SIZE + 0x1000
        with self.assertRaises(t.ToolError):
            run_one(c)


if __name__ == "__main__":
    unittest.main()
