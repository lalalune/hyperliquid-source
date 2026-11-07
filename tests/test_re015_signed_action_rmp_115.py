import hashlib
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import re015_signed_action_rmp_115 as tool  # noqa: E402

FOLDER = ROOT / "research" / "work-items" / "RE-015-signed-action-rmp-encoders-115"


class Layer:
    """One reconstruction layer of the merged tool: `<prefix>_NAME` first, shared names second."""

    def __init__(self, prefix):
        self.prefix = prefix

    def __getattr__(self, name):
        try:
            return getattr(tool, f"{self.prefix}_{name}")
        except AttributeError:
            return getattr(tool, name)


SA = Layer("sa")
FH = Layer("fh")
NT = Layer("nt")


class SignedActionMsgpackTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = SA.BINARY.read_bytes()
        cls.image = SA.Image(cls.data)
        cls.ext = SA.extents(cls.image)
        cls.cases = [c for va in sorted(SA.BODIES)
                     for c in (SA.make_case(SA.Stream(f"re015-signed-action-{va:x}"), va, k) for k in range(24))]

    def test_digest_is_node_115(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), SA.SHA256)

    def test_corrupted_binary_is_rejected(self):
        bad = bytearray(self.data)
        bad[0x1000] ^= 0xff
        with self.assertRaises(SA.ToolError):
            SA.Image(bytes(bad))

    def test_bodies_are_fde_starts_and_call_the_chain_serializer(self):
        rows = SA.static_rows(self.image, self.ext)
        self.assertEqual(len(rows), 17)
        self.assertNotIn(0x2406121, self.ext)
        for va, size, n, targets in rows:
            self.assertIn(SA.CHAIN, targets)
            self.assertGreater(n, 200)

    def test_header_immediates_follow_field_counts(self):
        sites = SA.count_imm_sites(self.image, self.ext)
        for va, at in sites.items():
            self.assertEqual(self.image.code(at, 1)[0], 0x80 | (len(SA.field_list(va, {})) + 1))

    def test_encoding_boundaries(self):
        self.assertEqual(SA.mp_uint(0x7f), b"\x7f")
        self.assertEqual(SA.mp_uint(0x80), b"\xcc\x80")
        self.assertEqual(SA.mp_uint(0x10000), b"\xce\x00\x01\x00\x00")
        self.assertEqual(SA.mp_uint(SA.M64)[:1], b"\xcf")
        self.assertEqual(SA.mp_str(b"x" * 31)[:1], b"\xbf")
        self.assertEqual(SA.mp_str(b"x" * 32)[:2], b"\xd9\x20")
        self.assertEqual(SA.mp_str(b"x" * 256)[:3], b"\xda\x01\x00")
        self.assertEqual(SA.hex_uint(0x10ff), b"0x10ff")

    def test_cases_match_the_machine_code(self):
        _, bad = SA.evaluate(self.image, self.ext, self.cases)
        self.assertEqual(bad, [])
        self.assertTrue(any(c["fault"] is not None for c in self.cases))
        self.assertTrue(any(not c["map"] for c in self.cases))

    def test_wrong_reconstructions_are_detected(self):
        results, _ = SA.evaluate(self.image, self.ext, self.cases)
        for mut in ({"map-flip": True}, {"count-off": True}, {"chain-order": True},
                    {"fault-ws-as-out": True}, {"swap": 0x2413110}, {"none-as-empty": True}):
            hits = [c for c, got, _ in results if SA.compare(c, SA.model(c, mut), got)]
            self.assertTrue(hits, mut)

    def test_corrupted_code_byte_is_detected(self):
        sites = SA.count_imm_sites(self.image, self.ext)
        at = sites[0x2406120]
        cases = [c for c in self.cases if c["body"] == 0x2406120]
        _, bad = SA.evaluate(self.image, self.ext, cases, override={at: self.image.code(at, 1)[0] ^ 1})
        self.assertTrue(bad)

    def test_out_of_range_inputs_are_refused(self):
        c = dict(self.cases[0])
        st = bytearray(c["st"])
        st[SA.BODIES[c["body"]][2]] = 4  # chain discriminant outside Local..Mainnet
        c["st"] = bytes(st)
        with self.assertRaises(IndexError):
            SA.model(c, {})
        with self.assertRaises(SA.ToolError):
            SA.Image(self.data).code(0x10, 4)

class FieldHelpers(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = FH.BINARY.read_bytes()
        cls.image = FH.Image(cls.data)
        cls.ext = FH.extents(cls.image)

    def test_digest_guard(self):
        bad = bytearray(self.data[:4096])
        with self.assertRaises(FH.ToolError):
            FH.Image(bytes(bad))
        flipped = bytearray(self.data)
        flipped[0x1000] ^= 1
        with self.assertRaises(FH.ToolError):
            FH.Image(bytes(flipped))

    def test_static_shape(self):
        rows = FH.static_rows(self.image, self.ext)
        self.assertEqual([r[0] for r in rows], sorted(FH.HELPERS))
        self.assertEqual(sum(r[2] for r in rows), 848)
        table = FH.table_rows(self.image, self.ext)
        self.assertEqual("".join(chr(s) for _, _, s in table), "eizup")
        self.assertEqual(len(FH.marker_sites(self.image, self.ext)), 24)

    def test_non_fde_and_outside_text(self):
        with self.assertRaises(FH.ToolError):
            FH.fde_rows(self.image, {0x24599a1})
        with self.assertRaises(FH.ToolError):
            self.image.code(0x10, 4)
        with self.assertRaises(FH.ToolError):
            self.image.read(0xffff_ffff_0000, 8)

    def test_out_of_range_discriminant_refused(self):
        c = FH.all_cases(5)[[c["helper"] for c in FH.all_cases(5)].index(0x24596c0)]
        c = dict(c, args=(c["args"][0], c["args"][1], 5), fault=None)
        with self.assertRaises(FH.ToolError):
            FH.model(c)

    def test_key_rules(self):
        cases = FH.all_cases(14)
        for c in cases:
            label, key, test, kind = FH.HELPERS[c["helper"]]
            data, _, _, _ = FH.model(dict(c, fault=None))
            if test == "eq1":
                self.assertEqual(data == b"\xa4data", c["flag"] == 1)
            elif test == "nz" and c["flag"] != 0:
                self.assertTrue(data.startswith(bytes([0xa0 | len(key)]) + key))

    def test_byte_corruption_detected(self):
        sites = FH.marker_sites(self.image, self.ext)
        va, at, _ = sites[0]
        cases = [c for c in FH.all_cases(40) if c["helper"] == va]
        _, clean = FH.evaluate(self.image, self.ext, cases)
        self.assertEqual(clean, [])
        _, bad = FH.evaluate(self.image, self.ext, cases, override={at: self.image.code(at, 1)[0] ^ 1})
        self.assertTrue(bad)

    def test_model_mutants_detected(self):
        cases = FH.all_cases(60)
        self.assertEqual(sum(1 for c in cases if FH.FAMILY[c["helper"]] == "b"), 180)
        results, bad = FH.evaluate(self.image, self.ext, cases)
        self.assertEqual(bad, [])
        for name in FH.MODEL_MUTANTS:
            hit = any(FH.compare(c, FH.model(c, frozenset({name})), got) for c, got, _ in results)
            self.assertTrue(hit, name)

class NewtypeTuples(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = NT.BINARY.read_bytes()
        cls.image = NT.Image(cls.data)
        cls.ext = NT.extents(cls.image)
        cls.static = NT.static_rows(cls.image, cls.ext)
        cls.msgs = {r["va"]: r["msg"] for r in cls.static}

    def test_digest_guard(self):
        with self.assertRaises(NT.ToolError):
            NT.Image(bytes(self.data[:4096]))
        flipped = bytearray(self.data)
        flipped[0x1000] ^= 1
        with self.assertRaises(NT.ToolError):
            NT.Image(bytes(flipped))

    def test_static_shape(self):
        self.assertEqual([r["va"] for r in self.static], sorted(NT.BODIES))
        texts = {r["text"] for r in self.static}
        self.assertEqual(texts, {m.decode() for m in NT.EXT_MESSAGES})
        for r in self.static:
            _, kind, header = NT.BODIES[r["va"]]
            self.assertEqual(r["text"] == "expected tuple", header is None, hex(r["va"]))
            self.assertEqual(r["hex_got"], kind == "h160")
        self.assertEqual(len(NT.byte_sites(self.image, self.ext)), 57)

    def test_outside_text_and_foreign_bodies(self):
        with self.assertRaises(NT.ToolError):
            self.image.code(0x10, 4)
        with self.assertRaises(NT.ToolError):
            self.image.read(0xffff_ffff_0000, 8)
        # 0x22781c0 (bytes newtype, hex or bin) calls the hex encoder 0x2a315b0: outside every declared layout
        saved = dict(NT.BODIES)
        try:
            NT.BODIES[0x22781c0] = ("a", "str", None)
            ext = dict(self.ext)
            with self.assertRaises(NT.ToolError):
                NT.static_rows(self.image, ext)
        finally:
            NT.BODIES.clear()
            NT.BODIES.update(saved)

    def test_ext_gate_rule(self):
        for c in NT.all_cases(40):
            data, res, calls = NT.model(c, self.msgs[c["body"]])
            if c["name"] == NT.EXT_NAME:
                self.assertEqual((data, calls, res[0]), (b"", [], NT.EXT_TAG))
            else:
                self.assertTrue(res is None or res[0] != NT.EXT_TAG)

    def test_byte_corruption_detected(self):
        va, label, at = NT.byte_sites(self.image, self.ext)[0]
        cases = [c for c in NT.all_cases(40) if c["body"] == va]
        _, clean = NT.evaluate(self.image, self.ext, self.msgs, cases)
        self.assertEqual(clean, [])
        _, bad = NT.evaluate(self.image, self.ext, self.msgs, cases, override={at: self.image.code(at, 1)[0] ^ 1})
        self.assertTrue(bad, label)

    def test_wrong_message_detected(self):
        cases = [c for c in NT.all_cases(16) if c["name"] == NT.EXT_NAME]
        msgs = {va: (at + 1, n) for va, (at, n) in self.msgs.items()}
        results, bad = NT.evaluate(self.image, self.ext, msgs, cases)
        self.assertEqual(len(bad), len(cases))

    def test_model_mutants_detected(self):
        cases = NT.all_cases(60)
        results, bad = NT.evaluate(self.image, self.ext, self.msgs, cases)
        self.assertEqual(bad, [])
        for name in NT.MODEL_MUTANTS:
            hit = any(NT.compare(c, NT.model(c, self.msgs[c["body"]], frozenset({name})), got) for c, got, _ in results)
            self.assertTrue(hit, name)


class MergedPacketTest(unittest.TestCase):
    def test_shared_rules(self):
        self.assertEqual(tool.mp_str(b"x" * 31, frozenset({"str-fix32"}))[:1], b"\xbf")
        self.assertEqual(tool.mp_str(b"x" * 32, frozenset({"str-fix32"}))[:1], b"\xa0")
        self.assertEqual(tool.mp_uint(0x80, frozenset({"uint-fixint"})), b"\x80")
        self.assertEqual(tool.mp_uint(0x100, frozenset({"uint-u16"}))[:1], b"\xce")
        self.assertIs(SA.Machine, tool.Machine)
        self.assertIs(FH.Machine, NT.Machine)

    def test_layers_do_not_overlap(self):
        sa, fh, nt = set(tool.sa_BODIES), set(tool.fh_HELPERS) | set(tool.fh_COPIES), set(tool.nt_BODIES)
        self.assertFalse(sa & fh or sa & nt or fh & nt)
        # the flow layer runs real exactly the helpers both other layers name: stubbed by one, modelled by the other
        self.assertEqual(tool.FL_HELPERS, (set(tool.sa_STUBS) & set(tool.fh_HELPERS)) - {0x245b4b0})


class FlowTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = tool.Image(tool.BINARY.read_bytes())
        cls.ext = tool.sa_extents(cls.image)
        cls.cases = tool.fl_all_cases(30)

    def test_bodies_call_the_helpers(self):
        rows = tool.fl_static(self.image, self.ext)
        self.assertEqual([r[0] for r in rows], [0x2407270, 0x240dec0, 0x240f270])
        self.assertEqual(sorted(t for r in rows for t in r[1]), sorted(tool.FL_HELPERS))
        self.assertEqual(rows[2][2], [0x245b4b0])

    def test_cases_match_with_helpers_real(self):
        results, bad = tool.fl_evaluate(self.image, self.ext, self.cases)
        self.assertEqual(bad, [])
        self.assertTrue(all(not any(s[0] in tool.FL_HELPERS for s in got["stubs"]) for _, got, _ in results))
        self.assertTrue(any(c["fault"] is not None for c in self.cases))

    def test_wrong_compositions_are_detected(self):
        results, _ = tool.fl_evaluate(self.image, self.ext, self.cases)
        for name in ("flow-stub", "key-always", "enc-nonzero", "abs-order"):
            hit = any(tool.sa_compare(c, tool.sa_model(c, {name: True}), got) for c, got, _ in results)
            self.assertTrue(hit, name)

    def test_corrupted_helper_byte_is_detected(self):
        va, at, _ = next(s for s in tool.fh_marker_sites(self.image, self.ext) if s[0] == 0x24596c0)
        cases = [c for c in self.cases if c["body"] == 0x240dec0]
        _, bad = tool.fl_evaluate(self.image, self.ext, cases, override={at: self.image.code(at, 1)[0] ^ 1})
        self.assertTrue(bad)

    def test_out_of_range_abstraction_refused(self):
        c = next(c for c in self.cases if c["body"] == 0x240dec0)
        st = bytearray(c["st"])
        st[0x3c] = 5
        with self.assertRaises(tool.ToolError):
            tool.sa_model(dict(c, st=bytes(st)), {})

    def test_regenerates_folder(self):
        with tempfile.TemporaryDirectory() as tmp:
            summary = tool.generate(tmp)
            self.assertEqual(summary["mismatches"], 0)
            self.assertEqual(summary["controls"], summary["controls_detected"])
            self.assertGreaterEqual(summary["cases"], 30000)
            names = sorted(p.name for p in pathlib.Path(tmp).iterdir())
            self.assertEqual(names, sorted(p.name for p in FOLDER.iterdir()
                                           if p.name not in ("README.md", "MANIFEST.sha256")))
            for name in names:
                self.assertEqual((pathlib.Path(tmp) / name).read_bytes(), (FOLDER / name).read_bytes(), name)
        for line in (FOLDER / "MANIFEST.sha256").read_text().splitlines():
            digest, name = line.split("  ", 1)
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest, name)


if __name__ == "__main__":
    unittest.main()
