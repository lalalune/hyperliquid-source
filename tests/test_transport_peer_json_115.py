import hashlib
import json
import pathlib
import struct
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import transport_peer_json_115 as T  # noqa: E402

FOLDER = ROOT / "research" / "work-items" / "transport-peer-json-115"


def bits(value):
    return struct.unpack("<Q", struct.pack("<d", value))[0]


class Fixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = T.load_image()
        relative = cls.image.relative()
        at = cls.image.offset(relative[T.ESCAPE_SLOT])
        cls.table = bytes(cls.image.blob[at:at + 256])
        hex_at = cls.image.offset(relative[T.HEX_SLOT])
        cls.hex = bytes(cls.image.blob[hex_at:hex_at + 16])
        cls.model = T.Model(cls.table, cls.hex)
        cls.rig = T.Rig(cls.image)

    def machine(self, kind, data, cap=0, content=b""):
        return self.rig.run(T.ENTRY[kind], kind, data, cap, content)

    def reference(self, kind, data, cap=0, content=b""):
        return T.model_run(self.model, kind, data, cap, content)


class BinaryChecks(Fixture):
    def test_digest_is_the_node_115_binary(self):
        self.assertEqual(hashlib.sha256(self.image.blob).hexdigest(), T.SHA256)

    def test_wrong_digest_is_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "blob"
            path.write_bytes(b"not the node binary")
            with self.assertRaises(T.EvidenceError):
                T.load_image(path)

    def test_escape_table_from_bytes(self):
        nonzero = {i: c for i, c in enumerate(self.table) if c}
        self.assertEqual(nonzero[0x22], 0x22)
        self.assertEqual(nonzero[0x5C], 0x5C)
        self.assertEqual(nonzero[0x0A], ord("n"))
        self.assertEqual(nonzero[0x08], ord("b"))
        self.assertEqual(nonzero[0x00], ord("u"))
        self.assertEqual(len(nonzero), 34)
        self.assertEqual(self.hex, b"0123456789abcdef")

    def test_function_extents(self):
        want = {T.IPV4_FN: 641, T.ENDPOINT_FN: 811, T.STAT_FN: 326, T.PAIR_VEC_FN: 1295, T.QUAD_VEC_FN: 2006,
                T.NAMED_STAT_FN: 2988, T.GROW_FN: 142}
        for entry, size in want.items():
            start, end = self.image.exact_fde(entry)
            self.assertEqual((start, end - start), (entry, size))


class ModelChecks(Fixture):
    def test_reserve_rule(self):
        sink = T.Sink(0, b"")
        sink.push(1)
        self.assertEqual(sink.events, [(0, 8)])
        sink = T.Sink(10, b"x" * 10)
        sink.extend(b"y" * 30)
        self.assertEqual(sink.events, [(10, 40)])
        sink = T.Sink(10, b"x" * 10)
        sink.push(1)
        self.assertEqual(sink.events, [(10, 20)])

    def test_ryu_text(self):
        cases = {1.0: "1.0", 1.5: "1.5", -0.0: "-0.0", 1e16: "1e16", 1e15: "1000000000000000.0", 1e-4: "0.0001",
                 1e-5: "0.00001", 1e-6: "1e-6", 1.2345e-5: "0.000012345", 5e-324: "5e-324", 123456.789: "123456.789", 0.1: "0.1"}
        for value, text in cases.items():
            self.assertEqual(T.ryu_pretty(value), text)

    def test_known_outputs(self):
        self.assertEqual(self.reference("ipv4_string", {"ip": [10, 0, 255, 7]})[2], b'"10.0.255.7"')
        ep = {"ip": [1, 2, 3, 4], "port": 8000, "flag": 1, "pad": 0}
        self.assertEqual(self.reference("endpoint_tuple", ep)[2], b'["Out","1.2.3.4",8000]')
        self.assertEqual(self.reference("endpoint_tuple", dict(ep, flag=2))[2], b'["In","1.2.3.4",8000]')
        st = {"n": 7, "total": bits(1.5), "max": bits(float("inf"))}
        self.assertEqual(self.reference("stat_object", st)[2], b'{"n":7,"total":1.5,"max":null}')

    def test_escape_contents(self):
        sink = T.Sink(0, b"")
        self.model.escape_contents(sink, b'a"b\\c\n\x01\x7f')
        self.assertEqual(bytes(sink.buf), b'a\\"b\\\\c\\n\\u0001\x7f')


class MachineAgainstModel(Fixture):
    def test_every_kind_matches(self):
        seen = {}
        for kind, index, data, cap, content in T.cases():
            if seen.get(kind, 0) >= 30:
                continue
            seen[kind] = seen.get(kind, 0) + 1
            self.assertEqual(self.machine(kind, data, cap, content), self.reference(kind, data, cap, content),
                             "%s-%d" % (kind, index))
        self.assertEqual(len(seen), 8)

    def test_grow_trace_at_every_slack(self):
        ep = {"ip": [255, 255, 255, 255], "port": 65535, "flag": 1, "pad": 0}
        length = len(self.reference("endpoint_tuple", ep)[2])
        for slack in range(0, length + 2):
            got = self.machine("endpoint_tuple", ep, 3 + slack, b"abc")
            self.assertEqual(got, self.reference("endpoint_tuple", ep, 3 + slack, b"abc"), slack)

    def test_non_finite_floats_write_null(self):
        for pattern in (0x7FF0000000000000, 0xFFF0000000000000, 0x7FF8000000000000, 0x7FF0000000000001):
            st = {"n": 1, "total": pattern, "max": 0}
            got = self.machine("stat_object", st)
            self.assertIn(b'"total":null', got[2])
            self.assertEqual(got, self.reference("stat_object", st))

    def test_nested_tree_in_order(self):
        leaf = lambda *names: {"keys": [(n, {"n": i, "total": bits(float(i)), "max": 0}) for i, n in enumerate(names)],
                               "children": None}
        tree = {"keys": [(b"m", {"n": 9, "total": 0, "max": 0})], "children": [leaf(b"a", b"b"), leaf(b"x")]}
        got = self.machine("named_stat_tree", tree)
        self.assertEqual(got, self.reference("named_stat_tree", tree))
        self.assertLess(got[2].index(b'"b"'), got[2].index(b'"m"'))
        self.assertLess(got[2].index(b'"m"'), got[2].index(b'"x"'))


class NegativeControls(Fixture):
    def test_wrong_models_are_caught(self):
        for name, wrong in T.wrong_models(self.model):
            hit, first = T.model_detects(self.model, wrong)
            self.assertTrue(hit, name)

    def test_punctuation_mutant_is_caught(self):
        patched = T.Rig(self.image, {0x4781f3b: 0x5C})
        ep = {"ip": [1, 2, 3, 4], "port": 1, "flag": 0, "pad": 0}
        got = patched.run(T.ENDPOINT_FN, "endpoint_tuple", ep, 64, b"")
        self.assertNotEqual(got, self.reference("endpoint_tuple", ep, 64, b""))

    def test_jcc_inversion_is_caught(self):
        sites = [s for s in T.code_sites(self.image) if "ipv4_string jcc" in s[4]]
        self.assertTrue(sites)
        va, at, old, new, _ = sites[0]
        hit, _ = T.detect_patch(self.image, self.model, {va + at: new})
        self.assertTrue(hit)

    def test_out_of_range_controls(self):
        for name, ok in T.out_of_range_controls(self.image):
            self.assertTrue(ok, name)

    def test_mid_function_and_unmapped_addresses_rejected(self):
        with self.assertRaises(T.EvidenceError):
            self.image.exact_fde(T.IPV4_FN + 4)
        with self.assertRaises(T.EvidenceError):
            self.image.offset(0x20)

    def test_unknown_kind_is_rejected(self):
        with self.assertRaises(T.PacketError):
            self.rig.build("no_such_kind", {})


class ExhaustiveDomains(Fixture):
    def test_every_byte_value_in_a_key(self):
        for byte in range(256):
            for key in (bytes((byte,)), bytes((97, byte, 98))):
                data = {"fn": T.NEXT_KEY_FN, "state": 2, "key": key, "value": bits(2.5)}
                self.assertEqual(self.machine("entry_call", data), self.reference("entry_call", data), byte)

    def test_every_octet_in_every_position(self):
        for position in range(4):
            for octet in range(256):
                ip = [7, 77, 177, 17]
                ip[position] = octet
                data = {"ip": ip}
                self.assertEqual(self.machine("ipv4_string", data), self.reference("ipv4_string", data), (position, octet))

    def test_counter_decimal_boundaries(self):
        values = {0, 1, 2 ** 64 - 1}
        for digits in range(1, 20):
            values |= {10 ** digits - 1, 10 ** digits, 10 ** digits + 1}
        for value in sorted(v for v in values if v < 1 << 64):
            data = {"fn": T.FIRST_KEY_FN, "state": 1, "key": b"n", "value": value}
            got = self.machine("entry_call", data, 4, b"")
            self.assertEqual(got, self.reference("entry_call", data, 4, b""), value)
            self.assertIn(str(value).encode(), got[2])

    def test_second_entry_starts_with_a_comma(self):
        for fn, value in ((T.FIRST_KEY_FN, 5), (T.NEXT_KEY_FN, bits(1.0))):
            first = self.machine("entry_call", {"fn": fn, "state": 1, "key": b"k", "value": value})
            later = self.machine("entry_call", {"fn": fn, "state": 2, "key": b"k", "value": value})
            self.assertFalse(first[2].startswith(b","))
            self.assertTrue(later[2].startswith(b","))
            self.assertEqual(first[2][-2:], later[2][-2:])
            self.assertEqual(first[2][-1], 2)

    def test_empty_sequences(self):
        for kind in ("pair_vec", "quad_vec", "named_stat_iter"):
            got = self.machine(kind, [])
            self.assertEqual(got[2], b"[]")
            self.assertEqual(got, self.reference(kind, []))
        empty = {"keys": [], "children": None}
        self.assertEqual(self.machine("named_stat_tree", empty)[2], b"[]")

    def test_sweep_every_capacity_for_each_kind(self):
        rng = T.random.Random(11)
        for kind, _ in T.KIND_WEIGHT:
            data = T.rand_input(rng, kind)
            full = len(self.reference(kind, data, 1 << 20, b"")[2])
            for cap in range(full + 2):
                self.assertEqual(self.machine(kind, data, cap, b""), self.reference(kind, data, cap, b""), (kind, cap))

    def test_ryu_stub_round_trips(self):
        rng = T.random.Random(5)
        checked = 0
        for _ in range(3000):
            pattern = rng.getrandbits(64)
            if (pattern & 0x7FFFFFFFFFFFFFFF) > 0x7FEFFFFFFFFFFFFF:
                continue
            value = struct.unpack("<d", struct.pack("<Q", pattern))[0]
            self.assertEqual(float(T.ryu_pretty(value)), value)
            checked += 1
        self.assertGreater(checked, 2900)

    def test_cases_are_deterministic(self):
        first = [(k, i, repr(d), c, s) for k, i, d, c, s in T.cases(("stat_object",))][:200]
        second = [(k, i, repr(d), c, s) for k, i, d, c, s in T.cases(("stat_object",))][:200]
        self.assertEqual(first, second)
        self.assertGreater(len(first), 100)


class RecordedEvidence(unittest.TestCase):
    def test_measure_json_is_consistent(self):
        if not FOLDER.exists():
            self.fail("evidence folder missing")
        data = json.loads((FOLDER / "measure.json").read_text())
        self.assertEqual(data["model_mismatches"], 0)
        self.assertEqual(data["negative_detected"] + data["equivalent"], data["negative_controls"])
        self.assertGreaterEqual(data["cases"], 10000)

    def test_manifest_hashes(self):
        if not FOLDER.exists():
            self.fail("evidence folder missing")
        for line in (FOLDER / "MANIFEST.sha256").read_text().splitlines():
            digest, name = line.split("  ")
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest, name)


if __name__ == "__main__":
    unittest.main()
