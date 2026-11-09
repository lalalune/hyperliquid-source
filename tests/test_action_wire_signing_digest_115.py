import copy
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import action_wire_signing_digest_115 as T  # noqa: E402

USD_SEND_WRAPPER = 0x44338B0


class SigningDigestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = T.load_image()
        cls.rig = T.Rig(cls.image)
        cls.labels = T.label_table(cls.image)
        cls.triples = T.find_triples(cls.image)
        cls.row = next(r for r in cls.triples if r["wrapper"] == USD_SEND_WRAPPER)
        cls.spec = T.probe(cls.rig, cls.row)

    def test_keccak_vectors(self):
        self.assertEqual(T.keccak256(b"").hex(), "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
        self.assertEqual(T.keccak256(b"abc").hex(), "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45")
        self.assertEqual(T.keccak256(b"a" * 136).hex(), T.keccak256(b"a" * 136).hex())
        self.assertNotEqual(T.keccak256(b"a" * 135), T.keccak256(b"a" * 136))

    def test_wrong_digest_refused(self):
        with self.assertRaises(T.EvidenceError):
            T.load_image(T.BINARY, "0" * 64)

    def test_labels(self):
        self.assertEqual(self.labels, [b"Local", b"Sandbox", b"Testnet", b"Mainnet"])

    def test_triples(self):
        self.assertEqual(len(self.triples), 40)
        self.assertEqual(len({r["wrapper"] for r in self.triples}), 40)
        self.assertEqual(self.row["hash"], 0x43D2B20)
        self.assertEqual(self.row["builder"], 0x43D3130)

    def test_usdsend_layout(self):
        spec = self.spec
        self.assertEqual(spec["status"], "ok")
        self.assertEqual(spec["name"], "UsdSend")
        self.assertEqual(spec["cid_off"], 48)
        got = [(f, k, o) for f, _, o, _, k in spec["layout"]]
        self.assertEqual(got, [("hyperliquidChain", "chain", 88), ("destination", "string", 0),
                               ("amount", "string", 24), ("time", "plain", 80)])
        self.assertEqual(spec["enums"]["hyperliquidChain"], self.labels)

    def test_usdsend_reference_matches_bytes(self):
        rng = T.Lcg(11)
        for index in range(12):
            case = T.make_case(self.spec, rng, self.labels, index)
            ok, out, steps = T.case_matches(self.rig, self.spec, self.labels, case)
            self.assertTrue(ok)
            self.assertGreater(steps, 1000)

    def test_real_sponge_equals_model(self):
        case = T.make_case(self.spec, T.Lcg(5), self.labels, 1)
        fast = T.case_matches(self.rig, self.spec, self.labels, case)
        self.rig.set_mode(False)
        try:
            real = T.case_matches(self.rig, self.spec, self.labels, case)
        finally:
            self.rig.set_mode(True)
        self.assertTrue(fast[0] and real[0])
        self.assertEqual(fast[1], real[1])
        self.assertGreater(real[2], 3 * fast[2])

    def test_reference_mutants_detected(self):
        case = T.make_case(self.spec, T.Lcg(3), self.labels, 2)
        for mutant in ("domain-name", "domain-version", "chain-id-plus-one", "prefix-0x1900", "drop-last-field",
                       "swap-first-two", "uint-little-endian", "type-string-no-prefix", "struct-hash-only"):
            ok, _, _ = T.case_matches(self.rig, self.spec, self.labels, case, mutant)
            self.assertFalse(ok, mutant)

    def test_wrong_inputs_detected(self):
        case = T.make_case(self.spec, T.Lcg(4), self.labels, 3)
        record, strings, values, chain_id, chain_idx = case
        # a different chain id in the record changes the digest
        other = bytearray(record)
        other[self.spec["cid_off"]] ^= 1
        out, _, _ = self.rig.call(USD_SEND_WRAPPER, bytes(other), strings)
        expect = T.reference_digest(self.spec["encode"], self.spec["fields"], values, chain_id)
        self.assertNotEqual(out[1:33], expect)
        # a selector outside the label table is not signed
        bad = bytearray(record)
        bad[88] = 40
        try:
            out, _, _ = self.rig.call(USD_SEND_WRAPPER, bytes(bad), strings)
            rejected = out[0] != 0
        except (T.Halt, T.EvidenceError, IndexError):
            rejected = True
        self.assertTrue(rejected)

    def test_entry_outside_function_halts(self):
        case = T.make_case(self.spec, T.Lcg(6), self.labels, 0)
        for entry in (USD_SEND_WRAPPER + 0x10, 0x10):
            with self.assertRaises((T.Halt, T.EvidenceError, T.Panicked, IndexError)):
                self.rig.call(entry, case[0], case[1])
        self.rig.reset()

    def test_corrupted_code_byte_detected(self):
        image = copy.copy(self.image)
        blob = bytearray(self.image.blob)
        image.blob = blob
        rig = T.Rig(image)
        rig.real_extra = set(self.rig.real_extra)
        rig.set_mode(True)
        case = T.make_case(self.spec, T.Lcg(8), self.labels, 4)
        self.assertTrue(T.case_matches(rig, self.spec, self.labels, case)[0])
        base, text = self.image.text_bytes()
        body = text[0x43D2B20 - base:0x43D2B20 - base + 0x200]
        at = body.find(b"\x41\x0f\xb6\x47\x58")
        self.assertGreater(at, 0)
        blob[self.image.offset(0x43D2B20 + at + 4)] += 1
        rig.m.cache.clear()
        try:
            ok = T.case_matches(rig, self.spec, self.labels, case)[0]
        except (T.Halt, T.EvidenceError, T.Panicked, IndexError):
            ok = False
        self.assertFalse(ok)

    def test_case_generation_is_deterministic(self):
        first = T.make_case(self.spec, T.Lcg(9), self.labels, 5)
        second = T.make_case(self.spec, T.Lcg(9), self.labels, 5)
        self.assertEqual(first, second)
        self.assertNotEqual(first, T.make_case(self.spec, T.Lcg(10), self.labels, 5))

    def test_byte_edit_table(self):
        edits = T.byte_edits(self.image, self.spec)
        labels = [e[0] for e in edits]
        for want in ("domain-name-alloc-size", "domain-version-byte", "selector-read-offset", "time-read-offset",
                     "sponge-rate-immediate", "prefix-literal-byte0", "domain-name-literal-byte"):
            self.assertIn(want, labels)
        self.assertEqual(len(labels), len(set(labels)))
        self.assertTrue(all(mode in ("fast", "real") for *_, mode in edits))

    def test_wrong_layout_is_found(self):
        shifted = dict(self.spec, cid_off=self.spec["cid_off"] + 8)
        self.assertTrue(T.wrong_spec_found(self.rig, shifted, self.spec, self.labels))
        self.assertFalse(T.wrong_spec_found(self.rig, self.spec, self.spec, self.labels))

    def test_selector_labels_come_from_the_wrapper(self):
        self.assertEqual(T.enum_labels(self.rig, USD_SEND_WRAPPER, 88), self.labels)
        self.assertEqual(T.enum_labels(self.rig, USD_SEND_WRAPPER, 89), [])

    def test_parse_encode_type(self):
        self.assertEqual(T.parse_encode_type(b"HyperliquidTransaction:A(string x,uint64 y)"), ("A", [("x", "string"), ("y", "uint64")]))
        self.assertIsNone(T.parse_encode_type(b"Other:A(string x)"))
        self.assertIsNone(T.parse_encode_type(b"HyperliquidTransaction:A"))


class OtherFamiliesTests(unittest.TestCase):
    """Wrappers with selectors, bytes32 ids, ten fields and multi-sig addresses resolve and reproduce their digests."""

    @classmethod
    def setUpClass(cls):
        cls.image = T.load_image()
        cls.rig = T.Rig(cls.image)
        cls.labels = T.label_table(cls.image)
        cls.by_wrapper = {r["wrapper"]: r for r in T.find_triples(cls.image)}

    def check(self, wrapper, name, fields, kinds):
        spec = T.probe(self.rig, self.by_wrapper[wrapper])
        self.assertEqual(spec["status"], "ok")
        self.assertEqual(spec["name"], name)
        self.assertEqual(len(spec["layout"]), fields)
        self.assertEqual(sorted(set(k for *_, k in spec["layout"])), kinds)
        rng = T.Lcg(wrapper)
        for index in range(6):
            case = T.make_case(spec, rng, self.labels, index)
            self.assertTrue(T.case_matches(self.rig, spec, self.labels, case)[0])
        return spec

    def test_gov_vote_selector_and_bytes32(self):
        spec = self.check(0x4431640, "GovVote", 4, ["chain", "enum", "plain"])
        self.assertEqual(len(spec["enums"]["choice"]), 3)

    def test_send_asset_eight_and_ten_fields(self):
        self.check(0x44331C0, "SendAsset", 8, ["chain", "plain", "string"])
        self.check(0x4430F50, "SendAsset", 10, ["chain", "plain", "string"])

    def test_multi_sig_family_has_signer_addresses(self):
        spec = self.check(0x442F740, "CWithdraw", 5, ["chain", "plain"])
        self.assertEqual([f for f, *_ in spec["layout"]][:3], ["hyperliquidChain", "payloadMultiSigUser", "outerSigner"])

    def test_dyn_callback_actions_stay_unresolved(self):
        with self.assertRaises(T.Halt):
            self.rig.learn(0x4433F90)

    def test_libc_slots_are_named(self):
        names = set(T.glob_dat_names(self.image).values())
        self.assertIn("memcpy", names)
        self.assertIn("memmove", names)

    def test_synthetic_usdsend_vector(self):
        """A hand-built UsdSend record: Testnet, a fixed destination, amount 1.25, time 1700000000, chain id 1337."""
        spec = T.probe(self.rig, self.by_wrapper[0x44338B0])
        offsets = dict((f, o) for f, _, o, _, _ in spec["layout"])
        record = bytearray(0x200)
        record[spec["cid_off"]:spec["cid_off"] + 32] = (1337).to_bytes(32, "little")
        record[offsets["hyperliquidChain"]] = 2
        destination, amount = b"0x00000000000000000000000000000000000000a1", b"1.25"
        record[offsets["destination"]:offsets["destination"] + 24] = (42).to_bytes(8, "little") + T.STR_AREA.to_bytes(8, "little") + (42).to_bytes(8, "little")
        record[offsets["amount"]:offsets["amount"] + 24] = (4).to_bytes(8, "little") + (T.STR_AREA + 64).to_bytes(8, "little") + (4).to_bytes(8, "little")
        record[offsets["time"]:offsets["time"] + 8] = (1700000000).to_bytes(8, "little")
        out, _, _ = self.rig.call(0x44338B0, bytes(record), [(T.STR_AREA, destination), (T.STR_AREA + 64, amount)])
        encode = b"HyperliquidTransaction:UsdSend(string hyperliquidChain,string destination,string amount,uint64 time)"
        words = [T.keccak256(b"Testnet"), T.keccak256(destination), T.keccak256(amount), T.be32(1700000000)]
        expect = T.keccak256(b"\x19\x01" + T.domain_separator(1337) + T.struct_hash(encode, words))
        self.assertEqual(out[0], 0)
        self.assertEqual(out[1:33], expect)
        self.assertEqual(spec["encode"], encode)

    def test_resolved_actions_sample(self):
        names = set()
        for wrapper in sorted(self.by_wrapper)[::4]:
            try:
                spec = T.probe(self.rig, self.by_wrapper[wrapper])
            except T.Halt:
                continue
            if spec["status"] != "ok":
                continue
            names.add(spec["name"])
            rng = T.Lcg(wrapper + 1)
            for index in range(2):
                case = T.make_case(spec, rng, self.labels, index)
                self.assertTrue(T.case_matches(self.rig, spec, self.labels, case)[0], hex(wrapper))
        self.assertGreaterEqual(len(names), 6)

    def test_category_and_abstraction_labels(self):
        category = T.probe(self.rig, self.by_wrapper[0x442F3D0])
        self.assertEqual(category["enums"]["category"], [b"accelerated", b"constitutional", b"ecosystem", b"electoral"])
        vote = T.probe(self.rig, self.by_wrapper[0x4431640])
        self.assertEqual(vote["enums"]["choice"], [b"yes", b"no", b"abstain"])
        self.assertEqual(category["enums"]["hyperliquidChain"], self.labels)

    def test_event_split_and_cover(self):
        events = [("r", 48, 16), ("r", 64, 8), ("m", "d", 0), ("r", 88, 1), ("m", "v", 0), ("r", 0, 8), ("r", 0, 8)]
        pre, groups = T.split_events(events)
        self.assertEqual(pre, [(48, 16), (64, 8)])
        self.assertEqual(groups, [[(88, 1)]])
        self.assertEqual(T.cover([(0, 8), (0, 8), (8, 4)]), ([(0, 8), (8, 4)], 0))
        self.assertEqual(T.cover([]), ([], None))


if __name__ == "__main__":
    unittest.main()
