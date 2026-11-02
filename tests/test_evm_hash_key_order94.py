"""Target-bound local comparator fields, independent oracle and corruptions."""
import importlib.util
import json
from pathlib import Path
import random
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research/work-items/RE-009-evm-hash-key-order-94"
SPEC = importlib.util.spec_from_file_location("key_order94", PACKET / "verify.py")
v = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(v)


class LocalKeyOrderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = v.NODE.read_bytes()
        cls.secs = v.sections(cls.data)
        cls.contract = v.validate_contract(cls.data, cls.secs)
        cls.plan = json.loads((PACKET / "PLAN.json").read_text())

    def mutate(self, address, replacement):
        sec = next(s for s in self.secs if s["type"] != 8 and
                   s["address"] <= address < s["address"] + s["size"])
        offset = sec["offset"] + address - sec["address"]
        changed = bytearray(self.data)
        self.assertNotEqual(changed[offset], replacement)
        changed[offset] = replacement
        return changed

    def assert_oracle(self, candidate, stored):
        left, right = int.from_bytes(candidate, "little"), int.from_bytes(stored, "little")
        self.assertEqual(v.compare_words(self.contract, candidate, stored),
                         (left > right) - (left < right))

    def test_complete_authenticated_record(self):
        actual = v.analyze(self.data)
        self.assertEqual(actual, json.loads((PACKET / "evidence.json").read_text()))
        self.assertEqual(actual["counts"], {"primary_FDE_extents": 1,
            "primary_bytes": 624, "selected_transfers": 22, "compared_key_words": 4})
        self.assertEqual(len(bytes.fromhex(actual["primary"]["body_hex"])), 624)
        self.assertEqual(actual["transfers"][15]["target"], "0x1ab3d20")
        self.assertEqual(actual["credited_context"]["call"]["target"], "0x28546c0")
        v.check_disassembly((PACKET / "native.asm").read_text(), self.data, self.secs)

    def test_disassembly_missing_or_changed_bytes_are_rejected(self):
        listing = (PACKET / "native.asm").read_text()
        with self.assertRaisesRegex(ValueError, "differs from target"):
            v.check_disassembly(listing.replace("\t55 ", "\t54 ", 1), self.data, self.secs)
        with self.assertRaisesRegex(ValueError, "incomplete"):
            v.check_disassembly("", self.data, self.secs)

    def test_manifest_omission_duplicate_and_corruption_controls(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "first").write_bytes(b"first")
            (directory / "second").write_bytes(b"second")
            first = v.hashlib.sha256(b"first").hexdigest() + "  first\n"
            second = v.hashlib.sha256(b"second").hexdigest() + "  second\n"
            manifest = directory / "MANIFEST.sha256"
            manifest.write_text(first + second)
            v.check_manifest(directory)
            for contents, error in ((first, "incomplete"),
                                    (first + first + second, "duplicate"),
                                    (first.replace(first[:64], "0" * 64) + second, "digest")):
                manifest.write_text(contents)
                with self.subTest(error=error), self.assertRaisesRegex(ValueError, error):
                    v.check_manifest(directory)

    def test_every_deciding_word_and_unsigned_boundary(self):
        for deciding in range(4):
            for low, high in ((0, 1), (2**63 - 1, 2**63), (2**64 - 2, 2**64 - 1)):
                a = [2**64 - 1 if i < deciding else 0 for i in range(4)]
                b = [0 for _ in range(4)]
                a[deciding], b[deciding] = low, high
                left = b"".join(x.to_bytes(8, "little") for x in a)
                right = b"".join(x.to_bytes(8, "little") for x in b)
                with self.subTest(word=deciding, low=low, high=high):
                    self.assert_oracle(left, right)
                    self.assert_oracle(right, left)
        for value in (0, 2**256 - 1):
            key = value.to_bytes(32, "little")
            self.assert_oracle(key, key)

    def test_all_bits_and_deterministic_independent_oracle(self):
        for bit in range(256):
            key = (1 << bit).to_bytes(32, "little")
            previous = ((1 << bit) - 1).to_bytes(32, "little")
            self.assert_oracle(key, bytes(32))
            self.assert_oracle(key, previous)
            self.assert_oracle(previous, key)
        rng = random.Random(94)
        for _ in range(2048):
            self.assert_oracle(rng.randbytes(32), rng.randbytes(32))

    def test_frozen_field_and_control_mutations(self):
        self.assertEqual(len(self.plan["native_mutations"]), 7)
        for mutation in self.plan["native_mutations"]:
            address = int(mutation["va"], 16)
            changed = self.mutate(address, int(mutation["replacement"], 16))
            with self.subTest(meaning=mutation["meaning"]):
                self.assertNotEqual(v.decode_contract(changed, self.secs), self.contract)
                with self.assertRaisesRegex(ValueError, "contract changed"):
                    v.validate_contract(changed, self.secs)

    def test_signedness_mutation_has_a_real_counterexample(self):
        changed = self.mutate(0x2854715, 0x9F)
        signed = v.decode_contract(changed, self.secs)
        self.assertEqual(signed["relation"], "signed-greater/unsigned-borrow")
        left = (2**255).to_bytes(32, "little")
        right = (2**255 - 1).to_bytes(32, "little")
        self.assertEqual(v.compare_words(self.contract, left, right), 1)
        self.assertEqual(v.compare_words(signed, left, right), 0)

    def test_word_source_mutation_has_a_real_counterexample(self):
        changed = self.mutate(0x28546E7, 0x10)
        altered = v.decode_contract(changed, self.secs)
        left, right = (2**192).to_bytes(32, "little"), bytes(32)
        self.assertEqual(v.compare_words(self.contract, left, right), 1)
        self.assertEqual(v.compare_words(altered, left, right), 0)

    def test_width_and_transfer_opcodes_fail_closed(self):
        for address, byte in ((0x28546E4, 0x40), (0x285473B, 0x74),
                              (0x28547C9, 0xB1), (0x28548F0, 0x89)):
            with self.subTest(address=hex(address)):
                with self.assertRaisesRegex(ValueError, "instruction form"):
                    v.decode_contract(self.mutate(address, byte), self.secs)
        with self.assertRaisesRegex(ValueError, "unexpected transfer"):
            v.transfer(self.mutate(0x2854859, 0x90), self.secs, 0x2854859)

    def test_whole_file_identity_is_separate(self):
        with self.assertRaisesRegex(ValueError, "size/SHA-256"):
            v.analyze(self.mutate(0x2854715, 0x9F))
        with self.assertRaisesRegex(ValueError, "size/SHA-256"):
            v.analyze(self.data[:-1])

    def test_input_and_mapping_boundaries(self):
        for left_size, right_size in ((31, 32), (32, 31), (33, 32), (32, 33)):
            with self.assertRaisesRegex(ValueError, "two 32-byte keys"):
                v.compare_words(self.contract, bytes(left_size), bytes(right_size))
        for address, size in ((-1, 1), (v.START, 0), (True, 1), (2**64, 4)):
            with self.assertRaises(ValueError):
                v.span(self.data, self.secs, address, size)
        section = next(s for s in self.secs if s["address"] <= v.START < s["address"] + s["size"])
        with self.assertRaisesRegex(ValueError, "uniquely file backed"):
            v.span(self.data, [section, section], v.START, 1)
        with self.assertRaisesRegex(ValueError, "uniquely file backed"):
            v.span(self.data, [{**section, "type": 8}], v.START, 1)
        with self.assertRaisesRegex(ValueError, "exceeds input"):
            v.span(self.data[:10], [section], v.START, 1)


if __name__ == "__main__":
    unittest.main()
