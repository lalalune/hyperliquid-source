import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))

import cpuid_field_map_static as fieldmap  # noqa: E402
from elf_index import sections  # noqa: E402
from fde_extents import fde_extents  # noqa: E402


TARGET = ROOT / "artifacts" / "node" / "115" / "hl-node"
PACKET = (
    ROOT
    / "research"
    / "work-items"
    / "RE-002-node115-cpuid-field-map"
)
SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"


def mutate(data, virtual_address, mask=0x01):
    changed = bytearray(data)
    offset = virtual_address - 0x1000
    changed[offset] ^= mask
    return bytes(changed)


def retained_records():
    return json.loads((PACKET / "records.json").read_text(encoding="utf-8"))


def entry(word, bit):
    for row in retained_records()["field_map"]:
        if row["word"] == word and row["bit"] == bit:
            return row
    raise AssertionError(f"no field_map entry for {word} bit {bit}")


class AuthenticatedCpuidFieldMapTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.capture = TARGET.read_bytes()
        if len(cls.capture) != 105896032 or \
                hashlib.sha256(cls.capture).hexdigest() != SHA:
            raise AssertionError("target is not the pinned node115 capture")
        cls.report = fieldmap.analyze(cls.capture)

    def test_packet_regeneration_matches_retained_outputs(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary:
            output = Path(temporary) / "retained"
            fieldmap.generate(TARGET, output)
            for name in ("records.json", "frames.txt", "helper.objdump.txt"):
                self.assertEqual(
                    (output / name).read_bytes(), (PACKET / name).read_bytes(), name
                )

    def test_retained_report_pins_the_helper_and_leaf_frames(self):
        retained = retained_records()
        for key, value in self.report.items():
            self.assertEqual(retained[key], value, key)
        helper = retained["owners"]["refresh_helper"]
        self.assertEqual(helper["range"], "0x5cadd50..0x5cae3da")
        self.assertEqual(helper["bytes"], 1674)
        self.assertEqual(
            helper["sha256"],
            "f4cc818ee02b994599bfc53910323d3edf8420d0b404c2e5060faab72524c349",
        )
        leaf = retained["owners"]["xcr0_leaf"]
        self.assertEqual(leaf["range"], "0x5cae3e0..0x5cae3ed")
        self.assertEqual(leaf["bytes"], 13)
        self.assertEqual(
            leaf["sha256"],
            "f347a1395ba474e85f6c71330ca7f30e1d067cc6af42548744b6310ae2dbf0be",
        )

    def test_intake_has_one_call_and_no_relocation_reference(self):
        census = self.report["call_census"]
        self.assertEqual(census["direct_call_sites"], ["0x5cae04c"])
        self.assertEqual(census["relocation_references"], 0)

    def test_field_map_is_complete_for_both_words(self):
        rows = retained_records()["field_map"]
        self.assertEqual(len(rows), 128)
        for word in ("A", "B"):
            bits = sorted(r["bit"] for r in rows if r["word"] == word)
            self.assertEqual(bits, list(range(64)), word)
        a_zero = [r["bit"] for r in rows if r["word"] == "A" and not r["support"]]
        self.assertEqual(a_zero, [53, 63])
        b_zero = [r["bit"] for r in rows if r["word"] == "B" and not r["support"]]
        self.assertEqual(b_zero, list(range(12, 64)))

    def test_early_a_spot_checks(self):
        self.assertEqual(entry("A", 0)["support"],
                         ["cpuid leaf 1 subleaf 0 ecx bit 25"])
        self.assertEqual(entry("A", 6)["support"],
                         ["cpuid leaf 1 subleaf 0 edx bit 25"])
        self.assertEqual(entry("A", 7)["support"],
                         ["cpuid leaf 1 subleaf 0 edx bit 26"])
        self.assertEqual(entry("A", 57)["support"],
                         ["cpuid leaf 7 subleaf 0 ebx bit 3"])
        self.assertEqual(entry("A", 59)["support"],
                         ["cpuid leaf 0x80000001 subleaf 0 ecx bit 5"])
        self.assertEqual(entry("A", 61)["support"],
                         ["cpuid leaf 1 subleaf 0 ecx bit 23"])
        self.assertEqual(entry("A", 62)["support"],
                         ["cpuid leaf 1 subleaf 0 edx bit 24"])

    def test_early_b_spot_checks(self):
        self.assertEqual(entry("B", 3)["support"],
                         ["cpuid leaf 1 subleaf 0 ecx bit 13"])
        self.assertEqual(entry("B", 4)["support"],
                         ["cpuid leaf 0x19 subleaf 0 ebx bit 0"])
        self.assertEqual(entry("B", 9)["support"],
                         ["cpuid leaf 7 subleaf 1 eax bit 31"])
        self.assertEqual(entry("B", 10)["support"],
                         ["cpuid leaf 7 subleaf 0 ebx bit 9"])
        self.assertEqual(entry("B", 11)["support"],
                         ["cpuid leaf 0x80000001 subleaf 0 ecx bit 11"])
        for bit in (0, 1, 2):
            self.assertIn("leaf 0xd", entry("B", bit)["driver"])

    def test_leaf_0x24_block_bits(self):
        self.assertEqual(entry("A", 53)["support"], [])
        self.assertIn("both arms", entry("A", 53)["driver"])
        self.assertEqual(
            entry("A", 54)["support"],
            [f"cpuid leaf 0x24 subleaf 0 ebx bit {i}" for i in range(1, 8)],
        )

    def test_corrections_to_pr_2474_are_recorded(self):
        corrections = retained_records()["corrections_to_pr_2474"]
        self.assertEqual(len(corrections), 3)
        subjects = {c["subject"] for c in corrections}
        self.assertEqual(subjects, {"leaf 0x24 block reach",
                                    "fall-through leaf 1 ecx bit 12 landing bit",
                                    "bit 25 compare operand"})
        self.assertEqual(entry("A", 44)["support"],
                         ["cpuid leaf 7 subleaf 0 edx bit 25"])
        self.assertEqual(entry("A", 56)["support"],
                         ["cpuid leaf 1 subleaf 0 ecx bit 12"])
        self.assertEqual(entry("A", 25)["support"],
                         ["cpuid leaf 7 subleaf 0 ebx bit 31"])

    def test_censuses_match_the_retained_counts(self):
        censuses = retained_records()["censuses"]
        self.assertEqual(len(censuses["cpuid_sites"]), 10)
        self.assertEqual(len(censuses["r12_writes"]), 35)
        self.assertEqual(len(censuses["r15_writes"]), 8)
        self.assertEqual(len(censuses["r13_writes"]), 5)
        self.assertEqual(len(censuses["r14_mentions"]), 7)
        self.assertEqual(
            sum(len(v) for v in censuses["slot_stores"].values()), 11)
        self.assertEqual(
            sum(len(v) for v in censuses["slot_loads"].values()), 17)

    def test_provenance_closes_the_map(self):
        provenance = retained_records()["provenance"]
        self.assertEqual(provenance["zero_bits"]["a"], [])
        self.assertEqual(provenance["zero_bits"]["b"], list(range(12, 64)))
        self.assertEqual(provenance["constant_bits"],
                         {"a": [25, 52, 53, 54, 63], "b": [0, 9]})
        bit52 = provenance["a"]["52"]
        self.assertIn("xcr0 bit 19", bit52["condition"])
        self.assertIn("cpuid leaf 7 subleaf 1 edx bit 21", bit52["condition"])
        for word in ("a", "b"):
            for bit, parts in provenance[word].items():
                self.assertNotIn("call:unknown", parts["value"], (word, bit))
                self.assertNotIn("call:unknown", parts["condition"], (word, bit))

    def test_selection_and_suffix_are_the_cited_rules(self):
        selection = self.report["selection"]
        self.assertEqual(selection["cleared_bits"], [14, 57, 58])
        self.assertEqual(selection["a_mask"], "0xf9ffffffffffbfff")
        self.assertIn("C2 = (B >> 62) | H = H", selection["source"])
        self.assertIn("C0 = A | H", self.report["suffix"]["equations"])

    def test_helper_body_mutations_are_rejected(self):
        for address in (0x5CADF4B, 0x5CAE33A, 0x5CAE35B):
            with self.subTest(address=hex(address)):
                with self.assertRaisesRegex(ValueError, "owner body changed"):
                    fieldmap.analyze(mutate(self.capture, address))

    def test_leaf_body_mutation_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "owner body changed"):
            fieldmap.analyze(mutate(self.capture, 0x5CAE3E5))

    def test_fde_record_mutation_is_rejected(self):
        _, fs, _ = fde_extents(self.capture)
        record = next(f for f in fs if f["start"] == 0x5CADD50)
        section = next(s for s in sections(self.capture)
                       if s["name"] == ".eh_frame")
        offset = record["fde"] - section["address"] + section["offset"] + 8
        changed = bytearray(self.capture)
        changed[offset] ^= 0x01
        with self.assertRaisesRegex(ValueError, "FDE"):
            fieldmap.analyze(bytes(changed))

    def test_public_identity_rejects_wrong_size_and_digest(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary:
            wrong_size = Path(temporary) / "wrong-size"
            wrong_size.write_bytes(self.capture[:-1])
            with self.assertRaisesRegex(ValueError, "pinned node115"):
                fieldmap.generate(wrong_size, Path(temporary) / "out1")
            wrong_digest = Path(temporary) / "wrong-digest"
            wrong_digest.write_bytes(mutate(self.capture, 0x6000000))
            with self.assertRaisesRegex(ValueError, "pinned node115"):
                fieldmap.generate(wrong_digest, Path(temporary) / "out2")


if __name__ == "__main__":
    unittest.main()
