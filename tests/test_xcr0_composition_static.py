import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))

import xcr0_composition_static as composition  # noqa: E402


TARGET = ROOT / "artifacts" / "node" / "115" / "hl-node"
PACKET = (
    ROOT
    / "research"
    / "work-items"
    / "RE-002-node115-xcr0-composition"
)


def mutate(data, virtual_address, mask=0x01):
    changed = bytearray(data)
    offset = virtual_address - 0x1000
    changed[offset] ^= mask
    return bytes(changed)


def retained_records():
    return json.loads((PACKET / "records.json").read_text(encoding="utf-8"))


class AuthenticatedXcr0CompositionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.capture = TARGET.read_bytes()
        if (
            len(cls.capture) != 105896032
            or hashlib.sha256(cls.capture).hexdigest() != composition.SHA
        ):
            raise AssertionError("target is not the pinned node115 capture")
        cls.report = composition.analyze(cls.capture)

    def test_packet_regeneration_matches_retained_outputs(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary:
            output = Path(temporary) / "retained"
            composition.generate(TARGET, output)
            for name in ("records.json", "frames.txt", "helper.objdump.txt"):
                self.assertEqual(
                    (output / name).read_bytes(), (PACKET / name).read_bytes(), name
                )

    def test_retained_report_pins_the_helper_and_leaf_frames(self):
        retained = retained_records()
        for key, value in self.report.items():
            self.assertEqual(retained[key], value, key)
        owners = {owner["role"]: owner for owner in retained["owners"]}
        helper = owners["refresh_helper"]
        self.assertEqual(helper["start"], "0x5cadd50")
        self.assertEqual(helper["end"], "0x5cae3da")
        self.assertEqual(helper["bytes"], 1674)
        self.assertEqual(
            helper["sha256"],
            "f4cc818ee02b994599bfc53910323d3edf8420d0b404c2e5060faab72524c349",
        )
        leaf = owners["xcr0_leaf"]
        self.assertEqual(leaf["start"], "0x5cae3e0")
        self.assertEqual(leaf["end"], "0x5cae3ed")
        self.assertEqual(
            leaf["sha256"],
            "f347a1395ba474e85f6c71330ca7f30e1d067cc6af42548744b6310ae2dbf0be",
        )

    def test_intake_has_one_call_and_three_post_call_result_reads(self):
        census = self.report["call_census"]
        self.assertEqual(census["direct_call_sites"], ["0x5cae04c"])
        self.assertEqual(census["relocation_references"], 0)
        intake = self.report["intake"]
        self.assertEqual(intake["call_site"], "0x5cae04c")
        self.assertEqual(intake["result_register"], "r14")
        reads = intake["post_call_reads"]
        self.assertEqual(reads["gate_field"], ["0x5cae054", "0x5cae057"])
        self.assertEqual(
            set(reads["mask_field_and_branch"]), {"0x5cae067", "0x5cae05d"}
        )
        self.assertEqual(reads["bit_19_test"], "0x5cae300")
        pre_call = intake["pre_call_r14"]
        self.assertEqual(pre_call["definition"], "0x5cadeb6")
        self.assertEqual(pre_call["reads"], ["0x5cadeba", "0x5cadfa6"])
        self.assertIn("leaf 7 subleaf 0 ecx", pre_call["value"])

    def test_xcr0_driven_fields_are_exactly_the_gated_set(self):
        fields = {
            (row["cache_word"], row["bit"]): row for row in self.report["field_map"]
        }
        h_row = fields[("C1", 0)]
        self.assertEqual(
            h_row["driver"], "xcr0 bits 1 and 2 both set (fall-through at 0x5cae061)"
        )
        self.assertEqual(h_row["a_bit"], 63)
        self.assertIn("0x5cae07b", h_row["mechanism"])
        bit52 = fields[("C0", 52)]
        self.assertIn("xcr0 bit 19", bit52["driver"])
        self.assertIn("0x5cae315", bit52["mechanism"])
        for bit in (1, 2, 3):
            self.assertIn("gated by xcr0 bits 1,2", fields[("C1", bit)]["driver"])
        self.assertFalse(any(word == "C2" for word, _ in fields))
        self.assertTrue(
            all(not row["value_bits_from_xcr0"] for row in self.report["field_map"])
        )

    def test_complemented_field_is_dead_and_drives_no_field(self):
        dead = self.report["dead_field"]
        self.assertEqual(dead["cache_fields"], [])
        self.assertIn("0x5cae157", dead["term"])
        self.assertIn("0x5cae15a", dead["value_use"])
        self.assertEqual(
            dead["first_rax_writes"],
            {
                "extra_block": "0x5cae165",
                "shared_block": "0x5cae278",
                "convergence": "0x5cae2fd",
            },
        )

    def test_selection_clears_no_xcr0_driven_field(self):
        selection = self.report["selection"]
        self.assertEqual(selection["cleared_bits"], [14, 57, 58])
        self.assertEqual(selection["xcr0_fields_cleared"], [])
        self.assertEqual(selection["a_mask"], "0xf9ffffffffffbfff")

    def test_censuses_match_the_retained_counts(self):
        censuses = retained_records()["censuses"]
        self.assertEqual(len(censuses["r14_mentions"]), 7)
        self.assertEqual(len(censuses["r12_writes"]), 35)
        self.assertEqual(len(censuses["r15_writes"]), 8)
        self.assertEqual(len(censuses["r13_writes"]), 5)
        self.assertEqual(len(censuses["rdi_mentions_after_intake"]), 8)
        self.assertEqual(len(censuses["rax_dead_ranges"]), 3)

    def test_value_taint_closes_without_xcr0_in_either_composed_word(self):
        taint = retained_records()["value_taint"]
        suffix = taint["suffix_entry"]
        for register in ("r12", "r13", "r15", "rdx"):
            self.assertFalse(suffix[register], register)
        self.assertEqual(taint["r12_tainted_blocks"], [])
        self.assertEqual(taint["r15_tainted_blocks"], [])
        self.assertTrue(taint["mask_field_block_r14_tainted"])

    def test_early_paths_never_read_xcr0(self):
        early = self.report["early_paths"]
        self.assertIn("never called", early["max_leaf_zero"])
        self.assertIn("never called", early["region_gate"])

    def test_helper_body_mutations_are_rejected(self):
        for address in (0x5cae078, 0x5cae300, 0x5cae35b, 0x5cae3af):
            with self.subTest(address=hex(address)):
                with self.assertRaisesRegex(ValueError, "body changed"):
                    composition.analyze(mutate(self.capture, address))

    def test_leaf_body_mutation_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "body changed"):
            composition.analyze(mutate(self.capture, 0x5cae3e5))

    def test_fde_record_mutation_is_rejected(self):
        owners = {owner["role"]: owner for owner in self.report["owners"]}
        fde = int(owners["refresh_helper"]["frames"]["fde"]["va"], 16)
        with self.assertRaisesRegex(ValueError, "FDE"):
            composition.analyze(mutate(self.capture, fde))

    def test_public_identity_rejects_wrong_size_and_digest(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary:
            wrong_size = Path(temporary) / "wrong-size"
            wrong_size.write_bytes(self.capture[:-1])
            with self.assertRaisesRegex(ValueError, "pinned node115"):
                composition.generate(wrong_size, Path(temporary) / "out1")
            wrong_digest = Path(temporary) / "wrong-digest"
            wrong_digest.write_bytes(mutate(self.capture, 0x6000000))
            with self.assertRaisesRegex(ValueError, "pinned node115"):
                composition.generate(wrong_digest, Path(temporary) / "out2")


if __name__ == "__main__":
    unittest.main()
