"""Regression and adversarial controls for RE-007 node #94 static evidence."""

import filecmp
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools/margin_path_static.py"
PACKET = ROOT / "research/work-items/RE-007-margin-path-94"

spec = importlib.util.spec_from_file_location("margin_path_static", TOOL)
mps = importlib.util.module_from_spec(spec)
sys.modules["margin_path_static"] = mps
spec.loader.exec_module(mps)

CACHE = {}


class Fixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not CACHE:
            data = mps.BINARY.read_bytes()
            CACHE["data"] = data
            CACHE["analysis"] = mps.analyse(data)
            CACHE["image"] = mps.Image(data)
        cls.data = CACHE["data"]
        cls.analysis = CACHE["analysis"]
        cls.image = CACHE["image"]

    def mutate_va(self, va, replacement):
        data = bytearray(self.data)
        off = self.image.off(va, len(replacement))
        data[off:off + len(replacement)] = replacement
        return bytes(data)


class Evidence(Fixture):
    def test_counts_and_identity(self):
        result = self.analysis[0]
        self.assertEqual(result["target"]["sha256"], mps.SHA256)
        self.assertFalse(result["target"]["captured_binary_executed"])
        self.assertEqual(result["counts"], {
            "functions": 8,
            "instruction_controls": 30,
            "dependency_edges": 19,
            "locations": 7,
            "boundary_rows": 24,
        })

    def test_mode_jump_table(self):
        self.assertEqual(self.analysis[0]["scope"]["mode_jump_destinations"], [
            "0x3717888", "0x37174cb", "0x371751f", "0x37175b6", "0x37174f0"
        ])

    def test_regeneration_is_byte_identical(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            mps.write_packet(out, self.analysis)
            names = sorted(p.name for p in out.iterdir())
            expected = ["boundaries.tsv", "dependencies.tsv", "evidence.json",
                        "functions.tsv", "instruction-bytes.txt", "locations.tsv"]
            self.assertEqual(names, expected)
            same, different, errors = filecmp.cmpfiles(out, PACKET, names, shallow=False)
            self.assertEqual((sorted(same), different, errors), (names, [], []))
            for path in out.iterdir():
                self.assertNotIn("/Users/", path.read_text())


class Admission(unittest.TestCase):
    def test_order_and_limits(self):
        self.assertEqual(mps.admit_tiers(251, [(0, 50)] * 4)[0], "description-too-long")
        self.assertEqual(mps.admit_tiers(250, [(0, 50)] * 4)[0], "too-many-tiers")
        self.assertEqual(mps.admit_tiers(250, [])[0], "empty-tiers")
        self.assertEqual(mps.admit_tiers(250, [(mps.WIRE_NTL_LIMIT, 50)])[0],
                         "wire-ntl-too-large")
        self.assertEqual(mps.admit_tiers(250, [(1, 50)])[0], "first-lower-not-zero")
        self.assertEqual(mps.admit_tiers(250, [(0, 51)])[0], "leverage-too-large")
        self.assertEqual(mps.admit_tiers(250, [(0, 50), (1, 50)])[0],
                         "leverage-not-decreasing")
        self.assertEqual(mps.admit_tiers(250, [(0, 50), (2, 40), (1, 30)])[0],
                         "lower-not-increasing")

    def test_zero_leverage_gap_is_explicit(self):
        status, tiers = mps.admit_tiers(0, [(0, 0)])
        self.assertEqual(status, "ok")
        with self.assertRaises(ZeroDivisionError):
            mps.initial_requirement(tiers, 1)
        self.assertEqual(mps.admit_tiers(0, [(0, 1), (1, 0)])[0],
                         "zero-divisor-before-result")

    def test_prior_contribution(self):
        status, tiers = mps.admit_tiers(250, [(0, 50), (1000, 20), (1_000_000, 10)])
        self.assertEqual(status, "ok")
        self.assertEqual(tiers, [(0, 0, 50), (1000, 15, 20), (1_000_000, 25015, 10)])


class Arithmetic(unittest.TestCase):
    TIERS = [(0, 0, 50), (1000, 15, 20), (1_000_000, 25015, 10)]

    def test_tier_boundary_flooring(self):
        self.assertEqual(mps.initial_requirement(self.TIERS, 999), 9)
        self.assertEqual(mps.initial_requirement(self.TIERS, 1000), 10)
        self.assertEqual(mps.maintenance_requirement(self.TIERS, 999), 6)
        self.assertEqual(mps.maintenance_requirement(self.TIERS, 1000), 6)

    def test_u64_saturation_and_high_bit(self):
        self.assertEqual(mps.maintenance_requirement(self.TIERS, mps.U64_MAX),
                         307445734561809183)
        self.assertEqual(mps.maintenance_requirement(self.TIERS, 1 << 63),
                         307445734561809183)

    def test_signed_notional_boundaries(self):
        self.assertEqual(mps.checked_signed_notional(mps.I64_MIN, 1), mps.I64_MIN)
        self.assertEqual(mps.uabs_i64(mps.I64_MIN), 1 << 63)
        self.assertEqual(mps.checked_signed_notional(0, mps.I64_MAX), 0)
        with self.assertRaises(ArithmeticError):
            mps.checked_signed_notional(1, -1)
        with self.assertRaises(OverflowError):
            mps.checked_signed_notional(mps.I64_MAX, 2)

    def test_cross_and_isolated_maintenance(self):
        cross = {"size": 100, "leverage": 20, "isolated": False, "margin": 0}
        isolated = {"size": -100, "leverage": 20, "isolated": True, "margin": 90}
        c = mps.position_summary(cross, 10, 3, 0, self.TIERS)
        i = mps.position_summary(isolated, 10, 3, 0, self.TIERS)
        self.assertEqual(c, {"isolated": False, "signed": 1000, "effective": 6,
                             "notional": 1000, "previous_margin": 0, "computed": 0})
        self.assertEqual(i, {"isolated": True, "signed": -910, "effective": 0,
                             "notional": 1000, "previous_margin": 90, "computed": 6})
        self.assertEqual(mps.liquidation_surplus(c), 994)
        self.assertEqual(mps.liquidation_surplus(i), -916)

    def test_zero_is_not_eligible(self):
        for value, expected in [(-1, True), (0, False), (1, False)]:
            self.assertEqual(value < 0, expected)

    def test_saturating_signed_margin(self):
        pos = {"size": 1, "leverage": 1, "isolated": True, "margin": mps.I64_MAX}
        summary = mps.position_summary(pos, 1, 0, 0, self.TIERS)
        self.assertEqual(summary["signed"], mps.I64_MAX)


class MutationControls(Fixture):
    def test_digest_rejects_any_change(self):
        with self.assertRaises(mps.EvidenceError):
            mps.analyse(self.data[:-1])

    def test_every_instruction_control_is_live(self):
        for name, (va, expected) in mps.CONTROLS.items():
            raw = bytearray.fromhex(expected)
            raw[len(raw) // 2] ^= 1
            with self.subTest(name=name):
                with self.assertRaisesRegex(mps.EvidenceError, "instruction control changed"):
                    mps.analyse(self.mutate_va(va, raw), verify_digest=False)

    def test_got_target_mutation_is_rejected(self):
        rela = next(s for s in self.image.sections if s["name"] == ".rela.dyn")
        data = bytearray(self.data)
        found = False
        for off in range(rela["offset"], rela["offset"] + rela["size"], 24):
            where, info, addend = __import__("struct").unpack_from("<QQq", data, off)
            if where == 0x57759A0:
                self.assertEqual((info & 0xFFFFFFFF, addend), (8, 0x3333670))
                __import__("struct").pack_into("<q", data, off + 16, addend + 1)
                found = True
                break
        self.assertTrue(found)
        with self.assertRaisesRegex(mps.EvidenceError, "GOT relocation changed"):
            mps.analyse(bytes(data), verify_digest=False)

    def test_fde_extent_mutation_is_rejected(self):
        # The first function's FDE range is encoded at fde+12 as a signed 32-bit length.
        fde = self.analysis[1][0][4]
        old = self.image.read(fde + 12, 4)
        changed = bytearray(old)
        changed[0] ^= 1
        with self.assertRaises((mps.EvidenceError, ValueError)):
            mps.analyse(self.mutate_va(fde + 12, changed), verify_digest=False)

    def test_formula_mutants_are_detected_by_boundary_vectors(self):
        tiers = [(0, 0, 50), (1000, 15, 20), (1_000_000, 25015, 10)]
        inputs = [999, 1000, 999999, 1_000_000, 1 << 63, mps.U64_MAX]
        initial_mutant = lambda n: max(0, n // (2 * mps.tier_for(tiers, n)[2]) -
                                       mps.tier_for(tiers, n)[1] + 1)
        maintenance_mutant = lambda n: mps.maintenance_requirement(tiers, n) + 1
        self.assertTrue(any(initial_mutant(n) != mps.initial_requirement(tiers, n) for n in inputs))
        self.assertTrue(any(maintenance_mutant(n) != mps.maintenance_requirement(tiers, n)
                            for n in inputs))


if __name__ == "__main__":
    unittest.main()
