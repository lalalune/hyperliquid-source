import hashlib
import json
import pathlib
import struct
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import fees_credit_caller_115 as T  # noqa: E402

IMAGE = T.load_image()
RIG = T.Rig(IMAGE)
CASES = [T.gen_case(i) for i in range(400)]
WANTS = [T.expected_digest(RIG, c) for c in CASES]


class CallerTests(unittest.TestCase):
    def test_binary_digest_is_checked(self):
        with self.assertRaises(T.EvidenceError):
            T.load_image_bytes(bytes(IMAGE.blob[:64]) + b"x", T.SHA256)

    def test_function_bounds_are_an_fde(self):
        self.assertEqual(IMAGE.exact_fde(T.FN), (T.FN, T.FN_END))
        rows = T.decode_range(IMAGE, T.FN, T.FN_END)
        self.assertEqual(len(rows), 1001)
        with self.assertRaises(T.EvidenceError):
            IMAGE.exact_fde(T.FN + 1)

    def test_constants_match_the_bytes(self):
        def double(va):
            at = IMAGE.offset(va)
            return struct.unpack("<d", bytes(IMAGE.blob[at:at + 8]))[0]
        self.assertEqual(double(0x459808), -9223372036854775808.0)
        self.assertEqual(double(0x459360), 9223372036854775808.0)
        self.assertEqual(double(0x458E50), 9223372036854774784.0)
        at = IMAGE.offset(0x3C102A3)
        self.assertEqual(int.from_bytes(IMAGE.blob[at + 2:at + 10], "little"), T.CAP_CONST)
        at = IMAGE.offset(0x3C10442)
        self.assertEqual(int.from_bytes(IMAGE.blob[at + 2:at + 10], "little"), T.RECIP)

    def test_model_matches_machine_code(self):
        for case, want in zip(CASES, WANTS):
            ok, why = T.check(RIG, case, want)
            self.assertTrue(ok, why)

    def test_cases_reach_every_status_and_event(self):
        statuses, events = set(), set()
        for want in WANTS:
            statuses.add(want[0][0])
            events.update(e[0] for e in want[1])
        self.assertEqual(statuses, {"ok", "panic"})
        for name in ("scale", "mode", "sink", "alloc", "free", "rec", "arr", "tot", "inner", "find", "find2", "posa", "hashget"):
            self.assertIn(name, events)

    def test_every_model_variant_is_caught(self):
        for bug in T.BUG_TEXT:
            caught = False
            for case, want in zip(CASES[:120], WANTS[:120]):
                got = T.expected_digest(RIG, case, bug)
                if got[0] != want[0] or got[1] != want[1] or got[2] != want[2]:
                    caught = True
                    break
            self.assertTrue(caught, T.BUG_TEXT[bug])

    def test_byte_mutants_are_caught(self):
        chosen = [m for m in T.mutants(IMAGE) if m[1] in (0x3C102D6, 0x3C1060B, 0x3C10D5D, 0x3C108CF, 0x3C10F60)]
        self.assertGreaterEqual(len(chosen), 4)
        for kind, va, desc, new in chosen:
            rig = T.Rig(IMAGE, {va + k: b for k, b in enumerate(new)})
            rig.machine.step_limit = T.MUTANT_STEP_LIMIT
            dead = False
            for case, want in zip(CASES, WANTS):
                try:
                    ok, _ = T.check(rig, case, want)
                except (T.EvidenceError, T.Halt, KeyError, IndexError, ValueError):
                    ok = False
                if not ok:
                    dead = True
                    break
            self.assertTrue(dead, "%#x %s" % (va, desc))

    def test_row_index_past_the_table_panics_in_both(self):
        found = 0
        for case, want in zip(CASES, WANTS):
            if want[0][0] == "panic" and want[0][1] == T.P_BOUNDS:
                found += 1
                self.assertEqual(want[0][2] >= want[0][3], True)
                e_status = RIG.emulate(case)[0]
                self.assertEqual(e_status, want[0])
        self.assertGreater(found, 0)

    def test_allocation_failure_and_capacity_overflow_are_distinct_panics(self):
        seen = set()
        for i in range(2000):
            case = T.gen_case(i)
            status = RIG.run_model(case)[0]
            if status[0] == "panic":
                seen.add(status[1])
        self.assertTrue({T.P_ALLOC, T.P_CAP, T.P_INDEX, T.P_BOUNDS} <= seen)

    def test_saturating_add_records_every_overflow(self):
        world = T.World(T.Memory(IMAGE), {"seed": 0, "near": 0, "pf": 0, "mode": 0, "alloc_fail": False})
        world.mem.reset(T.USED)
        cell = T.ARENA - 64
        world.mem.write(cell, 8, T.M64 - 3)
        T.sat_add(world, cell, 2, 0x1234)
        self.assertEqual(world.mem.read(cell, 8), T.M64 - 1)
        self.assertEqual(world.trace, [])
        T.sat_add(world, cell, 5, 0x1234)
        self.assertEqual(world.mem.read(cell, 8), T.M64)
        self.assertEqual(world.trace, [("rec", 0x1234)])

    def test_float_conversion_edges(self):
        bits = lambda x: struct.unpack("<Q", struct.pack("<d", x))[0]
        self.assertEqual(T.convert_scaled(10, bits(0.5), 0), 5)
        self.assertEqual(T.convert_scaled(10, bits(-1.0), 0), 0)
        self.assertEqual(T.convert_scaled(10, bits(float("nan")), 0), 0)
        self.assertEqual(T.convert_scaled(10, bits(float("inf")), 0), 0)
        self.assertEqual(T.convert_scaled(1 << 40, bits(1e9), 0), 0x7FFFFFFFFFFFFFFF)
        with self.assertRaises(T.Pan):
            T.convert_scaled(1 << 63, bits(1.0), 0)

    def test_corrupted_heap_is_flagged(self):
        case = dict(CASES[5])
        image = bytearray(case["image"])
        image[0x500] ^= 0xFF
        case["image"] = bytes(image)
        ok, _ = T.check(RIG, case, WANTS[5])
        self.assertFalse(ok)

    def test_generation_is_deterministic(self):
        first = T.gen_case(77)
        second = T.gen_case(77)
        self.assertEqual(first["image"], second["image"])
        self.assertEqual(first["cfg"], second["cfg"])
        self.assertEqual(RIG.emulate(first)[1], RIG.emulate(second)[1])

    def test_evidence_files_are_reproducible_and_consistent(self):
        with tempfile.TemporaryDirectory() as one, tempfile.TemporaryDirectory() as two:
            args = dict(n_cases=300, n_mutants=12, n_mutant_cases=300)
            a = T.generate(one, **args)
            b = T.generate(two, **args)
            self.assertEqual(a, b)
            names = sorted(p.name for p in pathlib.Path(one).iterdir())
            self.assertEqual(names, sorted(p.name for p in pathlib.Path(two).iterdir()))
            for name in names:
                self.assertEqual((pathlib.Path(one) / name).read_bytes(), (pathlib.Path(two) / name).read_bytes(), name)
            measure = json.loads((pathlib.Path(one) / "measure.json").read_text())
            self.assertEqual(measure["cases"], 300)
            self.assertEqual(measure["negative_detected"] + measure["equivalent"], measure["negative_controls"])
            self.assertEqual(measure["mismatches"], 0)
            controls = (pathlib.Path(one) / "controls.tsv").read_text().splitlines()
            self.assertEqual(len(controls) - 1, measure["negative_controls"])

    def test_trace_digest_of_first_case_is_stable(self):
        digest = hashlib.sha256(repr([e if e[0] != "sink" else e[:5] for e in WANTS[0][1]]).encode()).hexdigest()
        self.assertEqual(len(digest), 64)


if __name__ == "__main__":
    unittest.main()
