import json
import math
import struct
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import quantity_mark_pass_115 as q  # noqa: E402
import quantity_pass_x86_115 as cpu  # noqa: E402

EVIDENCE = ROOT / "research" / "work-items" / "RE-004-quantity-mark-pass-115"
FORBIDDEN = tuple("/%s/" % name for name in ("home", "mnt", "srv", "root", "tmp", "opt", "var", "etc"))


def simple_case(**fields):
    """One dex, two assets: slot 0 maps to oracle index 1 whose mark is 1500 with 3 size decimals."""
    c = q.Case()
    c.keys = (11, 22)
    c.scale = 2.0
    c.elems = [(6, b"ETHX", 4), (3, b"ETHX", 4)]
    c.marks = {1: 1500}
    c.tail = bytes(range(21))
    c.dexes = [dict(count=2, id=0, flag58=0, f378=5, f408=0, src=("btree", {0: 1}, 0x5000, 0))]
    c.rb = (q.MIN, 7, 2)
    for name, value in fields.items():
        setattr(c, name, value)
    return c


def inserts(events):
    return [e for e in events if e[0] == "insert"]


class RoundingAndCast(unittest.TestCase):
    def test_round_half_away(self):
        self.assertEqual(q.round_away(0.5), 1.0)
        self.assertEqual(q.round_away(-0.5), -1.0)
        self.assertEqual(q.round_away(2.5), 3.0)
        self.assertEqual(q.round_away(0.49999999999999994), 0.0)
        self.assertTrue(math.isnan(q.round_away(math.nan)))
        self.assertEqual(q.round_away(math.inf), math.inf)

    def test_wrong_rounding_is_different(self):
        self.assertNotEqual(round(2.5), q.round_away(2.5))
        self.assertNotEqual(math.floor(0.5), q.round_away(0.5))

    def test_count_boundaries(self):
        self.assertEqual(q.mark_count(1, 0.0, ())[1], 1)
        self.assertEqual(q.mark_count(1, math.nan, ())[1], 1)
        self.assertEqual(q.mark_count(1, math.inf, ())[1], 1)
        self.assertEqual(q.mark_count(1 << 63, 4.0, ())[1], (1 << 64) - 1)
        self.assertEqual(q.mark_count(1 << 62, 1.0, ())[1], 1 << 62)
        self.assertEqual(q.mark_count(3, -2.0, ())[1], 1)
        self.assertEqual(q.mark_count(5, 0.5, ())[1], 3)

    def test_count_variants_differ(self):
        self.assertNotEqual(q.mark_count(5, 0.5, ())[1], q.mark_count(5, 0.5, ("round_half_even",))[1])
        self.assertNotEqual(q.mark_count(3, 0.0, ())[1], q.mark_count(3, 0.0, ("no_floor",))[1])
        self.assertNotEqual(q.mark_count(1 << 63, 4.0, ())[1], q.mark_count(1 << 63, 4.0, ("no_saturate",))[1])


class ModelFlow(unittest.TestCase):
    def test_insert_value(self):
        events, out = q.model(simple_case())
        self.assertEqual(out, ("sink",))
        rows = inserts(events)
        self.assertEqual(len(rows), 1)
        # 1500 * 2.0 = 3000, divided by 10**3 = 3.0, the decimal 3 with scale 0
        self.assertEqual(rows[0][1], 0)
        self.assertEqual(rows[0][2], struct.pack("<IIQ", 0, 0, 3).hex())

    def test_scale_two_decimals(self):
        c = simple_case()
        c.elems[1] = (5, b"ETHX", 4)
        rows = inserts(q.model(c)[0])
        self.assertEqual(rows[0][2], struct.pack("<IIQ", 0, 0, 300).hex())

    def test_hype_scale_is_one(self):
        c = simple_case()
        c.elems[1] = (3, q.HYPE, 4)
        plain = simple_case()
        kernel = [e for e in q.model(c)[0] if e[0] == "kernel"]
        other = [e for e in q.model(plain)[0] if e[0] == "kernel"]
        self.assertEqual(len(kernel), 1)
        self.assertNotEqual(kernel, other)
        self.assertEqual(q.mark_count(1500, 1.0, ())[1], 1500)
        c.elems[1] = (3, q.PURR, 4)
        self.assertEqual([e for e in q.model(c)[0] if e[0] == "kernel"], kernel)
        c.elems[1] = (3, q.PURR, 3)
        self.assertEqual([e for e in q.model(c)[0] if e[0] == "kernel"], other)
        c.dexes[0]["id"] = 0
        c.elems[1] = (3, q.HYPE, 4)
        self.assertNotEqual([e for e in q.model(c, ("purr_off",))[0] if e[0] == "kernel"], [])

    def test_early_codes_and_drops(self):
        c = simple_case()
        c.dexes[0]["f378"] = q.MIN
        self.assertEqual(q.model(c), ([("guard",), ("guard",), ("drain",)], ("early", 0x19E)))
        c = simple_case(rb=(4, 0x1000, 1))
        c.dexes[0]["flag58"] = 1
        self.assertEqual(q.model(c), ([("guard",), ("guard",), ("dealloc", 0x1000, 96)], ("early", 0x101)))
        c.rb = (0, 0x1000, 1)
        self.assertEqual(q.model(c)[0][-1], ("guard",))

    def test_sentinel_beats_flag(self):
        c = simple_case()
        c.dexes[0]["f408"] = q.MIN + 1
        c.dexes[0]["flag58"] = 1
        self.assertEqual(q.model(c)[1], ("early", 0x19E))

    def test_panics(self):
        self.assertEqual(q.model(simple_case(index=1)), ([], ("panic", "dex-index")))
        c = simple_case()
        c.elems[1] = (7, b"ETHX", 4)
        self.assertEqual(q.model(c)[1], ("panic", "decimals"))
        c = simple_case()
        c.marks = {10001: 5}
        c.dexes[0]["src"] = ("btree", {0: 10001}, 0x5000, 0)
        self.assertEqual(q.model(c)[1], ("panic", "oracle-id"))
        c = simple_case()
        c.dexes[0]["id"] = 1844674407370956
        self.assertEqual(q.model(c)[1], ("panic", "key-mul"))
        c.dexes[0]["id"] = 1844674407370955
        c.dexes[0]["count"] = 1700
        self.assertEqual(q.model(c)[1], ("panic", "key-add"))

    def test_missing_mark_is_skipped(self):
        c = simple_case(marks={})
        events, out = q.model(c)
        self.assertEqual((out, inserts(events)), (("sink",), []))

    def test_variants_change_results(self):
        c = simple_case()
        base = q.model(c)
        for name in ("scale_plain", "dec_off_by_one", "sign_flip"):
            c2 = simple_case()
            c2.marks = {1: 10 ** 17}
            c2.scale = 0.1 if name == "scale_plain" else 2.0
            self.assertNotEqual(q.model(c2), q.model(c2, (name,)), name)
        self.assertEqual(base, q.model(c, ()))

    def test_ring_and_btree_agree(self):
        a = simple_case()
        b = simple_case()
        b.dexes[0]["src"] = ("ring", 3, 2, [(0, 1)])
        ea, eb = q.model(a), q.model(b)
        self.assertEqual(inserts(ea[0]), inserts(eb[0]))
        self.assertNotEqual(ea[0], eb[0])


class Recorded(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = [line.split("\t") for line in (EVIDENCE / "cases.tsv").read_text().splitlines()[1:]]
        cls.measure = json.loads((EVIDENCE / "measure.json").read_text())

    def test_signatures_match_the_model(self):
        for seed, kernel, events, outcome, signature in self.rows[::7]:
            c = q.gen_case(int(seed))
            log, out = q.model(c)
            self.assertEqual(q.sig(log, out, c.real_kernel), signature, seed)
            self.assertEqual(q.outcome_name(out), outcome)
            self.assertEqual(len(log), int(events))

    def test_corrupted_row_is_caught(self):
        seed, kernel, events, outcome, signature = self.rows[10]
        c = q.gen_case(int(seed))
        log, out = q.model(c)
        bad = q.sig(log + [("insert", 0, "00")], out, c.real_kernel)
        self.assertNotEqual(bad, signature)

    def test_measure_is_consistent(self):
        m = self.measure
        self.assertEqual(m["sampled_rows"], len(self.rows))
        self.assertEqual(m["cases"], 2 * len(self.rows))
        self.assertEqual(m["negative_detected"] + m["equivalent"], m["negative_controls"])
        self.assertEqual(m["dead_branch_reaches"], 0)
        controls = (EVIDENCE / "controls.tsv").read_text().splitlines()[1:]
        self.assertEqual(len(controls), m["negative_controls"])
        self.assertEqual(sum(1 for line in controls if line.split("\t")[3] == "1"), m["negative_detected"])
        equivalent = (EVIDENCE / "equivalent-mutants.tsv").read_text().splitlines()[1:]
        self.assertEqual(len(equivalent), m["equivalent"])

    def test_all_outcomes_present(self):
        kinds = {line.split("\t")[0] for line in (EVIDENCE / "outcome-kinds.tsv").read_text().splitlines()[1:]}
        self.assertEqual(kinds, {"early:257", "early:414", "panic:decimals", "panic:dex-index", "panic:key-add", "panic:key-mul",
                                 "panic:oracle-id", "sink"})

    def test_model_variants_move_signatures(self):
        moved = {}
        for name in q.MUTANTS:
            for seed, kernel, events, outcome, signature in self.rows:
                c = q.gen_case(int(seed))
                log, out = q.model(c, (name,))
                if q.sig(log, out, c.real_kernel) != signature:
                    moved[name] = seed
                    break
        self.assertEqual(sorted(moved), sorted(q.MUTANTS))

    def test_patch_table_is_unique_and_ordered(self):
        spots = [(va, at) for va, at, _, _, _ in q.PATCHES]
        self.assertEqual(len(spots), len(set(spots)))
        for va, at, old, new, _ in q.PATCHES:
            self.assertNotEqual(old, new)
            self.assertTrue(q.ENTRY <= va < 0x2C506E1)


class Guards(unittest.TestCase):
    def test_wrong_digest_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "node"
            path.write_bytes(b"not the node binary")
            with self.assertRaises(cpu.EvidenceError):
                cpu.load_image(path)

    def test_patch_byte_mismatch_refused(self):
        class Fake:
            blob = bytes([0x11] * 64)

            def offset(self, va):
                return va % 64

        with self.assertRaises(cpu.EvidenceError):
            q.make_patches(Fake(), [(0x2C4FE4B, 1, 0x83, 0x82, "x")])

    def test_unmodelled_call_halts(self):
        class Bare:
            pass

        machine = cpu.Machine.__new__(cpu.Machine)
        machine.calls, machine.real = {}, frozenset()
        machine.regs = [0] * 16
        machine.regs[cpu.RSP] = cpu.STACK_TOP - 0x100
        machine.memory = cpu.Memory(Bare())
        with self.assertRaises(cpu.Halt):
            code = bytes([0xE8, 0x10, 0, 0, 0])
            row = cpu.decode(lambda va, count: code[va - 0x1000:va - 0x1000 + count], 0x1000)
            cpu.Machine.step(machine, row)

    def test_no_server_paths_in_packet_files(self):
        files = [Path(q.__file__), Path(cpu.__file__), Path(__file__)] + [p for p in EVIDENCE.iterdir() if p.is_file()]
        for path in files:
            text = path.read_text()
            for marker in FORBIDDEN:
                self.assertNotIn(marker, text, "%s in %s" % (marker, path.name))


if __name__ == "__main__":
    unittest.main()
