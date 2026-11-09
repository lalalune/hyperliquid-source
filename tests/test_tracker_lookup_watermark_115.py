import copy
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import tracker_lookup_watermark_115 as tool  # noqa: E402

EVIDENCE = ROOT / "research/work-items/abci-tracker-lookup-watermark-115"
FILES = ("cases.tsv", "mutants.tsv", "calls.tsv", "summary.json", "measure.json")


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = tool.load_image()
        cls.lookups = tool.lookup_cases()
        cls.marks = tool.watermark_cases()

    def pick(self, kind, **want):
        pool = self.lookups if kind == "lookup" else self.marks
        for c in pool:
            if all(c.get(k) == v for k, v in want.items()):
                return c
        raise AssertionError(f"no case {want}")


class LookupModel(Base):
    def check(self, case):
        for start in tool.LOOKUPS:
            self.assertEqual(tool.run_body(self.image, start, case), tool.reconstruct(self.image, start, case))

    def test_gates_end_with_none(self):
        for want in ({"form": "ring", "rerr": 1}, {"form": "map", "root": 0}, {"form": "map", "root": 1, "found": 0}):
            case = self.pick("lookup", **want)
            got = tool.run_body(self.image, 0x2BAFCE0, case)
            self.assertEqual(got[1], tool.NONE_VEC)
            self.check(case)

    def test_ring_bound_and_wrap(self):
        beyond = self.pick("lookup", form="ring", ridx=1, len=1)
        self.assertEqual(tool.run_body(self.image, 0x2BAFCE0, beyond)[3][-1][0], "ring")
        wrap = next(c for c in self.lookups if c["form"] == "ring" and c["cap"] == 3 and c["head"] == 2
                    and c["ridx"] == 2 and c["len"] == 3 and c["entry"]["name"] == "deque/c4h1n3")
        self.assertEqual(tool.entry_address(wrap), tool.RING + 1 * 80 + 8)
        self.check(wrap)

    def test_set_hit_ends_lookup_miss_iterates(self):
        hit = next(c for c in self.lookups if c["entry"]["name"] == "set/leaf/=/0" and c["tsig"] == ("ring", 0, False, 0, 0))
        miss = next(c for c in self.lookups if c["entry"]["name"] == "set/leaf/>/0" and c["tsig"] == ("ring", 0, False, 0, 0))
        self.assertEqual(tool.run_body(self.image, 0x2BAFCE0, hit)[1], tool.NONE_VEC)
        self.assertEqual(tool.run_body(self.image, 0x2BAFCE0, miss)[1], tool.COLLECTED)
        self.check(hit)
        self.check(miss)

    def test_deque_head_beyond_capacity(self):
        case = next(c for c in self.lookups if c["entry"]["name"] == "deque/c4h9n3" and c["form"] == "map"
                    and c["root"] and c["found"])
        words = tool.run_body(self.image, 0x2BAFCE0, case)[3][-1][2]
        self.assertEqual(words[0], 2)
        self.check(case)

    def test_twins_agree(self):
        for case in self.lookups[::97]:
            self.assertEqual(tool.run_body(self.image, 0x2BAFCE0, case), tool.run_body(self.image, 0x2BAFF80, case))

    def test_wrong_models_caught(self):
        for name in tool.LOOKUP_VARIANTS:
            caught = any(tool.reconstruct(self.image, 0x2BAFCE0, c, name) != tool.run_body(self.image, 0x2BAFCE0, c)
                         for c in self.lookups)
            self.assertTrue(caught, name)


class WatermarkModel(Base):
    def test_cutoff_saturates(self):
        low = self.pick("watermark", h=49_999, prev=0, trace=0, count=0, equal=0, mark=0)
        high = self.pick("watermark", h=50_001, prev=0, trace=0, count=0, equal=0, mark=0)
        for start in tool.WATERMARKS:
            self.assertEqual(tool.run_body(self.image, start, low)[3][-1][3], 0)
            self.assertEqual(tool.run_body(self.image, start, high)[3][-1][3], 1)

    def test_unsigned_maximum_and_mark(self):
        case = self.pick("watermark", h=1, prev=1 << 63, equal=1, trace=0, count=0, mark=0)
        for start in tool.WATERMARKS:
            got = tool.run_body(self.image, start, case)
            self.assertEqual(got[1], 1 << 63)
            self.assertEqual(got[2], 1)
            self.assertEqual(got, tool.reconstruct(self.image, start, case))

    def test_release_and_trace(self):
        case = self.pick("watermark", h=1, prev=0, trace=1, count=3, equal=0, mark=0x201)
        for start in tool.WATERMARKS:
            got = tool.run_body(self.image, start, case)
            self.assertEqual([r[0] for r in got[3]], ["trace", "locate", "helper", "dealloc"])
            self.assertEqual(got[3][-1], ("dealloc", tool.DESC_PTR, 24, 0))
            self.assertEqual(got[2], 0x201)

    def test_wrong_models_caught(self):
        for name in tool.WATERMARK_VARIANTS:
            caught = any(tool.reconstruct(self.image, 0x27605D0, c, name) != tool.run_body(self.image, 0x27605D0, c)
                         for c in self.marks)
            self.assertTrue(caught, name)


class Controls(Base):
    def test_corrupt_target_digest_rejected(self):
        saved = tool.SHA256
        tool.SHA256 = "0" * 64
        try:
            with self.assertRaises(tool.Fail):
                tool.load_image()
        finally:
            tool.SHA256 = saved

    def test_out_of_range_and_mid_function_start_rejected(self):
        with self.assertRaises(tool.Fail):
            tool.body_insns(self.image, 0x2BAFCE1)
        with self.assertRaises(Exception):
            tool.body_insns(self.image, 0x10)

    def test_flipped_jumps_change_results(self):
        case = next(c for c in self.lookups if c["entry"]["name"] == "set/leaf/>/0" and c["tsig"] == ("ring", 0, False, 0, 0))
        real = tool.run_body(self.image, 0x2BAFCE0, case)
        changed = 0
        for va, off in tool.jcc_sites(self.image, 0x2BAFCE0):
            data = bytearray(self.image.data)
            data[off] ^= 1
            mutant = copy.copy(self.image)
            mutant.data = bytes(data)
            mutant.cache = {}
            changed += tool.run_body(mutant, 0x2BAFCE0, case) != real
        self.assertGreaterEqual(changed, 10)

    def test_corrupted_constant_changes_cutoff(self):
        case = self.pick("watermark", h=50_001, prev=0, trace=0, count=0, equal=0, mark=0)
        real = tool.run_body(self.image, 0x27605D0, case)
        at = next(i.off for i in tool.body_insns(self.image, 0x27605D0)[2]
                  if self.image.data[i.off:i.off + 3] == bytes.fromhex("4881eb") )
        data = bytearray(self.image.data)
        data[at + 3] ^= 0x01
        mutant = copy.copy(self.image)
        mutant.data = bytes(data)
        mutant.cache = {}
        self.assertNotEqual(tool.run_body(mutant, 0x27605D0, case), real)

    def test_unknown_callee_stops_run(self):
        case = self.pick("watermark", h=1, prev=0, trace=0, count=0, equal=0, mark=0)
        roles = {"locate": 0x1, "helper": 0x2, "dealloc": 0x3, "trace": 0x4}
        m = tool.Machine(self.image, case, roles)
        tool.watermark_setup(m, case, tool.trace_flag_address(self.image, 0x27605D0))
        m.pc = 0x27605D0
        with self.assertRaises(Exception):
            for _ in range(200):
                m.step()

    def test_static_facts_from_bytes(self):
        self.assertEqual(tool.watermark_slots(self.image, 0x27605D0)[0], self.image.slots[tool.slot_calls(self.image, 0x27605D0)[0][1]])
        self.assertEqual(len(tool.rip_leas(self.image, 0x27605D0)), 6)
        rows = tool.call_rows(self.image, 0x2BAFCE0)
        self.assertIn(0x236E750, [r[2] for r in rows])
        self.assertIn(0x236FF70, [r[2] for r in tool.call_rows(self.image, 0x2BAFF80)])


class Evidence(Base):
    def test_regeneration_matches_committed_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            summary = tool.generate(tmp)
            self.assertEqual(summary["mismatches"], 0)
            self.assertEqual(summary["mutants"]["survived"], 0)
            self.assertEqual(summary["measure"]["negative_controls"], summary["measure"]["negative_detected"])
            self.assertGreaterEqual(summary["measure"]["cases"], 10000)
            self.assertGreaterEqual(summary["measure"]["negative_controls"], 30)
            for name in FILES:
                self.assertEqual((pathlib.Path(tmp) / name).read_bytes(), (EVIDENCE / name).read_bytes(), name)


if __name__ == "__main__":
    unittest.main()
