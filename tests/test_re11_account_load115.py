import json
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import re11_account_load115 as t  # noqa: E402

IMAGE = None


def image():
    global IMAGE
    if IMAGE is None:
        IMAGE = t.al.Image(t.BINARY.read_bytes())
    return IMAGE


def sample(spec, n, start=0):
    return [t.make_case(image(), spec, i) for i in range(start, start + n)]


class AccountLoadTests(unittest.TestCase):
    def test_binary_digest_is_enforced(self):
        data = t.BINARY.read_bytes()
        with self.assertRaises(t.ToolError):
            t.al.Image(data[:-1] + bytes([data[-1] ^ 1]))

    def test_address_outside_text_is_rejected(self):
        with self.assertRaises(t.ToolError):
            image().code(0x10, 4)

    def test_function_extents_and_decode(self):
        rows = t.al.fde_rows(image(), [t.ORD, t.SPEC])
        self.assertEqual(rows[t.ORD][1] - rows[t.ORD][0], 1696)
        self.assertEqual(rows[t.SPEC][1] - rows[t.SPEC][0], 1546)
        for start in (t.ORD, t.SPEC):
            decoded = t.sweep_rows(image(), *rows[start])
            self.assertEqual(decoded[0][0], start)
            self.assertGreater(len(decoded), 300)

    def test_both_variants_match_the_machine_code(self):
        bad = 0
        machines = {False: t.Mach(image()), True: t.Mach(image())}
        seen = set()
        for spec in (False, True):
            for c, want, got, ok in t.run_stream(image(), machines=machines, cases=sample(spec, 330)):
                bad += 0 if ok else 1
                seen.add((spec, t.classify(c, want)))
        self.assertEqual(bad, 0)
        for spec in (False, True):
            for cls in ("hit/fresh", "load/ctor", "load/default", "refused/vacant", "refused/occupied", "default/ud2"):
                self.assertIn((spec, cls), seen)
        self.assertIn((False, "load/default+err-vcall"), seen)
        self.assertIn((False, "load/default+err-free"), seen)

    def test_every_model_mutant_is_detected(self):
        cases = sample(False, 300) + sample(True, 300)
        for name in t.MODEL_MUTANTS:
            self.assertTrue(t.detects(image(), None, frozenset([name]), cases), name)

    def test_corrupted_code_bytes_are_detected(self):
        # invert the near jne that follows "cmp eax, [r15+0x120]" (the stale-epoch test) in both bodies
        needle = bytes.fromhex("413b8720010000")
        for spec, start in ((False, t.ORD), (True, t.SPEC)):
            lo, hi = t.al.fde_rows(image(), [start])[start]
            body = image().code(lo, hi - lo)
            at = lo + body.index(needle) + len(needle)
            self.assertEqual(image().code(at, 2)[:2], b"\x0f\x85")
            self.assertFalse(t.detects(image(), None, frozenset(), sample(spec, 100)))
            self.assertTrue(t.detects(image(), {at + 1: 0x84}, frozenset(), sample(spec, 300)))

    def test_code_preparation_body_matches_the_machine_code(self):
        cases = [t.make_prep_case(image(), i) for i in range(260)]
        classes = set()
        for c, want, got, ok in t.run_stream(image(), cases=cases):
            self.assertTrue(ok, (c["i"], c["kind"], got.get("error")))
            classes.add(t.classify(c, want))
        for cls in ("prep/kept", "prep/db-code", "prep/default/empty-hash", "prep/default/db-err-vcall",
                    "prep/default/db-err-free", "prep/default/db-null"):
            self.assertIn(cls, classes)
        for name in t.PREP_MUTANTS:
            self.assertTrue(t.detects(image(), None, frozenset([name]), cases), name)

    def test_code_preparation_empty_hash_halves_are_the_rodata_constants(self):
        rows = t.al.fde_rows(image(), [t.PREP])
        self.assertEqual(rows[t.PREP][1] - rows[t.PREP][0], 291)
        low, high = t.img16(image(), t.HASH_LOW), t.img16(image(), t.HASH_HIGH)
        self.assertEqual(len(low + high), 32)
        c = t.make_prep_case(image(), 1)
        self.assertEqual(c["account"][0x48:0x68], low + high)
        flipped = dict(c, account=c["account"][:0x48] + bytes([c["account"][0x48] ^ 1]) + c["account"][0x49:])
        self.assertNotEqual(t.reconstruct_prep(image(), flipped)["events"], t.reconstruct_prep(image(), c)["events"])

    def test_wrong_variant_model_is_detected(self):
        machines = {False: t.Mach(image()), True: t.Mach(image())}
        wrong = 0
        for c in sample(False, 40):
            want = t.reconstruct(image(), False, c)
            try:
                ok = t.compare(want, t.run_machine(machines[True], True, c))
            except (t.ToolError, t.Boundary, IndexError, KeyError, ValueError):
                ok = False
            wrong += 0 if ok else 1
        self.assertGreater(wrong, 0)

    def test_refcount_overflow_flag_semantics(self):
        # 0x7fff...ff + 1 sets OF with SF, so the signed jle after lock inc is not taken;
        # -1 + 1 == 0 and 0x8000...00 + 1 (SF without OF) both reach ud2.
        c = next(x for x in sample(False, 500) if x["kind"] == "vac_arc_edge")
        res = {}
        for rc in (0x7fff_ffff_ffff_ffff, 0xffff_ffff_ffff_ffff, 0x8000_0000_0000_0000, 1):
            c = dict(c, refcnt=rc, dbraw=bytes(8) + c["dbraw"][8:], flag=0, warm=0, seed_state=2, lazy_state=0)
            want = t.reconstruct(image(), False, c)
            got = t.run_machine(t.Mach(image()), False, c)
            self.assertTrue(t.compare(want, got))
            res[rc] = got["status"]
        self.assertEqual(res[0x7fff_ffff_ffff_ffff], "ret")
        self.assertEqual(res[0xffff_ffff_ffff_ffff], "ud2")
        self.assertEqual(res[0x8000_0000_0000_0000], "ud2")
        self.assertEqual(res[1], "ret")

    def test_vacant_and_occupied_refusal_conditions_differ(self):
        # flag byte 3 with a cold address: vacant path tests (flag^1)|warm != 0, occupied path tests == 1
        c = next(x for x in sample(False, 500) if x["kind"] == "occ_stale")
        c = dict(c, flag=3, warm=0)
        want = t.reconstruct(image(), False, c)
        self.assertEqual(want["mem"][t.OUT_AT][0x38], 2)
        self.assertTrue(t.compare(want, t.run_machine(t.Mach(image()), False, c)))

    def test_committed_evidence_matches_summary(self):
        folder = ROOT / "research" / "work-items" / "RE-011-account-load-journal-115"
        if not folder.exists():
            return
        summary = json.loads((folder / "summary.json").read_text())
        measure = json.loads((folder / "measure.json").read_text())
        self.assertEqual(summary["cases"], measure["cases"])
        self.assertEqual(summary["mismatches"], 0)
        self.assertEqual(measure["negative_controls"], measure["negative_detected"])


if __name__ == "__main__":
    unittest.main()
