import random
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import transport_lz4_stream_api_115 as t  # noqa: E402

IMG = None


def image():
    global IMG
    if IMG is None:
        IMG = t.Image((ROOT / t.NODE_PATH).read_bytes())
    return IMG


def agree(case, table=None):
    spec = (table or t.SPEC)[case.func]
    try:
        got = t.run_target(image(), case)
    except t.Fault as exc:
        got = (t.FAULT, str(exc))
    return got == t.run_spec(case, spec)


class StreamApiTests(unittest.TestCase):
    def test_every_function_start_is_an_fde_extent(self):
        img = image()
        for name, start in t.FUNCTIONS.items():
            lo, hi = img.extent(start)
            self.assertEqual(lo, start, name)
            self.assertGreater(hi - lo, 8, name)

    def test_import_stubs_resolve_by_relocation_name(self):
        names = set(image().plt.values())
        self.assertTrue({'memset', 'malloc', 'calloc', 'free'} <= names)

    def test_compress_bound_boundaries(self):
        cap = 0x7e000000
        for v, want in ((0, 16), (254, 270), (255, 272), (cap, cap + cap // 255 + 16), (cap + 1, 0), (M32(), 0)):
            case = t.Case('LZ4_compressBound', (v,))
            ret, _ = t.run_target(image(), case)
            self.assertEqual(ret, want, hex(v))

    def test_init_gates(self):
        for p, size, ok in ((0x1000, 0x4020, True), (0x1000, 0x401f, False), (0, 0x4020, False),
                            (0x1004, 0x4020, False), (0x1008, 1 << 40, True)):
            ret, trace = t.run_target(image(), t.Case('LZ4_initStream', (p, size)))
            self.assertEqual(ret, p if ok else 0)
            self.assertEqual(bool(trace), ok)

    def test_level_clamp(self):
        for lv, want in ((-5, 9), (0, 9), (1, 1), (12, 12), (13, 12), (0x7fffffff, 12)):
            _, trace = t.run_target(image(), t.Case('LZ4_setCompressionLevel', (0x4000, lv & t.M32)))
            self.assertEqual(trace, [('store', 0x4000 + 0x40024, 2, want)])

    def test_dictionary_window_and_hash(self):
        small = t.Case('LZ4_loadDict', (0x5000, 0x100000, 7), seed=1)
        ret, trace = t.run_target(image(), small)
        self.assertEqual(ret, 0)
        self.assertEqual(len(trace), 2)
        big = t.Case('LZ4_loadDict', (0x5000, 0x100000, 0x10003), seed=2)
        ret, trace = t.run_target(image(), big)
        self.assertEqual(ret, 0x10000)
        self.assertTrue(agree(big))

    def test_random_cases_match_specification(self):
        cases = t.gen_cases(random.Random(7))
        picked = cases[::40]
        self.assertGreater(len(picked), 300)
        small = [c for c in picked if c.func != 'LZ4_loadDict' or c.args[2] <= 600 or c.args[2] >= 0x7ffffff0]
        self.assertTrue(all(agree(c) for c in small))

    def test_mutant_specifications_are_caught(self):
        by = {}
        for c in t.gen_cases(random.Random(3)):
            by.setdefault(c.func, []).append(c)
        caught = 0
        mutants = t.mutated_specs()
        for label, func, table in mutants:
            sample = by[func][:80] + by[func][80::60]
            if func == 'LZ4_loadDict':
                sample = [c for c in sample if c.args[2] <= 600 or c.args[2] >= 0x7ffffff0]
            if not all(agree(c, table) for c in sample):
                caught += 1
            else:
                self.fail(f'mutant survived: {label}')
        self.assertEqual(caught, len(mutants))

    def test_damaged_bytes_are_caught(self):
        img = image()
        by = {}
        for c in t.gen_cases(random.Random(3)):
            by.setdefault(c.func, []).append(c)
        t.STEP_LIMIT[0] = 20000
        try:
            for label, func, va, mask in t.BYTE_DAMAGE[:12]:
                img.patches[va] = img.byte(va) ^ mask
                try:
                    sample = [c for c in by[func][:80] + by[func][80::60]
                              if func != 'LZ4_loadDict' or c.args[2] <= 600]
                    self.assertFalse(all(agree(c) for c in sample), label)
                finally:
                    del img.patches[va]
        finally:
            t.STEP_LIMIT[0] = 400000

    def test_wrong_image_and_range_rejected(self):
        with self.assertRaises(t.ToolError):
            t.Image(b'\x7fELF' + bytes(200))
        with self.assertRaises(t.ToolError):
            image().extent(t.FUNCTIONS['LZ4_compressBound'] + 1)
        with self.assertRaises(t.Fault):
            image().offset(0x7000000000)

    def test_decoder_rejects_unknown_opcode(self):
        img = image()
        img.patches[0x62e5bf4] = 0xd6
        try:
            with self.assertRaises(t.Fault):
                t.decode_uncached(img, 0x62e5bf4)
        finally:
            del img.patches[0x62e5bf4]
            img.cache.clear()


def M32():
    return t.M32


if __name__ == '__main__':
    unittest.main()
