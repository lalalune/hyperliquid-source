"""Tests for tools/reserve_read_precompile.py. Expected numbers here are literals, not calls to the tool's rule list."""
import copy
import math
import pathlib
import struct
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import reserve_read_precompile as tool  # noqa: E402

FOLDER = ROOT / "research" / "work-items" / "RE-004-reserve-read-precompile-94"
E14 = 10 ** 14
TOP = 2 ** 64 - 1
SHIFT = 1 << 63


class Shared:
    image = None
    harness = None
    full = None


def shared_get():
    if Shared.image is None:
        Shared.image = tool.load_image()
        Shared.harness = tool.Harness(Shared.image)
    return Shared.image, Shared.harness


def shared_result():
    if Shared.full is None:
        Shared.full = tool.analyse(shared_get()[0])
    return Shared.full


def patched(image, va, value):
    other = copy.copy(image)
    blob = bytearray(image.blob)
    blob[image.offset(va)] = value
    other.blob = bytes(blob)
    return other


class Base(unittest.TestCase):
    def setUp(self):
        self.image, self.harness = shared_get()

    def run_case(self, **fields):
        return self.harness.run(tool.Case("probe", **fields))[1]

    def head(self, **fields):
        got = self.run_case(**fields)
        return struct.unpack_from("<5Q", got[1], tool.OUT - tool.HEAP_BASE), got

    def words(self, **fields):
        _, got = self.head(**fields)
        base = tool.ALLOC_ONE - tool.HEAP_BASE
        data = got[1][base:base + 256]
        for index in range(8):
            self.assertEqual(data[32 * index:32 * index + 24], bytes(24))
        return [struct.unpack_from(">Q", data, 32 * index + 24)[0] for index in range(8)]


class Identity(unittest.TestCase):
    def test_wrong_digest_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(expected="0" * 64)

    def test_changed_byte_refused(self):
        blob = bytearray(tool.BINARY.read_bytes())
        blob[-1] ^= 1
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "copy"
            path.write_bytes(blob)
            with self.assertRaises(tool.EvidenceError):
                tool.load_image(path)

    def test_source_starts_no_program(self):
        text = (ROOT / "tools" / "reserve_read_precompile.py").read_text()
        for word in ("subprocess", "popen", "os.system"):
            self.assertNotIn(word, text)


class Bounds(Base):
    def test_fde_bounds(self):
        self.assertEqual(self.image.exact_fde(0x324BDF0), (0x324BDF0, 0x324C52D))
        self.assertEqual(self.image.exact_fde(0x3790F20), (0x3790F20, 0x3790FBF))

    def test_not_an_fde_start(self):
        with self.assertRaises(tool.EvidenceError):
            self.image.exact_fde(0x324BDF1)

    def test_nobits_has_no_file_bytes(self):
        bss = self.image.named[".bss"]
        with self.assertRaises(tool.EvidenceError):
            self.image.offset(bss["address"] + 8)

    def test_outside_text(self):
        with self.assertRaises(tool.EvidenceError):
            self.image.fde(0x10)


class Gates(Base):
    def starved(self, **fields):
        self.assertEqual(self.head(**fields)[0][:3], (0, 0, SHIFT))

    def test_blocked_address(self):
        for shape in ("leaf", "deep", "deep left"):
            self.starved(keys=(0x812, 0x813), set_shape=shape)

    def test_other_address_passes(self):
        self.assertEqual(self.head(keys=(0x813, 0x814), set_shape="leaf")[0][0], tool.VTABLE)

    def test_length_cap(self):
        self.assertEqual(self.head(n=2000, gas=TOP)[0][4], 75448)
        self.starved(n=2001, gas=TOP)

    def test_base_gate_edge(self):
        self.assertEqual(self.head(n=32, gas=2056, ok=False)[0][2], 13)
        self.starved(n=32, gas=2055, ok=False)

    def test_total_gas_edge(self):
        self.assertEqual(self.head(n=32, gas=10504)[0][4], 10504)
        self.starved(n=32, gas=10503)

    def test_late_starvation_releases_bytes(self):
        got = self.run_case(n=32, gas=10503)
        self.assertEqual(got[3][-1], ("free_bytes", tool.ALLOC_ONE, 256))

    def test_invalid_input_text(self):
        head, got = self.head(ok=False)
        self.assertEqual(head[2:5], (13, tool.ALLOC_ONE, 13))
        base = tool.ALLOC_ONE - tool.HEAP_BASE
        self.assertEqual(got[1][base:base + 13], b"Invalid input")

    def test_token_bound_is_exclusive(self):
        self.assertEqual(self.run_case(tok=10, count=10)[3], (("format", 0xEA, 10), ("drop", 0xEA)))
        self.assertEqual(self.head(tok=9, count=10)[0][0], tool.VTABLE)

    def test_missing_record(self):
        for shape in ("empty", "miss", "below"):
            self.assertEqual(self.run_case(shape=shape)[3], (("format", 0xE1, 0), ("drop", 0xE1)))

    def test_utilization_errors_collapse(self):
        for fields in (dict(uw=(1, 3)), dict(uw=(1, 2)), dict(uf=(1, 3)), dict(lookup_fail=True)):
            self.assertEqual(self.run_case(**fields)[3], (("format", 0xE1, 0xA), ("drop", 0xE1)))

    def test_first_allocation_panics(self):
        got = self.run_case(oom=1)
        self.assertEqual((got[0], got[1]), ("panic", (1, 256)))
        got = self.run_case(oom=2)
        self.assertEqual((got[0], got[1]), ("panic", (8, 32)))


class Words(Base):
    def test_order(self):
        rec = tool.record(a=3 * 10 ** 15, ia=E14 + 11, b=5 * 10 ** 15, ib=E14 + 13, tag=1, ltv=7 * 10 ** 13, px=0x1020304, bal=0x5060708)
        self.assertEqual(self.words(rec=rec, r=2000, uw=(0, 3000), uf=(0, 0.75), c=2 * 10 ** 13),
                         [2000, 1200, 0x5060708, 3000, 0x1020304, 7000, 5000000000000650, 3000000000000330])

    def test_borrowed_floors(self):
        self.assertEqual(self.words(rec=tool.record(a=1, ia=E14 + 1))[7], 1)
        self.assertEqual(self.words(rec=tool.record(a=3, ia=E14 // 2))[7], 1)

    def test_total_past_guard_is_zero(self):
        self.assertEqual(self.words(rec=tool.record(a=TOP, ia=TOP))[7], 0)
        self.assertEqual(self.words(rec=tool.record(b=TOP, ib=TOP))[6], 0)

    def test_guard_edge(self):
        below = (E14 << 64) - 1
        factor = below // TOP
        self.assertEqual(self.words(rec=tool.record(a=factor, ia=TOP))[7], factor * TOP // E14)
        self.assertEqual(self.words(rec=tool.record(a=factor + 1, ia=TOP))[7], 0)

    def test_ltv_floor_and_tag(self):
        self.assertEqual(self.words(rec=tool.record(tag=1, ltv=2 * 10 ** 10 - 1))[5], 1)
        self.assertEqual(self.words(rec=tool.record(tag=1 | 1 << 32, ltv=2 * 10 ** 10))[5], 2)
        for tag in (0, 2, 257):
            self.assertEqual(self.words(rec=tool.record(tag=tag, ltv=2 * 10 ** 10))[5], 0)

    def test_ltv_top(self):
        self.assertEqual(self.words(rec=tool.record(tag=1, ltv=TOP))[5], 1844674407)


class Supply(Base):
    def supply(self, r, u, c=0):
        return self.words(r=r, uf=(0, u), c=c)[1]

    def test_plain(self):
        self.assertEqual(self.supply(10000, 0.5), 5000)
        self.assertEqual(self.supply(10000, 0.5, 10 ** 13), 4500)

    def test_share_above_one_goes_to_zero(self):
        self.assertEqual(self.supply(10000, 0.5, 2 * E14), 0)

    def test_truncates(self):
        self.assertEqual(self.supply(3, 0.5), 1)

    def test_double_floor(self):
        self.assertEqual(self.supply(1, 0.75, 10 ** 13), 0)

    def test_rate_read_as_signed_32_bits(self):
        self.assertEqual(self.supply(1 << 31, 1.0), 0)
        self.assertEqual(self.supply((1 << 32) + 7, 1.0), 7)

    def test_nan_and_infinity_give_zero(self):
        for u in (math.nan, math.inf, -math.inf):
            self.assertEqual(self.supply(10000, u), 0)

    def test_huge_finite_saturates(self):
        self.assertEqual(self.supply(10000, 1e300), TOP)
        self.assertEqual(self.supply(1, 1.7976931348623157e308), TOP)

    def test_largest_double_below_two_64(self):
        self.assertEqual(self.supply(1, 18446744073709549568.0), 18446744073709549568)


class RealCallees(Base):
    def test_rate_and_utilization_real(self):
        got = self.words(rec=tool.record(a=50, b=100), real=True)
        # u = 5e13, f = 6.25e13, rate = 3.125e12, so the two words are 312 and 5000.
        self.assertEqual((got[0], got[3]), (312, 5000))

    def test_real_error_reaches_internal(self):
        got = self.run_case(rec=tool.record(a=TOP, ia=TOP, b=10), real=True)
        self.assertEqual(got[3], (("format", 0xE1, 0xA), ("drop", 0xE1)))


class Lookup(Base):
    def test_found(self):
        got = self.run_case(kind=tool.LOOKUP, shape="deep", tok=5)
        base = tool.OUT - tool.HEAP_BASE
        self.assertEqual(got[1][base], 0)
        self.assertEqual(struct.unpack_from("<Q", got[1], base + 8)[0], tool.NODES + 2 * tool.NODE_STRIDE)

    def test_missing(self):
        got = self.run_case(kind=tool.LOOKUP, shape="miss", tok=5)
        base = tool.OUT - tool.HEAP_BASE
        self.assertEqual(got[1][base:base + 2], bytes((1, 9)))


class Negative(Base):
    def spots(self, va, value, case):
        other = patched(self.image, va, value)
        harness = tool.Harness(other)
        before, got = harness.run(case)
        return tool.same(got, tool.spec_run(case, before))

    def test_length_cap_edit_is_caught(self):
        self.assertFalse(self.spots(0x324BEC6 + 3, 0xD1, tool.Case("edge", n=2001, gas=tool.TOP)))

    def test_gas_base_edit_is_caught(self):
        self.assertFalse(self.spots(0x324BEDA + 3, 0xE9, tool.Case("edge", n=32, gas=2056, ok=False)))

    def test_rule_list_rejects_a_changed_word(self):
        case = tool.Case("edge")
        before, got = self.harness.run(case)
        want = tool.spec_run(case, before)
        at = tool.ALLOC_ONE - tool.HEAP_BASE + 24 + 7
        changed = bytearray(want[1])
        changed[at] ^= 1
        self.assertFalse(tool.same(got, (want[0], bytes(changed), want[2], want[3])))

    def test_constant_moved(self):
        with self.assertRaises(tool.EvidenceError):
            tool.constant_rows(patched(self.image, tool.F_RESERVE + 7, 0x42))

    def test_address_moved(self):
        with self.assertRaises(tool.EvidenceError):
            tool.constant_rows(patched(self.image, tool.ADDRESS_CONST + 19, 0x13))

    def test_arm_shape_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.arm_text(self.image, 0x324BDF0)

    def test_reciprocal_bound_can_fail(self):
        original = tool.MUL_E10
        tool.MUL_E10 = original - 1
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.reciprocal_rows()
        finally:
            tool.MUL_E10 = original

    def test_step_limit_control(self):
        # A sweep with a limit below a real run would count every mutant as killed.
        harness = tool.Harness(self.image)
        harness.machine.step_limit = 50
        with self.assertRaises(tool.Halt):
            harness.run(tool.Case("short"))


class Evidence(unittest.TestCase):
    def test_mutations(self):
        rows = shared_result()["mutations"]
        survivors = sorted((va, kind) for va, kind, outcome, _ in rows if outcome == "survived")
        self.assertEqual(len(survivors), 6)
        self.assertEqual(survivors, sorted(tool.EXPECTED_SURVIVORS))

    def test_tail_pieces(self):
        rows = shared_result()["pieces"]
        self.assertEqual(len(rows), 13)
        self.assertEqual((rows[0][0], rows[-1][1]), ("0x0", "0xffffffffffffffff"))
        for left, right in zip(rows, rows[1:]):
            self.assertEqual(int(left[1], 16) + 1, int(right[0], 16))

    def test_holders(self):
        rows = shared_result()["holders"]
        self.assertEqual(rows, [("slot", "0x56a6af8"), ("slot", "0x56dfb20"), ("direct_count", 0)])

    def test_gas_table(self):
        self.assertEqual(shared_result()["gas"][2], (32, 2056, 10504, 20720))

    def test_texts(self):
        self.assertEqual(shared_result()["texts"], [("0xea", "Invalid token"), ("0xe1 prefix", "Borrow/Lend error: "), ("0xe1 inner 0xa", "Internal error")])

    def test_only_landing_pads_unreached(self):
        unreached = shared_result()["unreached"]
        self.assertEqual(unreached[tool.LOOKUP], [])
        self.assertTrue(all(va >= 0x324C4F5 for va in unreached[tool.PRECOMPILE]))

    def test_folder_equals_generated_set(self):
        files = tool.render(shared_result())
        names = sorted(path.name for path in FOLDER.iterdir())
        self.assertEqual(names, sorted(list(files) + ["MANIFEST.sha256", "README.md"]))
        for name, text in files.items():
            self.assertEqual((FOLDER / name).read_text(), text, name)


if __name__ == "__main__":
    unittest.main()
