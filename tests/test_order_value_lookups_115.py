import filecmp
import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import order_value_lookups_115 as T  # noqa: E402

FOLDER = ROOT / "research" / "work-items" / "RE-004-order-value-lookups-115"
U64 = T.U64
IMAGE = None


def setUpModule():
    global IMAGE
    data = bytearray(T.TARGET.read_bytes())
    assert T.digest(data) == T.SHA256
    IMAGE = T.cpu.Image(data)


def key(first, fill=0):
    return bytes([first]) + bytes([fill]) * 19


def lookup(body, rows, probe_key, mode="exact", once=0, extra=0, k0=11, k1=22):
    case = T.Lookup(rows=rows, key=probe_key, kind="hit" if probe_key in rows else "far", mode=mode, extra=extra, k0=k0,
                    k1=k1, once=once, junk=0)
    consts = T.body_consts(IMAGE, body)
    how, value, log, _ = T.lookup_actual(IMAGE, case, body, T.START[body])
    want = T.lookup_expected(IMAGE, case, body, consts)
    return (how, value, log), want


def pair(first, second):
    return (first, 5), (second, 7)


class Extents(unittest.TestCase):
    def test_bodies_start_at_fde_starts(self):
        sizes = {name: T.body_extent(IMAGE, start)[1] - start for name, start in T.BODIES}
        self.assertEqual(sizes, {"state_lookup": 367, "map_get": 213, "state_map_a": 117, "state_map_b": 117,
                                 "total_a": 676, "total_b": 676, "ring_search": 455})

    def test_mid_function_start_refused(self):
        for _, start in T.BODIES:
            with self.assertRaises(T.ToolError):
                T.body_extent(IMAGE, start + 1)

    def test_totals_are_structural_twins(self):
        a = T.body_extent(IMAGE, 0x2d35520)
        b = T.body_extent(IMAGE, 0x2d357d0)
        sa = [bytes(IMAGE.data[i.off:i.off + i.size]) for i in T.sweep(IMAGE, *a)]
        sb = [bytes(IMAGE.data[i.off:i.off + i.size]) for i in T.sweep(IMAGE, *b)]
        self.assertEqual(len(sa), len(sb))
        same = sum(x == y for x, y in zip(sa, sb))
        # only rip-relative displacements and branch offsets differ between the twins
        self.assertGreater(same, len(sa) * 0.7)

    def test_wrapper_maps_differ_only_by_offset_and_constants(self):
        sizes = [T.body_extent(IMAGE, s)[1] - s for s in (0x55e8c30, 0x55e8cb0)]
        self.assertEqual(sizes, [117, 117])
        a = bytes(IMAGE.data[IMAGE.file_offset(0x55e8c30):][:117])
        b = bytes(IMAGE.data[IMAGE.file_offset(0x55e8cb0):][:117])
        diff = [i for i in range(117) if a[i] != b[i]]
        self.assertEqual(int.from_bytes(a[10:14], "little"), 0x968)
        self.assertEqual(int.from_bytes(b[10:14], "little"), 0x14d8)
        self.assertTrue(diff)

    def test_constants_come_from_lea_bytes(self):
        self.assertEqual(T.body_consts(IMAGE, "state_lookup")["panic"], 0x644ac08)
        self.assertEqual(T.body_consts(IMAGE, "state_lookup")["once_rcx"], 0x6446f28)
        self.assertEqual(T.body_consts(IMAGE, "state_lookup")["once_r8"], 0x6446f50)
        self.assertEqual(T.body_consts(IMAGE, "map_get")["panic"], 0x649e918)
        self.assertEqual(T.body_consts(IMAGE, "state_map_a")["once_rcx"], 0x64aa698)
        self.assertEqual(T.body_consts(IMAGE, "state_map_b")["panic"], 0x649e918)


class Lookups(unittest.TestCase):
    bodies = T.LOOKUP_BODIES

    def check(self, *args, **kw):
        for body in self.bodies:
            got, want = lookup(body, *args, **kw)
            self.assertEqual(got, want, body)
        return got

    def test_empty_map_misses_without_host_calls(self):
        for body in self.bodies:
            got, _ = lookup(body, [], key(1))
            self.assertEqual(got[2], [] if body == "map_get" else [])
            self.assertEqual(got[0], "ret")
        self.assertEqual(lookup("map_get", [], key(1))[0][1], 0)
        self.assertEqual(lookup("state_lookup", [], key(1))[0][1], T.default_record(IMAGE))

    def test_single_row_compares_all_twenty_bytes(self):
        row = bytes(range(1, 21))
        for at in range(20):
            probe = bytearray(row)
            probe[at] ^= 0x80
            for body in self.bodies:
                got, want = lookup(body, [row], bytes(probe))
                self.assertEqual(got, want, (body, at))
                self.assertNotEqual(got[1], T.ROWS + 8, (body, at))
        for body in self.bodies:
            got, want = lookup(body, [row], row)
            self.assertEqual(got, want)
            self.assertEqual(got[1], T.ROWS + 8)
            self.assertEqual(got[2][:2], [] if body == "map_get" else got[2][:2])

    def test_single_row_never_hashes(self):
        for body in self.bodies:
            got, _ = lookup(body, [key(3)], key(3), once=0)
            self.assertNotIn("hash", [e[0] for e in got[2]])

    def test_many_rows_hash_then_probe_with_frame(self):
        rows = [key(i, i) for i in range(1, 6)]
        for body in self.bodies:
            got, want = lookup(body, rows, rows[3], k0=0xdead, k1=0xbeef)
            self.assertEqual(got, want)
            self.assertEqual([e[0] for e in got[2]][:2], ["hash", "probe"])
            self.assertEqual(got[2][0][1:3], (0xdead, 0xbeef))
            self.assertEqual(got[2][1][3], "frame")
            self.assertEqual(got[1], T.ROWS + T.ROW_STRIDE * 3 + 8)

    def test_probe_answer_is_trusted_without_a_key_recheck(self):
        rows = [key(i, i) for i in range(1, 5)]
        got, want = lookup("map_get", rows, key(99), mode="last")
        self.assertEqual(got, want)
        self.assertEqual(got[1], T.ROWS + T.ROW_STRIDE * 3 + 8)

    def test_bucket_index_at_or_past_row_count_panics(self):
        rows = [key(i, i) for i in range(1, 4)]
        for extra in range(3):
            for body in self.bodies:
                got, want = lookup(body, rows, rows[0], mode="oob", extra=extra)
                self.assertEqual(got, want)
                self.assertEqual(got[0], "panic")
                self.assertEqual(got[2][-1][1:3], (3 + extra, 3))

    def test_last_valid_index_does_not_panic(self):
        rows = [key(i, i) for i in range(1, 4)]
        got, want = lookup("state_lookup", rows, key(1), mode="last")
        self.assertEqual(got[0], "ret")
        self.assertEqual(got, want)

    def test_null_probe_gives_default_or_null(self):
        rows = [key(i, i) for i in range(1, 4)]
        self.assertEqual(lookup("map_get", rows, rows[1], mode="null")[0][1], 0)
        self.assertEqual(lookup("state_lookup", rows, rows[1], mode="null")[0][1], T.default_record(IMAGE))

    def test_once_slow_path_runs_after_the_lookup_for_every_default_form(self):
        rows = [key(i, i) for i in range(1, 4)]
        for body in self.bodies[:1] + self.bodies[2:]:
            for state in (0, 1, 3, 0x100):
                for probe in (rows[0], key(77)):
                    got, want = lookup(body, rows, probe, once=state)
                    self.assertEqual(got, want)
                    names = [e[0] for e in got[2]]
                    self.assertEqual("once" in names, state != 0, (body, state))
                    if state:
                        self.assertEqual(got[2][-1][1:3], (T.default_record(IMAGE) + 0x40, 1))

    def test_once_word_in_the_file_is_nonzero(self):
        self.assertEqual(T.initial_once_byte(IMAGE), 3)

    def test_map_get_has_no_once_or_default(self):
        got, _ = lookup("map_get", [key(1)], key(2), once=5)
        self.assertEqual(got, ("ret", 0, []))

    def test_wrappers_use_their_own_map_offset(self):
        rows = [key(i, i) for i in range(1, 4)]
        a, _ = lookup("state_map_a", rows, rows[2])
        b, _ = lookup("state_map_b", rows, rows[2])
        self.assertEqual(a[2][1][1], T.STATE + 0x968 + 0x18)
        self.assertEqual(b[2][1][1], T.STATE + 0x14d8 + 0x18)
        self.assertEqual(a[1], b[1])


class Totals(unittest.TestCase):
    @staticmethod
    def run_total(body, first, second, probe):
        case = T.Box(first=first, second=second, key=probe)
        got, _ = T.total_actual(IMAGE, case, T.START[body])
        return got, T.total_expected(case)

    @staticmethod
    def deque(pairs, cap=None, head=0):
        return T.Box(kind="deque", pairs=pairs, cap=cap or max(len(pairs), 1), head=head)

    @staticmethod
    def tree(pairs, height=0, rng=None):
        plan = T.build_tree(rng or T.Lcg(1), pairs, height) if pairs else None
        return T.Box(kind="tree", pairs=T.tree_pairs_of(plan) if plan else [], plan=plan, height=height)

    def both(self, *args):
        for body in ("total_a", "total_b"):
            got, want = self.run_total(body, *args)
            self.assertEqual(got, want, body)
        return got

    def test_missing_everywhere_is_zero(self):
        self.assertEqual(self.both(self.deque([]), self.tree([]), key(1)), 0)

    def test_sum_of_both_containers(self):
        k = key(5)
        self.assertEqual(self.both(self.deque([(k, 40)]), self.deque([(k, 2)]), k), 42)

    def test_only_one_side_present(self):
        k = key(5)
        self.assertEqual(self.both(self.deque([(k, 9)]), self.tree([(key(6), 1)]), k), 9)
        self.assertEqual(self.both(self.tree([(key(6), 1)]), self.deque([(k, 8)]), k), 8)

    def test_carry_saturates_at_u64(self):
        k = key(5)
        self.assertEqual(self.both(self.deque([(k, U64)]), self.deque([(k, 1)]), k), U64)
        self.assertEqual(self.both(self.deque([(k, U64 - 1)]), self.deque([(k, 1)]), k), U64)
        self.assertEqual(self.both(self.deque([(k, 1 << 63)]), self.tree([(k, 1 << 63)]), k), U64)
        self.assertEqual(self.both(self.deque([(k, U64)]), self.deque([]), k), U64)

    def test_wrapped_deque_search(self):
        pairs = [(key(i, i), i * 10) for i in range(1, 6)]
        for head in range(5):
            got = self.both(self.deque(pairs, cap=5, head=head), self.deque([]), pairs[3][0])
            self.assertEqual(got, 40)

    def test_deque_with_spare_capacity(self):
        pairs = [(key(i, i), i) for i in range(1, 4)]
        for head in range(7):
            self.assertEqual(self.both(self.deque(pairs, cap=7, head=head), self.deque([]), pairs[2][0]), 3)

    def test_tree_heights(self):
        pairs = [(key(i, i), i + 100) for i in range(1, 61)]
        for height, take in ((0, 11), (1, 30), (2, 60)):
            sub = pairs[:take]
            for probe in (sub[0][0], sub[take // 2][0], sub[-1][0], key(200)):
                box = self.tree(sub, height)
                expect = dict(box.pairs).get(probe, 0)
                self.assertEqual(self.both(box, self.deque([]), probe), expect)

    def test_empty_tree_root_counts_as_zero(self):
        self.assertEqual(self.both(self.tree([]), self.tree([]), key(4)), 0)

    def test_tree_probe_below_all_keys_and_above_all_keys(self):
        pairs = [(key(i, 1), i) for i in range(10, 20)]
        self.assertEqual(self.both(self.tree(pairs), self.deque([]), key(1)), 0)
        self.assertEqual(self.both(self.tree(pairs), self.deque([]), key(250)), 0)

    def test_flaw_wrap_is_caught(self):
        k = key(5)
        case = T.Box(first=self.deque([(k, U64)]), second=self.deque([(k, 2)]), key=k)
        got, _ = T.total_actual(IMAGE, case, T.START["total_a"])
        self.assertNotEqual(got, T.total_expected(case, "wrap"))


class Ring(unittest.TestCase):
    def search(self, pairs, probe, cap=None, head=0):
        box = T.Box(kind="deque", pairs=pairs, cap=cap or len(pairs), head=head)
        return T.ring_actual(IMAGE, T.Box(box=box, key=probe), T.START["ring_search"])[0], \
            T.ring_expected(T.Box(box=box, key=probe))

    def test_every_position_in_every_rotation(self):
        pairs = [(key(i * 3, 1), i) for i in range(1, 8)]
        for head in range(7):
            for probe in [p for p, _ in pairs] + [key(i, 1) for i in (1, 4, 7, 10, 13, 16, 19, 22, 30)]:
                got, want = self.search(pairs, probe, head=head)
                self.assertEqual(got, want, (head, probe[0]))

    def test_empty_ring(self):
        got, want = self.search([], key(1), cap=1)
        self.assertEqual((got, want), ((1, 0), (1, 0)))

    def test_single_row(self):
        for probe, expect in ((key(4), (1, 0)), (key(5), (0, 0)), (key(6), (1, 1))):
            got, want = self.search([(key(5), 1)], probe)
            self.assertEqual((got, want), (expect, expect))

    def test_comparison_uses_twenty_bytes_ordered_by_first_difference(self):
        a, b = bytes(19) + b"\x01", bytes(19) + b"\x02"
        got, want = self.search([(a, 1), (b, 2)], bytes(19) + b"\x01")
        self.assertEqual(got, (0, 0))
        got, want = self.search([(a, 1), (b, 2)], bytes(19) + b"\x03")
        self.assertEqual(got, (1, 2))

    def test_flaw_late_insertion_is_caught(self):
        box = T.Box(kind="deque", pairs=[(key(2), 1)], cap=1, head=0)
        got, _ = T.ring_actual(IMAGE, T.Box(box=box, key=key(9)), T.START["ring_search"])
        self.assertNotEqual(got, T.ring_expected(T.Box(box=box, key=key(9)), "late"))


class Controls(unittest.TestCase):
    def test_generators_are_deterministic(self):
        def snap(value):
            if hasattr(value, "__dict__"):
                return {k: snap(v) for k, v in sorted(vars(value).items())}
            if isinstance(value, (list, tuple)):
                return [snap(v) for v in value]
            return value

        for body, _ in T.BODIES:
            first = [snap(c) for c in T.cases(body, 20)]
            self.assertEqual(first, [snap(c) for c in T.cases(body, 20)])
            self.assertNotEqual(first[0], first[1])

    def test_every_spec_flaw_is_detected(self):
        for body, _ in T.BODIES:
            consts = T.body_consts(IMAGE, body)
            for flaw in T.FLAWS[body]:
                self.assertTrue(any(not T.attempt(IMAGE, body, c, consts, flaw) for c in T.cases(body, 600)), (body, flaw))

    def test_no_flaw_means_no_mismatch(self):
        for body, _ in T.BODIES:
            consts = T.body_consts(IMAGE, body)
            self.assertTrue(all(T.attempt(IMAGE, body, c, consts) for c in T.cases(body, 150)), body)

    def test_branch_flip_in_ring_search_is_detected(self):
        consts = T.body_consts(IMAGE, "ring_search")
        sites = T.mutation_sites(IMAGE, "ring_search")
        self.assertGreater(len(sites), 10)
        va, _, new = next(s for s in sites if s[1] == "jcc-flip")
        old = T.patch(IMAGE, va, bytes([new]))
        try:
            self.assertTrue(any(not T.attempt(IMAGE, "ring_search", c, consts) for c in T.cases("ring_search", T.BATTERY)))
        finally:
            T.patch(IMAGE, va, old)
        self.assertTrue(all(T.attempt(IMAGE, "ring_search", c, consts) for c in T.cases("ring_search", 20)))

    def test_every_site_mutant_is_detected_in_the_totals(self):
        consts = T.body_consts(IMAGE, "total_a")
        for va, kind, new in T.mutation_sites(IMAGE, "total_a"):
            old = T.patch(IMAGE, va, bytes([new]))
            try:
                hit = any(not T.attempt(IMAGE, "total_a", c, consts) for c in T.cases("total_a", T.BATTERY))
            finally:
                T.patch(IMAGE, va, old)
            self.assertTrue(hit, (hex(va), kind))

    def test_out_of_range_key_pointer_is_refused(self):
        case = T.make_lookup(T.Lcg(3), "map_get")
        while len(case.rows) < 2:
            case = T.make_lookup(T.Lcg(case.junk), "map_get")
        m = T.build_lookup_world(IMAGE, case, "map_get", T.START["map_get"])
        m.set_reg(T.RSI, 0x1234)
        with self.assertRaises((T.ToolError, T.cpu.ToolError, KeyError)):
            T.run(m, T.START["map_get"])

    def test_wrong_digest_refused(self):
        self.assertNotEqual(T.digest(b"damaged"), T.SHA256)


class Evidence(unittest.TestCase):
    def test_regeneration_is_byte_identical_to_committed_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = pathlib.Path(tmp) / "again"
            measure = T.generate(out)
            committed = sorted(p.name for p in FOLDER.iterdir() if p.name not in ("README.md", "MANIFEST.sha256"))
            self.assertEqual(sorted(p.name for p in out.iterdir()), committed)
            for name in committed:
                self.assertTrue(filecmp.cmp(out / name, FOLDER / name, shallow=False), name)
            self.assertEqual(measure["mismatches"], 0)
            self.assertEqual(measure["negative_controls"], measure["negative_detected"])
            self.assertGreaterEqual(measure["cases"], 10000)
            self.assertGreaterEqual(measure["negative_controls"], 30)

    def test_measure_json_matches_tables(self):
        measure = json.loads((FOLDER / "measure.json").read_text())
        flaws = (FOLDER / "spec-flaws.tsv").read_text().splitlines()[1:]
        mutants = (FOLDER / "mutants.tsv").read_text().splitlines()[1:]
        damage = (FOLDER / "damage.tsv").read_text().splitlines()[1:]
        self.assertEqual(measure["spec_flaws"], len(flaws))
        self.assertEqual(measure["mutants_killed"], sum(r.endswith("killed") for r in mutants))
        self.assertEqual(measure["damage_controls"], len(damage))
        self.assertEqual(measure["negative_controls"], measure["mutants_killed"] + len(flaws) + len(damage))
        self.assertTrue(all(r.endswith("detected") for r in flaws + damage))


if __name__ == "__main__":
    unittest.main()
