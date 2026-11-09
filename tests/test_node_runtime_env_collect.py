from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import node_runtime_env_collect as t  # noqa: E402

BINARY = Path(__file__).resolve().parents[1] / 'artifacts' / 'node' / '115' / 'hl-node'


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = t.load_node(BINARY)
        cls.image = t.Image(cls.data)
        cls.extents = t.function_extents(cls.data)


class DecodeTests(Base):
    def test_extents_come_from_fde_records(self):
        self.assertEqual(self.extents, {t.ARGV_FN: 0x5c9a709, t.ENV_FN: 0x5c9abac})

    def test_decode_tiles_both_functions_exactly(self):
        counts = {}
        for start, end in self.extents.items():
            rows = t.disassemble(self.image, start, end)
            counts[start] = len(rows)
            self.assertEqual(rows[0][0], start)
            self.assertEqual(sum(r[1] for r in rows), end - start)
        self.assertEqual(counts, {t.ARGV_FN: 132, t.ENV_FN: 279})

    def test_prologues_are_frame_setup(self):
        for start in (t.ARGV_FN, t.ENV_FN):
            self.assertEqual(self.image.read(start, 4), bytes.fromhex('554889e5'))

    def test_unknown_opcode_is_refused(self):
        patched = t.Image(self.data, {t.ARGV_FN: 0x06})
        with self.assertRaises(t.EmuError):
            t.fetch(patched, t.ARGV_FN)

    def test_slots_are_zero_in_file_and_named(self):
        # call slots are filled by relocation at load time; the file holds no pointer there
        for slot in t.SLOTS:
            self.assertEqual(self.image.read(slot, 8), bytes(8))


class EnvironTests(Base):
    def run_case(self, strings, offsets=None, lock=0):
        offsets = offsets or [0] * len(strings)
        got = t.view_env(t.run_env(self.image, strings, offsets, lock))
        self.assertEqual(got, t.expected_env(strings, lock))
        return got

    def test_plain_pairs(self):
        got = self.run_case([b'HOME=/x', b'A=', b'B=c=d'])
        self.assertEqual([(k, v) for _, k, v in got[1]], [(b'HOME', b'/x'), (b'A', b''), (b'B', b'c=d')])

    def test_leading_equals_belongs_to_key(self):
        got = self.run_case([b'=C:=\\w', b'=', b'==', b'=a'])
        self.assertEqual([(k, v) for _, k, v in got[1]], [(b'=C:', b'\\w'), (b'=', b'')])

    def test_entries_without_equals_or_empty_are_skipped(self):
        self.assertEqual(self.run_case([b'', b'X', b'YY', b'k=v'])[1], ((True, b'k', b'v'),))

    def test_every_equals_position_across_length_and_alignment(self):
        for n in (2, 8, 9, 16, 17, 18, 31, 32, 33, 48):
            for pos in range(1, n):
                for off in (0, 1, 5):
                    s = bytearray(b'k' * n)
                    s[pos] = 0x3d
                    self.run_case([bytes(s)], [off])

    def test_high_bit_bytes_do_not_fake_an_equals(self):
        for bad in (0xbd, 0x3c, 0x3e, 0xff, 0x80):
            self.run_case([b'a' * 20 + bytes([bad]) * 20 + b'=v'], [3])

    def test_lock_fast_and_slow_paths(self):
        fast = t.run_env(self.image, [b'a=b'], [0], 5)
        self.assertEqual((fast[3], fast[4]), (5, ()))
        slow = t.run_env(self.image, [b'a=b'], [0], 0x3ffffffe)
        self.assertEqual((slow[3], slow[4]), (0x3ffffffe, (('read_contended',),)))
        wake = t.run_env(self.image, [b'a=b'], [0], 0x80000000)
        self.assertEqual(wake[4], (('read_contended',), ('wake',)))
        waiting = t.run_env(self.image, [b'a=b'], [0], 0x40000000)
        self.assertEqual(waiting[4], (('read_contended',),))

    def test_allocation_failure_reports_the_failing_size(self):
        strings = [b'KEY=value', b'Z=']
        for k in range(3):
            got = t.run_env(self.image, strings, [0, 0], 0, alloc_fail={k})
            self.assertEqual(got[:3], t.expected_env_alloc_failure(strings, k))
        self.assertEqual(t.expected_env_alloc_failure(strings, 0), ('trap', 'alloc_error', (1, 3)))
        self.assertEqual(t.expected_env_alloc_failure(strings, 1), ('trap', 'alloc_error', (1, 5)))

    def test_many_entries_grow_the_result(self):
        strings = [b'K%d=v%d' % (i, i) for i in range(23)]
        got = t.run_env(self.image, strings, [0] * 23)
        self.assertEqual(len(got[2]), 23)
        self.assertTrue(got[5])

    def test_generated_cases_agree(self):
        for strings, offsets, lock in t.env_cases(120, seed=99):
            self.run_case(strings, offsets, lock)


class ArgvTests(Base):
    def test_basic(self):
        self.assertEqual(t.run_argv(self.image, 3, [b'node', b'', b'--x']), t.spec_argv(3, [b'node', b'', b'--x']))

    def test_null_pointer_ends_collection_and_cap_is_argc(self):
        got = t.run_argv(self.image, 4, [b'a', b'b', b'c'], null_at=1)
        self.assertEqual(got, ('ok', 4, ((True, b'a'),)))

    def test_missing_argv_and_zero_argc_give_empty_result(self):
        self.assertEqual(t.run_argv(self.image, 2, [b'a'], argv_null=True), ('ok', 0, ()))
        self.assertEqual(t.run_argv(self.image, 0, []), ('ok', 0, ()))

    def test_allocation_failure(self):
        for k, want in enumerate([(8, 48), (1, 3), (1, 2)]):
            got = t.run_argv(self.image, 2, [b'abc', b'de'], alloc_fail={k})
            self.assertEqual(got, ('trap', 'alloc_error', want))
            self.assertEqual(got, t.expected_argv_alloc_failure(2, [b'abc', b'de'], None, k))

    def test_generated_cases_agree(self):
        for argc, args, null_at, argv_null in t.argv_cases(120):
            self.assertEqual(t.run_argv(self.image, argc, args, null_at, argv_null=argv_null),
                             t.spec_argv(argc, args, null_at, argv_null))


class NegativeControlTests(Base):
    def test_spec_mutants_are_detected(self):
        for name in t.SPEC_MUTANTS:
            seen = False
            for strings, _, lock in t.env_cases(400, seed=5):
                alt = t.spec_env(strings, lock, t.mutate_split(name))
                if tuple((True, k, v) for k, v in alt[0]) != t.expected_env(strings, lock)[1]:
                    seen = True
                    break
            self.assertTrue(seen, name)

    def test_byte_mutants_change_behaviour(self):
        cases = t.mutant_battery()
        base = t.normalise_battery(t.run_battery(self.image, cases))
        self.assertEqual(base, t.normalise_battery(t.expected_battery(cases)))
        for name, va, old, new in t.BYTE_MUTANTS:
            self.assertEqual(self.image.byte(va), old, name)
            mutated = t.Image(self.data, {va: new})
            self.assertNotEqual(t.normalise_battery(t.run_battery(mutated, cases)), base, name)

    def test_invalid_controls_all_raise(self):
        for name, fn in t.invalid_controls(self.data, self.image):
            with self.assertRaises((ValueError, t.EmuError, t.Trap, KeyError), msg=name):
                fn()

    def test_wrong_digest_is_refused(self):
        with self.assertRaises(ValueError):
            t.check_node(self.data[:-1] + bytes([self.data[-1] ^ 1]))

    def test_step_limit_stops_runaway_code(self):
        looping = t.Image(self.data, {t.ARGV_FN: 0xeb, t.ARGV_FN + 1: 0xfe})
        with self.assertRaises(t.EmuError):
            t.Cpu(looping).run(t.ARGV_FN)


if __name__ == '__main__':
    unittest.main()
