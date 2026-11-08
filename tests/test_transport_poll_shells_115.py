import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import transport_poll_shells_115 as t  # noqa: E402


class PollShellTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = t.TARGET.read_bytes()
        t.authenticate(cls.data)
        cls.image = t.Image(cls.data)

    def test_authentication_rejects_changed_or_short_input(self):
        bad = bytearray(self.data)
        bad[12345] ^= 0x40
        with self.assertRaises(ValueError):
            t.authenticate(bytes(bad))
        with self.assertRaises(ValueError):
            t.authenticate(self.data[:-5])

    def test_function_extents_end_in_int3_padding(self):
        fdes = {f['start']: f for f in t.fde_extents.fde_extents(self.data)[1]}
        for start in t.FUNCTIONS:
            fde = fdes[start]
            self.assertEqual(set(self.image.read(fde['end'], fde['next_index_upper_bound'] - fde['end'])), {0xcc})

    def test_both_functions_decode_to_their_boundary(self):
        fdes = {f['start']: f for f in t.fde_extents.fde_extents(self.data)[1]}
        for start in t.FUNCTIONS:
            length = fdes[start]['end'] - start
            listing = t.disassemble(self.image, start, length)
            self.assertEqual(sum(i.length for i in listing), length)
            self.assertEqual(listing[-1].op, 'callm' if start == t.GATE else 'call')

    def test_decoder_known_bytes(self):
        ins = t.decode(bytes.fromhex('66 41 83 f8 fe') + b'\0' * 11, 0x1000)
        self.assertEqual((ins.op, ins.size, ins.b), ('cmp', 2, ('i', 0xfffe)))
        ins = t.decode(bytes.fromhex('72 7c') + b'\0' * 14, 0x1000)
        self.assertEqual((ins.op, ins.a[1]), ('jb', 0x1000 + 2 + 0x7c))
        with self.assertRaises(ValueError):
            t.decode(bytes.fromhex('0f 05') + b'\0' * 14, 0x1000)

    def test_jump_tables_have_four_states(self):
        for start, table, targets, size in ((t.WRITE_ALL, 0x939fd8, 0x5ab3a72, 305), (t.GATE, 0x93a0f8, 0x5ab6d02, 267)):
            got = t.jump_table(self.image, table, start, start + size)
            self.assertEqual(len(got), 4)
            self.assertEqual(got[0], targets)

    def test_reconstruction_matches_bytes(self):
        cache = {}
        for function in t.FUNCTIONS:
            for index, case in t.case_stream(function, 400):
                self.assertEqual(t.run_original(self.image, case, cache), t.run_model(case), (function, index))

    def test_gate_predicate_boundaries(self):
        def flag(n, field):
            case = t.gate_case(t.Rng(3))
            case['state'] = 0
            t.put_bytes(case['mem'], t.BASE + 0x310, 1, 0)
            t.put_bytes(case['mem'], t.BASE + 0x20, 8, n)
            t.put_bytes(case['mem'], t.CTX + 0x90, 4, field)
            obs = t.run_original(self.image, case, {})
            return dict(obs[3])[t.BASE + 0x308]
        self.assertEqual(flag(0x401, 0), 1)
        self.assertEqual(flag(0x400, 0), 0)
        self.assertEqual(flag(0x401, 3998), 0)
        self.assertEqual(flag(0x401, 3999), 0)
        self.assertEqual(flag(0x401, 4000), 1)
        self.assertEqual(flag(0x401, 0x10000 + 3998), 0)
        self.assertEqual(flag(1 << 63, 3997), 1)

    def test_write_zero_error_path(self):
        case = t.write_case(t.Rng(1))
        t.put_bytes(case['mem'], t.BASE + 0x40, 1, 3)
        t.put_bytes(case['mem'], t.BASE + 0x28, 8, 10)
        t.put_bytes(case['mem'], t.BASE + 0x30, 8, 4)
        case['steps'] = [(0, 0, 0)]
        obs = t.run_original(self.image, case, {})
        self.assertEqual(obs[1], 1)
        self.assertEqual(obs[2], t.convert_error(t.const_error(0x25, t.MSG_ZERO, 9)))
        self.assertEqual(dict(obs[3])[t.BASE + 0x40], 1)

    def test_pending_keeps_cursor_and_sets_state_three(self):
        case = t.write_case(t.Rng(2))
        t.put_bytes(case['mem'], t.BASE + 0x40, 1, 3)
        t.put_bytes(case['mem'], t.BASE + 0x28, 8, 10)
        t.put_bytes(case['mem'], t.BASE + 0x30, 8, 4)
        case['steps'] = [(1, 0, 0)]
        obs = t.run_original(self.image, case, {})
        self.assertEqual(obs[1], 2)
        self.assertEqual(dict(obs[3])[t.BASE + 0x40], 3)
        self.assertEqual(dict(obs[3])[t.BASE + 0x30], 4)

    def test_negative_controls_are_detected(self):
        for function, mutation in ((t.WRITE_ALL, 'no-counter'), (t.GATE, 'threshold'), (t.GATE, 'bound')):
            at = t.first_difference(function, 600, lambda c: t.run_original(self.image, c, {}),
                                    lambda c, m=mutation: t.run_model(c, m))
            self.assertGreaterEqual(at, 0, mutation)
        self.assertEqual(t.first_difference(t.GATE, 200, lambda c: t.run_original(self.image, c, {}), t.run_model), -1)

    def test_corrupted_bytes_and_bad_states_are_detected(self):
        broken = t.Image(self.data)
        broken.patch[0x5ab3ab6] = 0x73
        at = t.first_difference(t.WRITE_ALL, 600, lambda c: t.run_original(broken, c, {}), t.run_model)
        self.assertGreaterEqual(at, 0)
        case = t.write_case(t.Rng(4))
        case['state'] = 4
        with self.assertRaises(ValueError):
            t.validate_case(case)
        missing = t.write_case(t.Rng(5))
        missing['mem'] = {a: v for a, v in missing['mem'].items() if a < t.BASE + 0x40}
        put = dict(missing['mem'])
        put[t.BASE + 0x40] = 0
        missing['mem'] = put
        self.assertTrue(t.run_original(self.image, missing, {})[0].startswith('unmapped'))

    def test_landing_pads_store_state_two_and_resume(self):
        rng = t.Rng(21)
        for function, pad, drop in t.PADS:
            case = t.pad_case(function, pad, drop, rng)
            obs = t.run_pad_original(self.image, case, {})
            self.assertEqual(obs[0], 'resume')
            self.assertEqual(dict(obs[3])[t.BASE + t.STATE_AT[function]], 2)
            self.assertEqual(obs[4][-1], ('unwind_resume', case['exc']))
            self.assertEqual(obs[4][0] == ('inner_drop', t.BASE + 0x28), drop)
            self.assertEqual(obs, t.run_pad_model(case))

    def test_gate_state_three_repolls_without_recopying(self):
        case = t.gate_case(t.Rng(8))
        t.put_bytes(case['mem'], t.BASE + 0x310, 1, 3)
        case['inner'] = (1, 0x77)
        before = dict(case['mem'])
        obs = t.run_original(self.image, case, {})
        self.assertEqual((obs[0], obs[1], obs[2]), ('ret', 1, 0x77))
        self.assertEqual(dict(obs[3]), before)
        case['inner'] = (0, 0x55)
        obs = t.run_original(self.image, case, {})
        self.assertEqual((obs[1], obs[2], dict(obs[3])[t.BASE + 0x310]), (0, 0x55, 1))
        self.assertEqual([e[0] for e in obs[4]], ['inner_poll', 'inner_drop'])

    def test_first_poll_adds_length_to_shared_counter_once(self):
        case = t.write_case(t.Rng(6))
        t.put_bytes(case['mem'], t.BASE + 0x40, 1, 0)
        t.put_bytes(case['mem'], t.BASE + 0x10, 8, 100)
        t.put_bytes(case['mem'], t.COUNTER + 0x10, 8, 5)
        case['steps'] = [(1, 0, 0)]
        obs = t.run_original(self.image, case, {})
        mem = dict(obs[3])
        counter = sum(mem[t.COUNTER + 0x10 + i] << (8 * i) for i in range(8))
        self.assertEqual(counter, 105)
        self.assertEqual((obs[1], mem[t.BASE + 0x40]), (2, 3))
        self.assertEqual([e[0] for e in obs[4]], ['cursor_write'])

    def test_rng_is_stable_across_processes(self):
        r = t.Rng(1)
        self.assertEqual([r.next() for _ in range(3)],
                         [1082269761, 1152992998833853505, 11177516664432764457])

    def test_generation_is_deterministic_and_complete(self):
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            result = t.run()
            names = t.emit(Path(a), result)
            t.emit(Path(b), result)
            for name in names:
                self.assertEqual((Path(a) / name).read_bytes(), (Path(b) / name).read_bytes())
            measure = json.loads((Path(a) / 'measure.json').read_text())
            self.assertEqual(measure['cases'], 2 * t.CASES_PER_FUNCTION + t.PAD_CASES * len(t.PADS))
            self.assertEqual(measure['negative_detected'], measure['negative_controls'])
            self.assertGreaterEqual(measure['negative_controls'], 30)
            self.assertEqual(result['mismatches'], 0)


if __name__ == '__main__':
    unittest.main()
