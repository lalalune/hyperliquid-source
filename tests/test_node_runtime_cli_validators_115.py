import hashlib
import random
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import node_runtime_cli_validators_115 as t  # noqa: E402

IMG = t.load()
FUNC_NAMES = ('u64', 'bool', 'ip')


def run(name, s, cap=0, patches=None, max_steps=20000):
    res, frees, ptr, steps = t.call_callback(IMG, name, s, cap, patches, max_steps)
    return t.classify(IMG, name, res), frees, ptr, steps


class IdentityTests(unittest.TestCase):
    def test_digest_pinned(self):
        self.assertEqual(hashlib.sha256(t.BINARY.read_bytes()).hexdigest(), t.SHA)

    def test_wrong_digest_refused(self):
        data = bytearray(t.BINARY.read_bytes())
        data[4096] ^= 1
        self.assertNotEqual(hashlib.sha256(bytes(data)).hexdigest(), t.SHA)

    def test_function_extents(self):
        ext = t.extents(IMG)
        self.assertLessEqual(ext[0x56544b0], 0x56546c0)
        self.assertLessEqual(ext[0x56546c0], 0x56547d0)
        self.assertLessEqual(ext[0x56547d0], 0x5654920)
        for va in t.FUNCS.values():
            self.assertIn(va, ext)
        self.assertEqual(ext[0x167ccb0] - 0x167ccb0, 978)

    def test_messages_are_the_rust_texts(self):
        self.assertEqual(IMG.read(*t.MSG['empty']), b'cannot parse integer from empty string')
        self.assertEqual(IMG.read(*t.MSG['digit']), b'invalid digit found in string')
        self.assertEqual(IMG.read(*t.MSG['big']), b'number too large to fit in target type')
        self.assertEqual(IMG.read(*t.MSG['bool']), b'provided string was not `true` or `false`')
        self.assertEqual(IMG.read(*t.IP_ERR), b'NodeIpParseError')

    def test_nobits_and_outside_addresses_rejected(self):
        with self.assertRaises(ValueError):
            IMG.read(0xffffffffff, 1)
        with self.assertRaises(ValueError):
            IMG.read(0x0, 1)


class U64Tests(unittest.TestCase):
    def test_known(self):
        table = {
            b'': ('err', 'empty'), b'+': ('err', 'digit'), b'-': ('err', 'digit'), b'0': ('ok',), b'+0': ('ok',),
            b'-0': ('err', 'digit'), b'-1': ('err', 'digit'), b'1 ': ('err', 'digit'), b' 1': ('err', 'digit'),
            b'18446744073709551615': ('ok',), b'+18446744073709551615': ('ok',),
            b'18446744073709551616': ('err', 'big'), b'18446744073709551620': ('err', 'big'),
            b'99999999999999999999': ('err', 'big'), b'184467440737095516150': ('err', 'big'),
            b'0000000000000000000018446744073709551615': ('ok',), b'1' + b'0' * 20: ('err', 'big'),
            b'18446744073709551616a': ('err', 'big'), b'184467440737095516150a': ('err', 'big'), b'9999999999999999999x': ('err', 'digit'),
            b'1234567890123456': ('ok',), b'12345678901234567': ('ok',), b'1234567890123456a': ('err', 'digit'),
        }
        for s, want in table.items():
            self.assertEqual(run('u64', s)[0], want, s)

    def test_model_agrees_with_replay_on_generated_cases(self):
        total, bad, hist = t.compare(IMG, 'u64', t.model_u64, t.u64_cases(random.Random(5), 600))
        self.assertEqual((total, bad), (600, 0))
        self.assertEqual(set(hist), {'empty', 'digit', 'ok', 'big'})

    def test_input_buffer_released_only_when_capacity_nonzero(self):
        res, frees, ptr, _ = run('u64', b'12', cap=0)
        self.assertEqual(frees, [])
        res, frees, ptr, _ = run('u64', b'12', cap=48)
        self.assertEqual(frees, [(ptr, 48, 0)])
        res, frees, ptr, _ = run('u64', b'zz', cap=7)
        self.assertEqual(frees, [(ptr, 7, 0)])

    def test_short_and_long_paths_differ_only_after_sixteen_digits(self):
        self.assertEqual(run('u64', b'9' * 16)[0], ('ok',))
        self.assertEqual(run('u64', b'9' * 20)[0], ('err', 'big'))
        self.assertEqual(run('u64', b'9' * 15 + b'x')[0], ('err', 'digit'))
        # the multiply-overflow branch classifies the byte that was already loaded
        self.assertEqual(run('u64', b'1844674407370955162' + b'0')[0], ('err', 'big'))
        self.assertEqual(run('u64', b'18446744073709551620' + b'x')[0], ('err', 'big'))
        self.assertEqual(run('u64', b'9999999999999999999x')[0], ('err', 'digit'))
        self.assertEqual(run('u64', b'99999999999999999990x')[0], ('err', 'big'))

    def test_wrong_models_detected(self):
        for name, label, wrong in t.wrong_models():
            if name != 'u64':
                continue
            total, bad, _ = t.compare(IMG, name, wrong, t.GENS[name](random.Random(8), 900), stop_on_diff=True)
            self.assertGreater(bad, 0, label)


class BoolTests(unittest.TestCase):
    def test_exact_lowercase_only(self):
        for s in (b'true', b'false'):
            self.assertEqual(run('bool', s)[0], ('ok',))
        for s in (b'', b'True', b'FALSE', b'tru', b'truee', b'fals', b'falsee', b'1', b'0', b'true ', b'fa\x00se'):
            self.assertEqual(run('bool', s)[0], ('err', 'bool'), s)

    def test_all_single_byte_mutations_of_both_words(self):
        for word in (b'true', b'false'):
            for i in range(len(word)):
                for v in (0, 0x20, 0x41, 0x7f, 0xff, word[i] ^ 0x20, word[i] + 1):
                    s = bytearray(word)
                    s[i] = v & 255
                    s = bytes(s)
                    want = ('ok',) if s in (b'true', b'false') else ('err', 'bool')
                    self.assertEqual(run('bool', s)[0], want, s)

    def test_release_rule(self):
        _, frees, ptr, _ = run('bool', b'true', cap=9)
        self.assertEqual(frees, [(ptr, 9, 0)])
        _, frees, ptr, _ = run('bool', b'nope', cap=0)
        self.assertEqual(frees, [])

    def test_wrong_models_detected(self):
        for name, label, wrong in t.wrong_models():
            if name == 'bool':
                total, bad, _ = t.compare(IMG, name, wrong, t.GENS[name](random.Random(9), 900), stop_on_diff=True)
                self.assertGreater(bad, 0, label)


class IpTests(unittest.TestCase):
    def test_known(self):
        good = [b'0.0.0.0', b'255.255.255.255', b'127.0.0.1', b'1.2.3.4', b'100.100.100.100', b'10.0.0.10']
        bad = [b'', b'1.2.3', b'1.2.3.4.5', b'01.2.3.4', b'1.2.3.04', b'0.0.0.00', b'256.1.1.1', b'1.2.3.4 ',
               b' 1.2.3.4', b'1.2.3.', b'.1.2.3', b'1..2.3', b'+1.2.3.4', b'1.2.3.-4', b'255.255.255.2555',
               b'1111.1.1.1', b'255.255.255.255.', b'::1', b'1.2.3.4/32']
        for s in good:
            self.assertEqual(run('ip', s)[0], ('ok',), s)
        for s in bad:
            self.assertEqual(run('ip', s)[0], ('err', 'ip'), s)

    def test_error_value_is_fixed_sixteen_byte_text(self):
        res, frees, ptr, _ = t.call_callback(IMG, 'ip', b'bad', 0)
        self.assertEqual(res, ('err', 16, 16, b'NodeIpParseError'))

    def test_length_gate_before_the_reader(self):
        # sixteen bytes never reach the reader, so no reader instruction runs
        _, _, _, short_steps = run('ip', b'1' * 16)
        _, _, _, reader_steps = run('ip', b'1' * 15)
        self.assertLess(short_steps, reader_steps)

    def test_model_agrees_with_replay(self):
        total, bad, hist = t.compare(IMG, 'ip', t.model_ip, t.ip_cases(random.Random(6), 500))
        self.assertEqual((total, bad), (500, 0))
        self.assertEqual(set(hist), {'ip', 'ok'})

    def test_release_on_both_outcomes(self):
        for s in (b'1.2.3.4', b'x'):
            _, frees, ptr, _ = run('ip', s, cap=64)
            self.assertEqual(frees, [(ptr, 64, 0)])

    def test_wrong_models_detected(self):
        for name, label, wrong in t.wrong_models():
            if name == 'ip':
                total, bad, _ = t.compare(IMG, name, wrong, t.GENS[name](random.Random(10), 900), stop_on_diff=True)
                self.assertGreater(bad, 0, label)


class ByteDamageTests(unittest.TestCase):
    def test_every_listed_mutation_changes_behaviour(self):
        for label, name, patch in t.byte_mutations(IMG):
            total, bad, _ = t.compare(IMG, name, t.model_dispatch(name), t.GENS[name](random.Random(11), 900), patch,
                                      stop_on_diff=True)
            self.assertGreater(bad, 0, label)

    def test_unmutated_bytes_have_no_difference(self):
        for name in FUNC_NAMES:
            total, bad, _ = t.compare(IMG, name, t.model_dispatch(name), t.GENS[name](random.Random(12), 200))
            self.assertEqual(bad, 0, name)

    def test_unknown_opcode_and_spin_are_refused(self):
        for label, fn in t.damage_cases(IMG):
            with self.assertRaises((t.Unsupported, ValueError), msg=label):
                fn()

    def test_indirect_call_requires_relative_slot(self):
        patch = {0x56544b0: 0xff, 0x56544b1: 0x15, 0x56544b2: 0, 0x56544b3: 0, 0x56544b4: 0, 0x56544b5: 0}
        with self.assertRaises((t.Unsupported, ValueError)):
            t.call_callback(IMG, 'u64', b'1', 0, patch)


class AddressWrapperTests(unittest.TestCase):
    def test_validator_error_order_and_tag(self):
        res, ev, frees, ptr = t.call_wrapper(IMG, 'addr_val', b'zz', 24, True, b'bad', 0)
        self.assertEqual(res, ('err', True, b'bad'))
        self.assertEqual(ev, [('parse', 2), ('vdrop', True), ('fmt', 0xb3), ('dropres', 0xb3)])
        self.assertEqual(frees, [(ptr, 24, 0)])

    def test_signer_error_order(self):
        res, ev, frees, ptr = t.call_wrapper(IMG, 'addr_sig', b'zz', 0, True, b'', 0)
        self.assertEqual(res, ('err', True, b''))
        self.assertEqual(ev, [('parse', 2), ('fmt', True), ('vdrop', True)])
        self.assertEqual(frees, [])

    def test_ok_path_does_not_touch_error_objects(self):
        for name in ('addr_val', 'addr_sig'):
            res, ev, frees, ptr = t.call_wrapper(IMG, name, b'q', 8, False, b'unused', 0)
            self.assertEqual((res, ev, frees), (('ok',), [('parse', 1)], [(ptr, 8, 0)]))

    def test_format_failure_reaches_the_panic_path(self):
        for name in ('addr_val', 'addr_sig'):
            with self.assertRaises(t.Unsupported):
                t.call_wrapper(IMG, name, b'q', 0, True, b'x', 1)

    def test_generated_cases_match_model(self):
        for name in ('addr_val', 'addr_sig'):
            self.assertEqual(t.compare_wrapper(IMG, name, 300, 3), (300, 0))

    def test_wrong_models_and_byte_damage_detected(self):
        for name, label, wrong in t.wrapper_wrong_models():
            self.assertGreater(t.compare_wrapper(IMG, name, 400, 4, stop_on_diff=True, model=wrong)[1], 0, label)
        for label, name, patch in t.wrapper_mutations():
            self.assertGreater(t.compare_wrapper(IMG, name, 400, 5, patch, stop_on_diff=True)[1], 0, label)


class EmulatorTests(unittest.TestCase):
    def test_flags_for_sub_and_add(self):
        e = t.Emu(IMG)
        self.assertEqual(e.alu(5, 1, 2, 8), M64_MINUS_1)
        self.assertEqual((e.cf, e.zf, e.sf, e.of), (1, 0, 1, 0))
        self.assertEqual(e.alu(0, M64_MINUS_1, 1, 8), 0)
        self.assertEqual((e.cf, e.zf), (1, 1))
        self.assertEqual(e.alu(5, 0x80, 1, 1), 0x7f)
        self.assertEqual(e.of, 1)

    def test_register_widths(self):
        e = t.Emu(IMG)
        e.regs[0] = t.M64
        e.setr(0, 4, 0, 5)
        self.assertEqual(e.regs[0], 5)
        e.setr(0, 1, 0, 0xff)
        self.assertEqual(e.regs[0], 0xff)
        e.setr(4, 1, 0, 0x12)  # ah without a REX prefix
        self.assertEqual(e.regs[0], 0x12ff)
        self.assertEqual(e.getr(4, 1, 0), 0x12)

    def test_condition_table_has_sixteen_codes(self):
        self.assertEqual(sorted(t.COND), list(range(16)))

    def test_stub_pad_writes_message_into_string(self):
        res, frees, ptr, _ = t.call_callback(IMG, 'bool', b'x', 0)
        self.assertEqual(res[3], IMG.read(*t.MSG['bool']))


M64_MINUS_1 = t.M64

if __name__ == '__main__':
    unittest.main()
