"""Controls for tools/spot_wei_scale.py (RE-004, node #94)."""

import filecmp
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from gnu_binutils import requires_gnu  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / 'tools' / 'spot_wei_scale.py'
PACKET = ROOT / 'research' / 'work-items' / 'RE-004-spot-wei-scale-family-94'

spec = importlib.util.spec_from_file_location('spot_wei_scale', TOOL)
sws = importlib.util.module_from_spec(spec)
sys.modules['spot_wei_scale'] = sws
spec.loader.exec_module(sws)

BINARY = ROOT / sws.BINARY
HELPERS = {h[0]: h for h in sws.HELPERS}


def listing(entry, end):
    return sws.parse_listing(sws.disassemble(BINARY, entry, end))


def mutate(insns, va, mnemonic=None, ops=None):
    out = []
    for ins in insns:
        if ins[0] == va:
            ins = (ins[0], mnemonic or ins[1], ops if ops is not None else ins[2], ins[3])
        out.append(ins)
    return out


def find(insns, mn, pred=lambda ins: True):
    return next(ins for ins in insns if ins[1] == mn and pred(ins))


CACHE = {}


@requires_gnu('objdump')
class Fixture(unittest.TestCase):
    def set_up_class(cls):
        if not CACHE:
            data = BINARY.read_bytes()
            CACHE['data'] = data
            CACHE['analysis'] = sws.analyse(BINARY, data)
        cls.data = CACHE['data']
        cls.result, cls.exponents, cls.byte_dump = CACHE['analysis']
        cls.img = sws.Image(cls.data)
        cls.scale_loc = int(cls.result['locations']['scale_unwrap']['va'], 16)
        cls.token_loc = int(cls.result['locations']['token_index']['va'], 16)
        cls.panics = {cls.scale_loc, cls.token_loc}
        cls.spec_fn = listing(0x3760790, 0x376081c)

    setUpClass = classmethod(set_up_class)

    def ladder(self, insns):
        machine = sws.Machine(insns, self.panics, sws.UDIVTI3_SLOT, default_mem=0)
        lads = sws.find_ladders(insns, self.scale_loc)
        self.assertEqual(len(lads), 1)
        return machine, lads[0]

    def helper_mismatch(self, name, end, change):
        helper = HELPERS[name]
        insns = change(listing(helper[1], end))
        machine = sws.Machine(insns, self.panics, sws.UDIVTI3_SLOT)
        return sws.check_helper(machine, helper, stop_at_first=True)['mismatch']


class Results(Fixture):
    def test_counts(self):
        s = self.result['summary']
        self.assertEqual(s['scale_location_lea_sites'], 15)
        self.assertEqual(s['holder_functions'], 15)
        self.assertEqual(s['ladders_evaluated'], 15)
        self.assertEqual(s['ladder_mismatches'], 0)
        self.assertEqual(s['distinct_pow_tables'], 1)
        self.assertEqual((s['exponents_admitted'], s['exponent_max']), (20, 19))
        self.assertEqual(s['all_pairs_mismatch_on_spec_scale'], 0)
        self.assertEqual(s['helpers_modelled'], 12)
        self.assertEqual(s['helper_mismatches'], 0)
        self.assertEqual((s['token_bound_helpers'], s['token_bound_at_location']), (7, 7))

    def test_exponent_table(self):
        for e in self.exponents:
            if e['k'] < 20:
                self.assertEqual(e['value'], 10 ** e['k'])
            else:
                self.assertIsNone(e['value'])

    def test_panic_message_is_unwrap(self):
        self.assertEqual(self.result['panic']['message'], sws.UNWRAP_MESSAGE.decode())
        self.assertEqual(self.result['panic']['message_length'], 43)

    def test_divergence_direction(self):
        d = self.result['reference_lead_divergence']
        self.assertGreater(d['binary_below_lead'], 0)
        self.assertEqual(d['binary_above_lead'], 0)
        self.assertEqual(d['binary_none_lead_some'], 0)
        first = d['examples'][0]
        self.assertEqual(first['binary'], 10 ** 17)
        self.assertEqual(first['lead'], 10 ** 17 + 99900)

    def test_no_at_sign_in_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            sws.write(Path(tmp), self.result, self.exponents, self.byte_dump)
            for path in Path(tmp).iterdir():
                self.assertNotIn(chr(64), path.read_text())

    def test_regeneration_is_byte_identical(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            sws.write(out, self.result, self.exponents, self.byte_dump)
            names = sorted(p.name for p in out.iterdir())
            self.assertEqual(names, ['evidence.json', 'helper-bytes.txt', 'helpers.tsv', 'holders.tsv',
                                     'pow10-exponents.tsv'])
            match, mismatch, errors = filecmp.cmpfiles(out, PACKET, names, shallow=False)
            self.assertEqual((sorted(match), mismatch, errors), (names, [], []))


class InputControls(Fixture):
    def test_digest_rejects_flipped_byte(self):
        bad = bytearray(self.data[:4096])
        with self.assertRaises(sws.EvidenceError):
            sws.check_digest(bytes(bad))
        with self.assertRaises(sws.EvidenceError):
            sws.check_digest(self.data[:-1])

    def test_elf_magic_rejected(self):
        with self.assertRaises(sws.EvidenceError):
            sws.sections(b'\0' * 256)

    def test_va_outside_sections_rejected(self):
        with self.assertRaises(sws.EvidenceError):
            self.img.read(0x7fffffff0000, 8)

    def test_fde_lookup_rejects_address_before_table(self):
        with self.assertRaises(sws.EvidenceError):
            sws.Fdes(self.img).range_of(0x10)

    def test_panic_stub_shape_enforced(self):
        with self.assertRaises(sws.EvidenceError):
            sws.panic_message(self.img, 0x3760790)

    def test_call_slot_requires_indirect_call(self):
        with self.assertRaises(sws.EvidenceError):
            sws.call_slot_target(self.img, {}, 0x3760790)

    def test_lea_scan_exact_target(self):
        # lea rdi,[rip+0x10] at VA 0x1000 loads 0x1017
        code = b'\x48\x8d\x3d\x10\x00\x00\x00'
        self.assertEqual(sws.lea_rip_refs(0x1000, code, 0x1017), [0x1000])
        self.assertEqual(sws.lea_rip_refs(0x1000, code, 0x1018), [])


class LadderControls(Fixture):
    def bad_count(self, insns):
        _, lad = self.ladder(self.spec_fn)      # anchors from the unchanged listing
        machine = sws.Machine(insns, self.panics, sws.UDIVTI3_SLOT, default_mem=0)
        return len(sws.check_ladder(machine, lad)[1])

    def test_unchanged_is_clean(self):
        self.assertEqual(self.bad_count(self.spec_fn), 0)

    def test_corrupted_step_constant(self):
        ins = find(self.spec_fn, 'imul', lambda i: i[2][2] == ('i', 0x2710))
        changed = mutate(self.spec_fn, ins[0], ops=(ins[2][0], ins[2][1], ('i', 0x2711)))
        self.assertGreater(self.bad_count(changed), 0)

    def test_inverted_borrow_branch(self):
        ins = find(self.spec_fn, 'jb')
        changed = mutate(self.spec_fn, ins[0], 'jae')
        self.assertGreater(self.bad_count(changed), 0)
        self.assertEqual(sws.find_ladders(changed, self.scale_loc), [])

    def test_overflow_branch_removed(self):
        ins = find(self.spec_fn, 'jo')
        self.assertGreater(self.bad_count(mutate(self.spec_fn, ins[0], 'jno')), 0)

    def test_high_exponent_mask_changed(self):
        ins = find(self.spec_fn, 'and', lambda i: i[2][1] == ('i', 0xfffffff0))
        changed = mutate(self.spec_fn, ins[0], ops=(ins[2][0], ('i', 0xffffff10)))
        self.assertGreater(self.bad_count(changed), 0)

    def test_off_by_one_model_detected(self):
        machine, lad = self.ladder(self.spec_fn)
        table, _ = sws.check_ladder(machine, lad)
        self.assertIsNone(table[20])
        self.assertEqual(table[19], 10 ** 19)
        self.assertIsNone(sws.pow10_model(0, 20))
        self.assertNotEqual(table[18], 10 ** 19)


class HelperControls(Fixture):
    def test_fallback_overflow_flag_inverted(self):
        def change(insns):
            ins = find(insns, 'setno')
            return mutate(insns, ins[0], 'seto')
        self.assertGreater(self.helper_mismatch('mul_div_token', 0x32815ef, change), 0)

    def test_round_up_flag_inverted(self):
        def change(insns):
            ins = find(insns, 'setne')
            return mutate(insns, ins[0], 'sete')
        self.assertGreater(self.helper_mismatch('ratio_round', 0x333e441, change), 0)

    def test_hundred_divisor_changed(self):
        def change(insns):
            ins = find(insns, 'mov', lambda i: i[2][1] == ('i', 0x64))
            return mutate(insns, ins[0], ops=(ins[2][0], ('i', 0x65)))
        self.assertGreater(self.helper_mismatch('ntl_ratio_capped', 0x3281767, change), 0)

    def test_clamp_direction_changed(self):
        def change(insns):
            ins = find(insns, 'cmovb')
            return mutate(insns, ins[0], 'cmovae')
        self.assertGreater(self.helper_mismatch('max_sz_for_px', 0x327fa32, change), 0)

    def test_floor_one_removed(self):
        def change(insns):
            ins = find(insns, 'mov', lambda i: i[2][1] == ('i', 1) and i[2][0][3] == 'eax')
            return mutate(insns, ins[0], ops=(ins[2][0], ('i', 2)))
        self.assertGreater(self.helper_mismatch('mul_div_floor_one', 0x3c099b9, change), 0)

    def test_side_token_swapped(self):
        def change(insns):
            ins = find(insns, 'mov', lambda i: i[2][1][0] == 'm' and i[2][1][5] == 8)
            return mutate(insns, ins[0], ops=(ins[2][0], ins[2][1][:5] + (0,)))
        self.assertGreater(self.helper_mismatch('side_amount', 0x375e421, change), 0)


class EvaluatorControls(unittest.TestCase):
    def run_text(self, text, **regs):
        insns = sws.parse_listing(text)
        machine = sws.Machine(insns, set())
        for name, val in regs.items():
            machine.regs[sws.REGS[name][0]] = val
        machine.run(insns[0][0])
        return machine

    def test_poisoned_register_stops(self):
        with self.assertRaises(sws.Unmodelled):
            self.run_text('  10:\tmov    rax,rbx\n  13:\tret\n')

    def test_unknown_call_stops(self):
        with self.assertRaises(sws.Unmodelled):
            self.run_text('  10:\tcall   20 <x>\n  15:\tret\n')

    def test_unknown_mnemonic_stops(self):
        with self.assertRaises(sws.Unmodelled):
            self.run_text('  10:\tmovaps xmm0,xmm1\n  13:\tret\n')

    def test_sub_borrow_and_mul_overflow(self):
        m = self.run_text('  10:\tsub    al,cl\n  12:\tret\n', rax=1, rcx=2)
        self.assertTrue(m.cf)
        self.assertEqual(m.regs[0], 0xff)
        m = self.run_text('  10:\tmul    rcx\n  13:\tret\n', rax=1 << 63, rcx=2)
        self.assertTrue(m.of)
        self.assertEqual((m.regs[0], m.regs[2]), (0, 1))

    def test_writing_32_bits_clears_top(self):
        m = self.run_text('  10:\tmov    eax,0x1\n  15:\tret\n', rax=sws.MASK)
        self.assertEqual(m.regs[0], 1)

    def test_divide_by_zero_stops(self):
        with self.assertRaises(sws.Unmodelled):
            self.run_text('  10:\tdiv    rcx\n  13:\tret\n', rax=1, rcx=0, rdx=0)


if __name__ == '__main__':
    unittest.main()
