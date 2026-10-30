"""Controls for tools/evm_amount_scale.py (RE-004, node #94)."""

import filecmp
import hashlib
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from gnu_binutils import requires_gnu  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / 'tools' / 'evm_amount_scale.py'
PACKET = ROOT / 'research' / 'work-items' / 'RE-004-evm-amount-scale-94'

spec = importlib.util.spec_from_file_location('evm_amount_scale', TOOL)
eas = importlib.util.module_from_spec(spec)
sys.modules['evm_amount_scale'] = eas
spec.loader.exec_module(eas)

BINARY = ROOT / eas.BINARY
CACHE = {}
VECTORS = [(0, 5), (1, 19), (2, 1001), (10, 3 * 10 ** 19), (18, 10 ** 36 + 7), (19, eas.U256 - 1),
           (-1, 7), (-2, 1001), (-18, 2), (-19, 2 ** 200), (-19, 1), (20, 5), (-20, 5), (-128, 5),
           (2, eas.CAP * 100 - 1), (2, eas.CAP * 100), (-2, (eas.CAP - 1) // 100),
           (-2, (eas.CAP - 1) // 100 + 1), (-19, 2 ** 237)]


def small(text, rows):
    """Assemble an evaluator program from objdump-shaped lines."""
    listing = '\n'.join(f'  {0x1000 + 4 * i:x}:\t{row}' for i, row in enumerate(rows))
    return eas.parse_listing(listing + f'\n  {0x1000 + 4 * len(rows):x}:\tint3')


@requires_gnu('objdump')
class Fixture(unittest.TestCase):
    def set_up_class(cls):
        if not CACHE:
            data = BINARY.read_bytes()
            img = eas.Image(data)
            fdes = eas.Fdes(img)
            CACHE['data'] = data
            CACHE['img'] = img
            CACHE['fdes'] = fdes
            CACHE['slots'] = img.slots()
            CACHE['insns'] = eas.load_code(BINARY, fdes, (eas.SCALE, eas.DIV_HELPER, eas.MUL_HELPER))[0]
            CACHE['analysis'] = eas.analyse(BINARY, data)
        cls.data = CACHE['data']
        cls.img = CACHE['img']
        cls.fdes = CACHE['fdes']
        cls.slots = CACHE['slots']
        cls.insns = CACHE['insns']
        cls.result, cls.table, cls.bounds, cls.scale_insns = CACHE['analysis']

    setUpClass = classmethod(set_up_class)

    def machine(self, insns=None):
        return eas.Machine(insns or self.insns, self.img, self.slots)

    def differs(self, insns):
        machine = self.machine(insns)
        for exponent, amount in VECTORS:
            try:
                if eas.run_scale(machine, exponent, amount) != eas.scale_model(exponent, amount):
                    return True
            except eas.Unmodelled:
                return True
        return False

    def mutate(self, va, mnemonic=None, ops=None):
        out = []
        for ins in self.insns:
            if ins[0] == va:
                ins = (ins[0], mnemonic or ins[1], ops if ops is not None else ins[2], ins[3])
            out.append(ins)
        return out


class Results(Fixture):
    def test_counts(self):
        v = self.result['vectors']
        self.assertEqual(v['total'], 13091)
        self.assertEqual(v['mismatches'], 0)
        self.assertEqual(v['some'], 2368)
        self.assertGreater(v['u256_product_overflows'], 300)
        self.assertEqual(self.result['ladder']['admitted'], 39)
        self.assertEqual(self.result['function']['instructions'], 122)
        h = self.result['multiply_helper_vectors']
        self.assertEqual((h['total'], h['mismatches']), (3660, 0))
        self.assertGreater(h['overflows'], 100)

    def test_extents(self):
        self.assertEqual(self.fdes.range_of(eas.SCALE)['end'], eas.SCALE_END)
        h = self.result['helpers']
        self.assertEqual((h['divide']['start'], h['divide']['end']), (0x32d6ad0, 0x32d7e3f))
        self.assertEqual((h['multiply']['start'], h['multiply']['end']), (0x32d7e40, 0x32d830a))

    def test_only_the_panic_is_unexecuted(self):
        self.assertEqual(self.result['coverage']['function_not_executed'],
                         [0x3281943, 0x328194a, 0x3281951, 0x3281956])
        self.assertEqual(self.result['panic']['line'], 13)

    def test_sites(self):
        rows = {row['site']: row for row in self.result['sites']}
        self.assertEqual(sorted(rows), sorted(eas.SITES))
        self.assertEqual(rows[0x342753a]['exponent']['value'], 10)
        self.assertEqual(rows[0x3baf539]['exponent']['load_offset'], 0xd1)
        self.assertEqual(rows[0x3baf779]['exponent']['load_offset'], 0xd1)
        self.assertEqual(eas.call_sites(self.img, eas.SCALE), list(eas.SITES))

    def test_cap_identity(self):
        self.assertEqual(eas.CAP, (2 ** 63 - 1) // 10)
        self.assertEqual(self.result['largest_result'], 922337203685477579)

    def test_table_every_i8(self):
        self.assertEqual(len(self.table), 256)
        for exponent, k, power in self.table:
            self.assertEqual(k, abs(exponent))
            self.assertEqual(power, 10 ** k if k < 20 else None)

    def test_bounds(self):
        self.assertEqual(len(self.bounds), 39)
        machine = self.machine()
        for exponent, _power, top, value, first in self.bounds:
            self.assertEqual(eas.run_scale(machine, exponent, top)[0], value)
            self.assertIsNone(eas.run_scale(machine, exponent, first)[0])

    def test_floor_and_dead_remainder(self):
        machine = self.machine()
        self.assertEqual(eas.run_scale(machine, 2, 1099)[0], 10)
        self.assertEqual(eas.dead_divisor_slot(machine), 99)
        self.assertEqual(self.result['quotient_reads'], [0x3281906, 0x3281909, 0x328190d, 0x3281911])

    def test_amount_is_changed_in_place_only_when_dividing(self):
        machine = self.machine()
        self.assertEqual(eas.run_scale(machine, 3, 12345)[1], 12)
        self.assertEqual(eas.run_scale(machine, -3, 12345)[1], 12345)
        self.assertEqual(eas.run_scale(machine, 20, 12345)[1], 12345)

    def test_rdi_is_never_needed(self):
        machine = self.machine()
        self.assertEqual(machine.known[eas.RDI], 0)
        eas.enter(machine, 2, 100)
        self.assertEqual(machine.known[eas.RDI], 0)
        machine.run(eas.SCALE)
        self.assertEqual(machine.regs[eas.RDX], 1)

    def test_lead_witnesses(self):
        rows = {(w['exponent'], w['amount']): w for w in self.result['lead']['witnesses']}
        self.assertEqual((rows[2, 1000]['binary'], rows[2, 1000]['lead']), (10, 100000))
        self.assertEqual((rows[-2, 1001]['binary'], rows[-2, 1001]['lead']), (100100, None))
        self.assertIsNone(rows[0, 2 ** 64 - 1]['binary'])
        self.assertEqual(rows[0, 2 ** 64 - 1]['lead'], 2 ** 64 - 1)

    def test_outputs_match_packet(self):
        with tempfile.TemporaryDirectory() as tmp:
            eas.write_outputs(Path(tmp), self.result, self.table, self.bounds, self.data)
            names = ['evidence.json', 'exponent-table.tsv', 'boundaries.tsv', 'function-bytes.txt']
            match, bad, err = filecmp.cmpfiles(tmp, PACKET, names, shallow=False)
            self.assertEqual((sorted(match), bad, err), (sorted(names), [], []))

    def test_manifest(self):
        rows = (PACKET / 'MANIFEST.sha256').read_text().splitlines()
        self.assertEqual(len(rows), 5)
        for row in rows:
            digest, name = row.split('  ')
            self.assertEqual(hashlib.sha256((PACKET / name).read_bytes()).hexdigest(), digest)


class NegativeControls(Fixture):
    def test_unmodified_passes(self):
        self.assertFalse(self.differs(self.insns))

    def test_tampered_digest(self):
        with self.assertRaises(eas.EvidenceError):
            eas.check_digest(self.data[:-1] + bytes([self.data[-1] ^ 1]))
        with self.assertRaises(eas.EvidenceError):
            eas.analyse(BINARY, self.data[:4096])

    def test_out_of_range_va(self):
        with self.assertRaises(eas.EvidenceError):
            self.img.read(0x7fffffff0000, 8)
        with self.assertRaises(eas.EvidenceError):
            self.fdes.range_of(0x10)
        with self.assertRaises(eas.EvidenceError):
            eas.find(self.scale_insns, 0x3281772)

    def test_changed_cap(self):
        ins = eas.find(self.insns, eas.CAP_INSN)
        self.assertTrue(self.differs(self.mutate(eas.CAP_INSN, ops=(ins[2][0], ('i', eas.CAP + 1)))))

    def test_cap_compare_flipped(self):
        self.assertTrue(self.differs(self.mutate(0x328192b, 'setae')))

    def test_sign_branch_flipped(self):
        self.assertTrue(self.differs(self.mutate(0x3281840, 'js')))

    def test_ladder_multiplier(self):
        ins = eas.find(self.insns, 0x32817ad)
        self.assertTrue(self.differs(self.mutate(0x32817ad, ops=ins[2][:2] + (('i', 101),))))

    def test_upper_limbs_ignored(self):
        self.assertTrue(self.differs(self.mutate(0x328191b, 'setne')))

    def test_multiply_overflow_ignored(self):
        machine = self.machine(self.mutate(0x3281860, 'nop', ()))
        self.assertEqual(eas.run_scale(machine, -19, 2 ** 237)[0], 0)
        self.assertIsNone(eas.run_scale(self.machine(), -19, 2 ** 237)[0])

    def test_divide_helper_step(self):
        ins = eas.find(self.insns, 0x32d6d6a)
        self.assertEqual(ins[1], 'sub')
        self.assertTrue(self.differs(self.mutate(0x32d6d6a, 'add')))

    def test_multiply_helper_step(self):
        # The function only exposes products below the cap, so this carry shows at the helper.
        self.assertFalse(self.differs(self.mutate(0x32d8107, 'nop', ())))
        right = 10 ** 19
        lefts = [(int.from_bytes(hashlib.sha256(bytes([i])).digest(), 'little') >> 66) for i in range(32)]
        good, bad = self.machine(), self.machine(self.mutate(0x32d8107, 'nop', ()))
        wrong = 0
        for left in lefts:
            want = ((left * right) % eas.U256, int(left * right >= eas.U256))
            self.assertEqual(eas.run_multiply(good, left, right), want)
            wrong += eas.run_multiply(bad, left, right) != want
        self.assertGreater(wrong, 0)

    def test_wrong_model(self):
        self.assertNotEqual(eas.scale_model(2, 1001)[0], eas.scale_model(2, 1000)[0] + 1)
        self.assertIsNone(eas.scale_model(0, eas.CAP)[0])
        self.assertEqual(eas.scale_model(0, eas.CAP - 1)[0], eas.CAP - 1)

    def test_wrong_site_list(self):
        self.assertEqual(eas.call_sites(self.img, eas.SCALE + 1), [])


class Evaluator(unittest.TestCase):
    def setUp(self):
        self.img = eas.Image(BINARY.read_bytes())

    def run_rows(self, rows):
        machine = eas.Machine(small('', rows), self.img, {})
        machine.setreg(eas.RSP, eas.STACK_TOP)
        machine.store(eas.STACK_TOP, 8, eas.RET_MAGIC)
        return machine, 0x1000

    def execute(self, rows):
        machine, entry = self.run_rows(rows + ['ret'])
        machine.run(entry)
        return machine

    def test_unset_register_stops(self):
        with self.assertRaises(eas.Unmodelled):
            self.execute(['add    rax,rcx'])

    def test_unset_memory_stops(self):
        with self.assertRaises(eas.Unmodelled):
            self.execute(['mov    rax,QWORD PTR [rsp-0x10]'])

    def test_read_outside_model_stops(self):
        with self.assertRaises(eas.Unmodelled):
            self.execute(['mov    eax,0x8', 'mov    rax,QWORD PTR [rax]'])

    def test_write_outside_ram_stops(self):
        with self.assertRaises(eas.Unmodelled):
            self.execute(['xor    eax,eax', 'mov    QWORD PTR [rax],rax'])

    def test_unknown_mnemonic_stops(self):
        with self.assertRaises(eas.Unmodelled):
            self.execute(['vpaddq ymm0,ymm1,ymm2'])

    def test_unset_flag_stops(self):
        with self.assertRaises(eas.Unmodelled):
            self.execute(['je     1000'])

    def test_unknown_target_stops(self):
        with self.assertRaises(eas.Unmodelled):
            self.execute(['call   2000'])

    def test_int3_stops(self):
        with self.assertRaises(eas.Unmodelled):
            self.execute(['int3'])

    def test_divide_fault_stops(self):
        with self.assertRaises(eas.Unmodelled):
            self.execute(['xor    eax,eax', 'xor    edx,edx', 'xor    ecx,ecx', 'div    rcx'])

    def test_misaligned_movaps_stops(self):
        with self.assertRaises(eas.Unmodelled):
            self.execute(['xorps  xmm0,xmm0', 'movaps XMMWORD PTR [rsp+0x4],xmm0'])

    def test_carry_chain(self):
        m = self.execute(['mov    rax,0xffffffffffffffff', 'add    rax,0x1', 'mov    ecx,0x5', 'adc    rcx,0x0',
                          'mov    edx,0x5', 'sbb    rdx,0x0'])
        self.assertEqual((m.regs[eas.RAX], m.regs[eas.RCX], m.regs[eas.RDX]), (0, 6, 5))

    def test_partial_register_merge(self):
        m = self.execute(['mov    eax,0x12345', 'mov    al,0x1'])
        self.assertEqual(m.regs[eas.RAX], 0x12301)

    def test_cmov_32_clears_upper_when_not_taken(self):
        m = self.execute(['mov    rax,0xffffffffffffffff', 'xor    ecx,ecx', 'cmp    ecx,0x1', 'cmove  eax,ecx'])
        self.assertEqual(m.regs[eas.RAX], 0xffffffff)

    def test_shifts(self):
        m = self.execute(['mov    eax,0x1', 'mov    edx,0x80000000', 'shl    rdx,0x20', 'mov    ecx,0x4',
                          'shld   rax,rdx,cl'])
        self.assertEqual(m.regs[eas.RAX], 0x18)
        m = self.execute(['mov    eax,0x80', 'mov    edx,0xf', 'mov    ecx,0x4', 'shrd   rax,rdx,cl'])
        self.assertEqual(m.regs[eas.RAX], (0xf << 60) | 8)
        m = self.execute(['mov    eax,0x80', 'sar    al,0x7'])
        self.assertEqual(m.regs[eas.RAX], 0xff)

    def test_mul_imul_bsr(self):
        m = self.execute(['mov    rax,0xffffffffffffffff', 'mov    ecx,0x2', 'mul    rcx', 'seto   bl'])
        self.assertEqual((m.regs[eas.RAX], m.regs[eas.RDX], m.regs[eas.RBX] & 1), (2 ** 64 - 2, 1, 1))
        m = self.execute(['mov    rax,0xffffffffffffffff', 'imul   rcx,rax,0x3'])
        self.assertEqual(m.regs[eas.RCX], 2 ** 64 - 3)
        m = self.execute(['mov    eax,0x80', 'bsr    rcx,rax'])
        self.assertEqual(m.regs[eas.RCX], 7)


if __name__ == '__main__':
    unittest.main()
