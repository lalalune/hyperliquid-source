import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

import node115_blst_field_ops as ops  # noqa: E402

PACKET = ROOT / 'research/work-items/RE-002-blst-field-ops-emulated-115'
CODE = None


def code():
    global CODE
    if CODE is None:
        CODE = ops.build_context(ops.TARGET)
    return CODE


def run_bytes(body, **regs):
    """Execute hand-assembled bytes placed at the start of the code window."""
    buf = bytearray(body) + bytearray(64)
    mem = ops.Memory()
    mem.add(0x1000, 0x100, 0)
    mem.add(0x2000, 0x100, 0)
    cpu = ops.Cpu(buf, mem)
    regs.setdefault('rsp', 0x2080)
    cpu.mem = mem
    rax = cpu.call(ops.CODE_BASE, **regs)
    return rax, cpu


class InterpreterTests(unittest.TestCase):
    def test_add_adc_carry_chain(self):
        # add %rbx,%rax ; adc %rdx,%rcx ; mov %rcx,%rax ; ret
        rax, cpu = run_bytes(b'\x48\x01\xd8\x48\x11\xd1\x48\x89\xc8\xc3', rax=ops.M64, rbx=1, rcx=5, rdx=6)
        self.assertEqual(rax, 12)
        self.assertEqual(cpu.regs[0], 12)

    def test_sub_sbb_borrow_chain(self):
        # sub %rbx,%rax ; sbb %rdx,%rcx ; mov %rcx,%rax ; ret
        rax, _ = run_bytes(b'\x48\x29\xd8\x48\x19\xd1\x48\x89\xc8\xc3', rax=0, rbx=1, rcx=10, rdx=3)
        self.assertEqual(rax, 6)

    def test_sbb_self_makes_mask(self):
        # sub %rbx,%rax ; sbb %rdx,%rdx ; mov %rdx,%rax ; ret
        rax, _ = run_bytes(b'\x48\x29\xd8\x48\x19\xd2\x48\x89\xd0\xc3', rax=1, rbx=2)
        self.assertEqual(rax, ops.M64)
        rax, _ = run_bytes(b'\x48\x29\xd8\x48\x19\xd2\x48\x89\xd0\xc3', rax=2, rbx=2)
        self.assertEqual(rax, 0)

    def test_cmov_condition_and_32bit_zero_extension(self):
        # cmp %rbx,%rax ; cmovb %rcx,%rdx ; mov %rdx,%rax ; ret   (rax < rbx -> move)
        body = b'\x48\x39\xd8\x48\x0f\x42\xd1\x48\x89\xd0\xc3'
        self.assertEqual(run_bytes(body, rax=1, rbx=2, rcx=7, rdx=9)[0], 7)
        self.assertEqual(run_bytes(body, rax=2, rbx=2, rcx=7, rdx=9)[0], 9)
        # dec %edx clears the upper half
        rax, _ = run_bytes(b'\xff\xca\x48\x89\xd0\xc3', rdx=(5 << 32) | 1)
        self.assertEqual(rax, 0)

    def test_shifts_neg_not(self):
        # shl $0x3f,%rax ; ret
        self.assertEqual(run_bytes(b'\x48\xc1\xe0\x3f\xc3', rax=3)[0], 1 << 63)
        # shr $1,%rax ; ret   with carry out in CF -> adc $0,%rbx ; mov %rbx,%rax
        rax, _ = run_bytes(b'\x48\xd1\xe8\x48\x83\xd3\x00\x48\x89\xd8\xc3', rax=5, rbx=10)
        self.assertEqual(rax, 11)
        self.assertEqual(run_bytes(b'\x48\xf7\xd8\xc3', rax=1)[0], ops.M64)
        self.assertEqual(run_bytes(b'\x48\xf7\xd0\xc3', rax=0)[0], ops.M64)

    def test_push_pop_call_ret(self):
        # call +1 ; ret ; (target) mov $7,%rax ; ret
        body = b'\xe8\x01\x00\x00\x00\xc3\x48\xc7\xc0\x07\x00\x00\x00\xc3'
        self.assertEqual(run_bytes(body)[0], 7)
        # push %rbx ; pop %rax ; ret
        self.assertEqual(run_bytes(b'\x53\x58\xc3', rbx=0x1234)[0], 0x1234)

    def test_memory_operands_and_lea(self):
        # mov (%rsi),%rax ; add 0x8(%rsi),%rax ; lea 0x10(%rax),%rax ; ret
        buf = bytearray(b'\x48\x8b\x06\x48\x03\x46\x08\x48\x8d\x40\x10\xc3') + bytearray(32)
        mem = ops.Memory()
        mem.add(0x1000, 0x100, 0)
        mem.add(0x2000, 0x100, 0)
        mem.store(0x1000, 8, 4)
        mem.store(0x1008, 8, 5)
        cpu = ops.Cpu(buf, mem)
        self.assertEqual(cpu.call(ops.CODE_BASE, rsi=0x1000, rsp=0x2080), 25)

    def test_decoder_rejects_unknown_forms(self):
        for raw in (b'\x0f\x0b', b'\x66\x90', b'\xf3\x0f\xb8', b'\x48\x8b\x05\x00\x00\x00\x00', b'\x48\x8b'):
            with self.assertRaises(ops.Fault):
                ops.decode(bytearray(raw), ops.CODE_BASE)

    def test_memory_model_faults(self):
        mem = ops.Memory()
        mem.add(0x1000, 16)
        with self.assertRaises(ops.Fault):
            mem.read(0x1000 + 9, 8)
        with self.assertRaises(ops.Fault):
            mem.write(0xfff, b'x')
        mem.store(0x1000, 8, -1)
        self.assertEqual(mem.load(0x1000, 8), ops.M64)


class ImageTests(unittest.TestCase):
    def test_digest_gate(self):
        with self.assertRaises(SystemExit):
            ops.check_image(b'')

    def test_window_tiling_and_known_bytes(self):
        c = code()
        for spec in ops.FUNCS:
            ds = ops.static_decode(c, spec[1], spec[2])
            self.assertEqual(sum(d.length for d in ds), spec[2], spec[0])
            self.assertEqual(ds[-1].op, 'ret', spec[0])
        self.assertEqual(c[0x5d2b040 - ops.CODE_BASE:0x5d2b044 - ops.CODE_BASE], b'\xf3\x0f\x1e\xfa')
        with self.assertRaises(ops.Fault):
            ops.static_decode(c, 0x5d2b040, 121)

    def test_helpers_end_at_ret(self):
        c = code()
        for name, va, length in ops.HELPERS:
            ds = ops.static_decode(c, va, length)
            self.assertEqual(ds[-1].op, 'ret', name)


class ArithmeticTests(unittest.TestCase):
    def test_every_function_matches_model_on_sample(self):
        cpu = ops.Cpu(code(), None)
        for spec in ops.FUNCS:
            rng = ops.Rng(77 + spec[1])
            for _ in range(60):
                case = ops.gen_case(rng, spec)
                ok, _, _ = ops.verify_case(cpu, spec, *case)
                self.assertTrue(ok, (spec[0], case))

    def test_known_values(self):
        cpu = ops.Cpu(code(), None)
        spec = ops.spec_by_name('add_mod_256')
        p = (1 << 255) + 95
        ret, _, problems = ops.run_case(cpu, spec, p, p - 1, p - 1, 0)
        self.assertEqual((ret, problems), (p - 2, []))
        spec = ops.spec_by_name('sgn0_pty_mod_384')
        _, rax, _ = ops.run_case(cpu, spec, 13, 7, 0, 0)
        self.assertEqual(rax, 3)
        _, rax, _ = ops.run_case(cpu, spec, 13, 6, 0, 0)
        self.assertEqual(rax, 0)
        spec = ops.spec_by_name('cneg_mod_256')
        ret, _, _ = ops.run_case(cpu, spec, 13, 0, 0, 1 << 40)
        self.assertEqual(ret, 0)
        ret, _, _ = ops.run_case(cpu, spec, 13, 4, 0, 1 << 40)
        self.assertEqual(ret, 9)

    def test_models_reject_wrong_results(self):
        cpu = ops.Cpu(code(), None)
        spec = ops.spec_by_name('sub_mod_256')
        wrong = lambda n, kind, w, parts, p, a, b, k: ((a - b) & ops.mask(256), None)  # noqa: E731
        ok, _, _ = ops.verify_case(cpu, spec, 13, 2, 5, 0, model=wrong)
        self.assertFalse(ok)

    def test_corrupt_byte_is_noticed(self):
        bad = bytearray(code())
        spec = ops.spec_by_name('add_mod_256')
        bad[0x5d2b05c - ops.CODE_BASE + 1] ^= 0x08
        self.assertTrue(ops._batch_detects(bad, spec))
        self.assertFalse(ops._batch_detects(code(), spec))

    def test_zero_shift_count_is_out_of_range(self):
        cpu = ops.Cpu(code(), None)
        with self.assertRaises(ops.Fault):
            ops.run_case(cpu, ops.spec_by_name('lshift_mod_384'), 13, 5, 0, 0)


class ControlTests(unittest.TestCase):
    def test_all_negative_controls_detected(self):
        results = ops.run_controls(code())
        self.assertGreaterEqual(len(results), 30)
        self.assertEqual([r[0] for r in results if not r[2]], [])


class EvidenceTests(unittest.TestCase):
    def test_regenerated_evidence_matches_committed(self):
        with tempfile.TemporaryDirectory() as tmp:
            measure = ops.write_evidence(tmp, code())
            for name in ('windows.tsv', 'decoded.tsv', 'results.tsv', 'controls.tsv', 'sample_cases.tsv', 'measure.json'):
                self.assertEqual((Path(tmp) / name).read_bytes(), (PACKET / name).read_bytes(), name)
        self.assertEqual(measure['cases'], measure['cases_matched'])
        self.assertEqual(measure['negative_controls'], measure['negative_detected'])
        stored = json.loads((PACKET / 'measure.json').read_text())
        self.assertGreaterEqual(stored['cases'], 10000)
        self.assertGreaterEqual(stored['negative_controls'], 30)


if __name__ == '__main__':
    unittest.main()
