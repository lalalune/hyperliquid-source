"""Target-backed checks for the interpreter-driven blst modular-arithmetic packet."""
from pathlib import Path
import random
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import node115_blst_modarith_exec as m

PACKET = ROOT / 'research/work-items/RE-002-blst-modarith-exec-115'


class Interpreter(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = m.TARGET.read_bytes()
        cls.image = m.Image(cls.data)

    def test_binary_gate(self):
        bad = bytearray(self.data)
        bad[1000] ^= 1
        with self.assertRaises(ValueError):
            m.Image(bytes(bad))

    def test_function_entries_are_fde_starts(self):
        for name, va, _, _ in m.SPECS:
            start, end = self.image.extent(va)
            self.assertEqual(start, va, name)
            self.assertGreater(end, start)
        with self.assertRaises(ValueError):
            self.image.extent(m.SPECS[0][1] + 4)

    def test_every_function_matches_its_model(self):
        for name, n, bad, lo, hi, seen in m.sweep(self.image, count=40):
            self.assertEqual((n, bad), (40, 0), name)
            self.assertGreater(len(seen), 20, name)

    def test_decoder_known_bytes(self):
        cpu = m.Cpu(self.image)
        length, name, ops = cpu.decode(0x5d24a80)
        self.assertEqual((length, name), (4, 'nop'))  # endbr64
        length, name, ops = cpu.decode(0x5d24ac4)  # mov r8,[rsi]
        self.assertEqual((length, name, ops[0], ops[2]), (3, 'mov', ('r', 8), 64))
        length, name, ops = cpu.decode(0x5d24adb)  # add r8,[rdx]
        self.assertEqual((length, name, ops[0]), (3, 'alu', 'add'))

    def test_flags_and_shifts(self):
        cpu = m.Cpu(self.image)
        self.assertEqual(cpu.alu('add', m.M64, 1, 64), 0)
        self.assertEqual((cpu.cf, cpu.zf), (1, 1))
        self.assertEqual(cpu.alu('sub', 0, 1, 64), m.M64)
        self.assertEqual((cpu.cf, cpu.sf), (1, 1))
        cpu.cf = 1
        self.assertEqual(cpu.alu('sbb', 5, 5, 64), m.M64)
        self.assertEqual(cpu.alu('add', 0x7fffffffffffffff, 1, 64), 1 << 63)
        self.assertEqual(cpu.of, 1)

    def test_wrong_models_are_caught(self):
        for name, mut in [('add_mod_384', 'no-reduce'), ('rshift_mod_384', 'n-1'), ('cneg_mod_384', 'flag-32'),
                          ('sgn0_pty_mod_384', 'gt'), ('sgn0_pty_mod_384x', 'bit1-re')]:
            bad = sum(r[2] for r in m.sweep(self.image, mut=mut, only=name, count=300))
            self.assertGreater(bad, 0, mut)

    def test_corrupted_code_is_caught(self):
        va = 0x5d24ae6 + 0  # mov r14,r8 in __add_mod_384
        patches = {va + 2: self.image.byte(va + 2) ^ 1}
        bad = sum(r[2] for r in m.sweep(self.image, patches=patches, only='__add_mod_384', count=50))
        self.assertGreater(bad, 0)

    def test_faults(self):
        cpu = m.Cpu(self.image)
        with self.assertRaises(m.Fault):
            cpu.call(0x10, (0, 0, 0, 0), {})
        with self.assertRaises(m.Fault):
            cpu.call(0x5d24a80, (1, 2, 3, 4), {})
        ok, _ = m.run_case(cpu, 0x5d24d80, 'lsh', {'mod': m.BLS_P, 'a': [3], 'n': 0}, False)
        self.assertFalse(ok)

    def test_cneg_zero_and_flag_width(self):
        cpu = m.Cpu(self.image)
        va = 0x5d25100
        for flag in (0, 1, 1 << 32, m.M64):
            for a in (0, 1, m.BLS_P - 1):
                case = {'mod': m.BLS_P, 'a': [a], 'flag': flag}
                self.assertTrue(m.run_case(cpu, va, 'cneg', case, False)[0], (flag, a))

    def test_sgn0x_rule(self):
        cpu = m.Cpu(self.image)
        rng = random.Random(7)
        for _ in range(30):
            c = {'mod': m.BLS_P, 'a': [0, rng.randrange(m.BLS_P)]}
            self.assertTrue(m.run_case(cpu, 0x5d25560, 'sgn0x', c, False)[0])
            c['a'][0] = rng.randrange(1, m.BLS_P)
            self.assertTrue(m.run_case(cpu, 0x5d25560, 'sgn0x', c, False)[0])

    def test_packet_matches_regeneration(self):
        with tempfile.TemporaryDirectory() as tmp:
            m.generate(tmp)
            for name in ('functions.tsv', 'sample-cases.tsv', 'executed-instructions.tsv', 'negative-controls.tsv', 'measure.json'):
                self.assertEqual((Path(tmp) / name).read_bytes(), (PACKET / name).read_bytes(), name)


if __name__ == '__main__':
    unittest.main()
