import random
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import action_prior_key_wrapper_115 as T  # noqa: E402


class Tiny:
    """A code source holding a few raw instruction bytes at a fake address."""

    def __init__(self, blob, base=0x1000):
        self.blob, self.base = blob, base

    def byte_at(self, va):
        if not self.base <= va < self.base + len(self.blob):
            raise T.Fail('fetch outside tiny code')
        return self.blob[va - self.base]


def run_tiny(blob, setup=None):
    m = T.Machine(Tiny(blob), {})
    if setup:
        setup(m)
    m.r[4] = T.STACK
    m.rip = 0x1000
    while m.rip < 0x1000 + len(blob):
        m.step()
    return m


class InterpreterTest(unittest.TestCase):
    def test_sub_borrow_and_jb(self):
        # mov $0,%r15d ; sub $1,%r15 -> borrow (CF=1)
        m = run_tiny(bytes.fromhex('41bf00000000' '4983ef01'))
        self.assertEqual(m.f['c'], 1)
        self.assertEqual(m.r[15], (1 << 64) - 1)

    def test_cltq_sign_extends(self):
        m = run_tiny(bytes.fromhex('b8ffffffff' '4898'))
        self.assertEqual(m.r[0], (1 << 64) - 1)

    def test_setg_after_signed_compare(self):
        # mov $5,%ecx ; mov $3,%edx ; cmp %edx,%ecx ; setg %al
        m = run_tiny(bytes.fromhex('b905000000' 'ba03000000' '39d1' '0f9fc0'))
        self.assertEqual(m.r[0] & 0xff, 1)

    def test_lea_scaled_index(self):
        # mov $3,%eax ; lea (%rax,%rax,4),%r14
        m = run_tiny(bytes.fromhex('b803000000' '4c8d34 80'.replace(' ', '')))
        self.assertEqual(m.r[14], 15)

    def test_unknown_opcode_fails_closed(self):
        with self.assertRaises(T.Fail):
            run_tiny(bytes([0xf4]))

    def test_fetch_outside_text_fails(self):
        data, text = T.load_binary()
        with self.assertRaises(T.Fail):
            T.Code(data, text).byte_at(0x1000)


class BinaryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data, cls.text = T.load_binary()
        cls.code = T.Code(cls.data, cls.text)

    def test_digest_rejects_damage(self):
        with self.assertRaises(T.Fail):
            T.check_digest(self.data[:-1])

    def test_clones_have_ten_distinct_sinks(self):
        sinks = {T.sink_of(self.code, a) for a in T.COPIES}
        self.assertEqual(len(sinks), 10)
        self.assertEqual(T.sink_of(self.code, T.COPIES[0]), 0x2962880)

    def test_clone_bodies_equal_outside_displacements(self):
        base = self.code.slice(T.COPIES[0], T.SIZE)
        for a in T.COPIES[1:]:
            body = self.code.slice(a, T.SIZE)
            diff = [i for i in range(T.SIZE) if body[i] != base[i]]
            self.assertTrue(diff)
            self.assertTrue(all(i in range(0x20, 0x440) for i in diff))

    def test_emulator_matches_model_on_every_clone(self):
        for a in (T.COPIES[0], T.COPIES[4], T.COPIES[9]):
            sink = T.sink_of(self.code, a)
            for k in range(60):
                st = T.make_state(random.Random(k))
                agree, real, mod = T.evaluate(self.code, a, sink, st)
                self.assertTrue(agree, (hex(a), k))
                self.assertTrue(T.semantic_ok(st, mod))

    def test_every_outcome_is_reached(self):
        sink = T.sink_of(self.code, T.COPIES[0])
        kinds = set()
        for k in range(300):
            st = T.make_state(random.Random(k))
            kinds.add(T.kind_of(*T.evaluate(self.code, T.COPIES[0], sink, st)[2][:3]))
        self.assertEqual(kinds, {'panic', 'rejected', 'first-failed', 'second-failed', 'dispatched'})

    def test_model_mutants_are_caught(self):
        sink = T.sink_of(self.code, T.COPIES[0])
        for mut in ('reject-code', 'skip-value-walk', 'swap-calls', 'no-drop'):
            seen = False
            for k in range(200):
                st = T.make_state(random.Random(k))
                real = T.run_case(self.code, T.COPIES[0], sink, st)
                got = T.model(st, T.reader_for(st), sink, frozenset([mut]))[:3]
                seen |= got != real
            self.assertTrue(seen, mut)

    def test_byte_damage_and_bad_inputs_are_caught(self):
        sink = T.sink_of(self.code, T.COPIES[0])
        st = T.make_state(random.Random(0))
        with self.assertRaises(T.Fail):
            T.run_case(self.code, 0x1000, sink, st)
        with self.assertRaises(T.Fail):
            T.run_case(T.PatchedCode(self.code, {T.COPIES[0]: 0xcc}), T.COPIES[0], sink, st)
        with self.assertRaises(T.Fail):
            T.sink_of(T.PatchedCode(self.code, {T.COPIES[0] + T.TAIL_SITE: 0x90}), T.COPIES[0])

    def test_generation_is_deterministic(self):
        a = [T.make_state(random.Random(k))['key'] for k in range(20)]
        b = [T.make_state(random.Random(k))['key'] for k in range(20)]
        self.assertEqual(a, b)


if __name__ == '__main__':
    unittest.main()
