import json
from pathlib import Path
import random
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import node115_ring_offset as subject

PACKET = subject.ROOT / 'research/work-items/RE-001-node115-ring-offset'


class RingOffsetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # One mutable copy for all target-backed controls; restore each mutation.
        cls.data = bytearray(subject.TARGET.stat().st_size)
        with subject.TARGET.open('rb') as stream:
            if stream.readinto(cls.data) != len(cls.data):
                raise ValueError('short target read')

    def mutate_reject(self, position, value, message, authenticate=False):
        old = self.data[position]
        try:
            self.data[position] = value
            with self.assertRaisesRegex(ValueError, message):
                subject.inspect(self.data, authenticate=authenticate)
        finally:
            self.data[position] = old

    def test_authenticated_regeneration(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            record = subject.generate(self.data, out)
            self.assertEqual(record['window']['size'], 83)
            self.assertEqual({p.name for p in out.iterdir()}, {p.name for p in PACKET.iterdir()})
            for path in out.iterdir():
                self.assertEqual(path.read_bytes(), (PACKET / path.name).read_bytes(), path.name)

    def test_wrong_digest_rejected_before_output(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / 'missing'
            with self.assertRaisesRegex(ValueError, 'digest mismatch'):
                subject.generate(b'wrong artifact', out)
            self.assertFalse(out.exists())
        self.mutate_reject(subject.offset(subject.START), 0, 'digest mismatch', True)

    def test_mutated_body_rejected_below_authentication(self):
        pos = subject.offset(subject.START + 7)
        self.mutate_reject(pos, self.data[pos] ^ 1, 'unexpected instruction')

    def test_shifted_fde_rejected_below_authentication(self):
        pos = subject.FDE + 8
        self.mutate_reject(pos, self.data[pos] ^ 1, 'FDE extent')

    def test_wrong_caller_target_rejected_below_authentication(self):
        pos = subject.offset(subject.CALLER + 1)
        self.mutate_reject(pos, self.data[pos] ^ 1, 'caller scan changed')

    def test_readme_counts_follow_semantic_records(self):
        r = json.loads((PACKET / 'records.json').read_text())
        c = r['counts']
        self.assertEqual(c['instructions'], len(r['instructions']))
        self.assertEqual(c['callees'], len(r['callees']))
        self.assertEqual(c['caller_candidates'], len(r['direct_rel32_candidates']))
        self.assertEqual(c['padding_bytes'], len(bytes.fromhex(r['window']['padding_hex'])))
        text = (PACKET / 'README.md').read_text()
        for fragment in (f"{r['window']['size']} bytes", f"following {c['padding_bytes']} bytes",
                         f"The {c['instructions']} individually", f"are {c['callees']} direct",
                         f"yields {c['caller_candidates']} candidate"):
            self.assertIn(fragment, text)

    def test_instruction_derived_boundary_vectors(self):
        max64 = subject.MASK
        vectors = [
            ((0, 0, 0), (1, 0)), ((8, 3, 10), (0, 5)),
            ((8, 3, 5), (0, 4)), ((8, 8, 9), (0, 8)),
            ((8, 9, 20), (0, 7)), ((8, 3, 1), (0, 0)),
            ((0, 1, max64), (0, max64 - 1)),
            ((max64, max64, max64), (0, max64 - 1)),
        ]
        for args, expected in vectors:
            with self.subTest(args=args):
                self.assertEqual(subject.model(*args), expected)
        for bad in (-1, 1 << 64):
            with self.assertRaises(ValueError):
                subject.model(bad, 0, 1)

    def test_loop_telescoping_and_unsigned_branches(self):
        rng = random.Random(115)
        for _ in range(3000):
            capacity, head, length = (rng.getrandbits(64) for _ in range(3))
            # Separately follow the decoded machine branch and loop operations.
            if length == 0:
                actual = (1, 0)
            else:
                dx = (0 if head < capacity else capacity)
                dx = (dx - head + capacity) & subject.MASK
                if dx >= length:
                    dx = 0
                    k = length
                    while k > 1:
                        half = k >> 1
                        dx = (dx + half) & subject.MASK
                        k -= half
                actual = (0, dx)
            self.assertEqual(subject.model(capacity, head, length), actual)


if __name__ == '__main__':
    unittest.main()
