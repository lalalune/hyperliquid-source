# SPDX-License-Identifier: MIT
import hashlib
import unittest

from tools import reduce_queue_filter94 as q


class ReduceQueueFilter94Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = q.TARGET.read_bytes()
        cls.sections = q.sections(cls.data)
        cls.records = q.collect(cls.data)

    def test_digest_rejects_corruption(self):
        q.authenticate(self.data)
        damaged = bytearray(self.data)
        damaged[0] ^= 1
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            q.authenticate(damaged)

    def test_fdes_and_partitioned_windows(self):
        functions = self.records['functions.tsv'][1]
        self.assertEqual([(r[1], r[2], r[3], r[6]) for r in functions], [
            ('0x24c47f0', '0x24c4a64', '0x10beb64', '628'),
            ('0x2775400', '0x27755d5', '0xd84004', '469'),
        ])
        for _, start, end, _ in q.FUNCTIONS:
            ranges = [(a, b) for _, a, b, _ in q.WINDOWS if start <= a < end]
            self.assertEqual(ranges[0][0], start)
            self.assertEqual(ranges[-1][1], end)
            self.assertTrue(all(a[1] == b[0] for a, b in zip(ranges, ranges[1:])))
        for _, start, end, digest in q.WINDOWS:
            original = q.read_code(self.data, self.sections, start, end-start)
            self.assertEqual(hashlib.sha256(original).hexdigest(), digest)
            for index in (0, len(original)//2, len(original)-1):
                damaged = bytearray(original)
                damaged[index] ^= 1
                with self.assertRaisesRegex(ValueError, 'window changed'):
                    q.check_window(damaged, digest)

    def test_branch_and_call_targets(self):
        for site, opcode, expected, _ in q.BRANCHES:
            raw = q.read_code(self.data, self.sections, site, 6)
            destination, encoded = q.branch(raw, site, opcode)
            self.assertEqual(destination, expected)
            damaged = bytearray(encoded)
            damaged[-1] ^= 1
            self.assertNotEqual(q.branch(damaged, site, opcode)[0], expected)
            damaged[0] ^= 0x20
            with self.assertRaises(ValueError):
                q.branch(damaged, site, opcode)
        calls = self.records['calls.tsv'][1]
        self.assertEqual([r[2] for r in calls[1:5]], ['0x2775400'] * 4)
        self.assertEqual(calls[0][1:3], ['e8c45eddff', '0x24c47f0'])
        with self.assertRaises(ValueError):
            q.branch(b'\x0f\x84\x00', 0, '0f84')

    def test_bounds_and_file_backing(self):
        with self.assertRaises(ValueError):
            q.read_code(self.data, self.sections, 0, 1)
        with self.assertRaises(ValueError):
            q.read_code(self.data, self.sections, -1, 2)
        with self.assertRaises(ValueError):
            q.read_code(self.data, self.sections, 0x2775400, 0)
        bss = next(s for s in self.sections if s['type'] == 8 and s['size'])
        with self.assertRaises(ValueError):
            q.read_code(self.data, self.sections, bss['address'], 1)

    def test_recovered_immediates_and_corruptions(self):
        values = {r[0]: int(r[3]) for r in self.records['fields.tsv'][1]}
        self.assertEqual(values['slot-stride'], 248)
        self.assertEqual(values['vacant-tag'], 2)
        self.assertEqual(values['slot-side-byte-offset'], 0xc2)
        self.assertEqual(values['position-node-key-count-offset'], 0x322)
        self.assertEqual(values['position-child-array-offset'], 0x328)
        self.assertEqual(values['initial-allocation-bytes'], 32)
        self.assertEqual(values['initial-capacity'], 4)
        self.assertEqual(values['empty-output-pointer'], 8)
        for _, site, pattern, start, width, signed in q.FIELDS:
            raw = q.read_code(self.data, self.sections, site, len(bytes.fromhex(pattern)))
            self.assertIsInstance(q.immediate(raw, pattern, start, width, signed), int)
            damaged = bytearray(raw)
            damaged[start] ^= 1
            with self.assertRaises(ValueError):
                q.immediate(damaged, pattern, start, width, signed)
            with self.assertRaises(ValueError):
                q.immediate(raw, pattern, len(raw), width, signed)

    def test_indirect_slots_are_relocated(self):
        actual = [(r[0], r[2], r[3]) for r in self.records['indirect.tsv'][1]]
        self.assertEqual(actual, [(hex(site), hex(slot), hex(addend))
                                  for site, slot, addend, _ in q.INDIRECT])

    def test_fde_and_relocation_negative_controls(self):
        good = {'start': 10, 'end': 20, 'fde': 30}
        self.assertEqual(q.require_fde([good], 20, 30), good)
        for rows, end, fde in (([], 20, 30), ([good, good], 20, 30),
                               ([good], 21, 30), ([good], 20, 31)):
            with self.assertRaises(ValueError):
                q.require_fde(rows, end, fde)
        self.assertEqual(q.require_relocation({100: (8, 200)}, 100, 200), 200)
        for bad in ({}, {100: (7, 200)}, {100: (8, 201)}):
            with self.assertRaises(ValueError):
                q.require_relocation(bad, 100, 200)

    def test_static_condition_and_layout_witnesses(self):
        # These are instruction bytes, not execution of the captured code.
        self.assertEqual(q.read_code(self.data, self.sections, 0x2775594, 15).hex(),
                         '4885c00f9fc074074030e8b0017427')
        self.assertEqual(q.read_code(self.data, self.sections, 0x24c4a00, 24).hex(),
                         '488b44243048c74010000000004c89701848890848895008')
        # Position value address on equality: the loop advances 0x40 before
        # loading at -0x30. Check first and last key in an 11-key node.
        values = {r[0]: int(r[3]) for r in self.records['fields.tsv'][1]}
        stride = values['position-value-stride']
        disp = values['position-found-value-displacement']
        self.assertEqual([stride * (i + 1) + disp for i in (0, 10)], [0x10, 0x290])

    def test_documented_branch_fixtures_are_model_only(self):
        # Independent inputs to the branch rule, useful for reviewing its edge
        # cases. This model is not target execution or differential validation.
        def outcome(live, position, side):
            if not live:
                return 'drop'
            if position is None or position == 0 or int(position > 0) != side:
                return 'reject'
            return 'keep'
        cases = [
            (False, 5, 1, 'drop'), (True, None, 1, 'reject'),
            (True, 0, 0, 'reject'), (True, 0, 1, 'reject'),
            (True, -(1 << 63), 0, 'keep'), (True, -(1 << 63), 1, 'reject'),
            (True, (1 << 63)-1, 1, 'keep'), (True, (1 << 63)-1, 0, 'reject'),
            (True, 1, 2, 'reject'),
        ]
        for live, position, side, expected in cases:
            self.assertEqual(outcome(live, position, side), expected)
        first, second = [(7, 'keep'), (2, 'drop')], [(7, 'keep'), (8, 'reject')]
        flat = first + second
        self.assertEqual([x for x, result in flat if result == 'keep'], [7, 7])
        self.assertEqual([x for x, result in flat if result == 'reject'], [8])


if __name__ == '__main__':
    unittest.main()
