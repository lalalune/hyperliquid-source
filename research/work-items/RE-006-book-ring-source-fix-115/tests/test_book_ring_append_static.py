import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))

from book_ring_append_static import (
    PACKET,
    TARGET,
    analyze,
    append_index,
    authenticate,
    generate,
    signed_key,
)
from elf_index import sections


def file_offset(data, va):
    for section in sections(data):
        if (section['type'] != 8 and section['address'] <= va
                < section['address'] + section['size']):
            return section['offset'] + va - section['address']
    raise AssertionError(f'VA not mapped: {va:#x}')


class BookRingAppendStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not TARGET.exists():
            raise unittest.SkipTest('node 115 target is not materialized')
        cls.data = TARGET.read_bytes()
        authenticate(cls.data)
        cls.report = analyze(cls.data)

    def test_native_regeneration_matches_retained_packet(self):
        retained = json.loads((PACKET / 'records.json').read_text())
        self.assertEqual(
            self.report,
            {key: value for key, value in retained.items()
             if key != 'source_exports'},
        )
        self.assertEqual(
            self.report['scope']['measured_denominator_bytes'], 1_326)
        self.assertEqual(
            sum(self.report['frames'][name]['bytes'] for name in
                ('ring_append_a', 'ring_append_b')),
            1_326,
        )
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'packet'
            generate(TARGET, output)
            retained_files = sorted(
                path.name for path in PACKET.iterdir()
                if path.name != 'MANIFEST.sha256' and path.name != 'README.md'
            )
            self.assertEqual(
                retained_files,
                sorted(path.name for path in output.iterdir()),
            )
            for name in retained_files:
                self.assertEqual(
                    (PACKET / name).read_bytes(),
                    (output / name).read_bytes(),
                    name,
                )

    def test_trace_facts(self):
        trace = self.report['trace']
        self.assertEqual(trace['entry_guard']['field_offset'], '0xb0')
        self.assertEqual(
            trace['entry_guard']['panic_location'],
            'l1/src/book/level.rs:32:54',
        )
        self.assertEqual(trace['arm_split']['field_offset'], '0xd8')
        self.assertEqual(trace['arm_split']['append_arm_value'], 1)
        self.assertEqual(trace['append']['element_bytes'], 32)
        self.assertEqual(trace['append']['length_increment'], 1)
        self.assertEqual(
            self.report['owners']['ring_append_a']['direct_e8_call_sites'],
            ['0x5903fab', '0x590bd0b'],
        )
        self.assertEqual(
            self.report['owners']['ring_append_b']['direct_e8_call_sites'],
            ['0x5908216', '0x590ff76'],
        )
        detail = trace['owners_detail']
        self.assertEqual(
            detail['ring_append_a']['callees']['shared_in_append_arm'],
            '0x58df360',
        )
        self.assertEqual(
            detail['ring_append_b']['callees']['shared_in_append_arm'],
            '0x58df790',
        )
        self.assertEqual(
            detail['ring_append_a']['slots']['grow'], '0x64e27a8')

    def test_signed_key_rule_cases(self):
        self.assertEqual(signed_key(5, 0), -5)
        self.assertEqual(signed_key(5, 1), 5)
        self.assertEqual(signed_key(5, 0x80), 5)
        self.assertEqual(signed_key(-7, 0), 7)
        self.assertEqual(signed_key(-7, 2), -7)
        self.assertEqual(signed_key(0, 0), 0)
        self.assertEqual(signed_key(-(1 << 63), 0), -(1 << 63))
        self.assertEqual(signed_key((1 << 63) - 1, 0), -((1 << 63) - 1))

    def test_append_index_matches_modulo(self):
        for capacity in range(1, 200):
            for head in range(capacity):
                for length in range(capacity):
                    self.assertEqual(
                        append_index(head, length, capacity),
                        (head + length) % capacity,
                        (head, length, capacity),
                    )

    def mutate_va_byte(self, va, mask=0x01):
        changed = bytearray(self.data)
        changed[file_offset(self.data, va)] ^= mask
        return bytes(changed)

    def test_counterfactual_pinned_bytes_and_records(self):
        owner_a = 0x5911890
        cases = (
            # The guarded field displacement +0xb0 in the entry load.
            (owner_a + 0x1A + 3, 'Pinned instruction changed'),
            # One opcode byte of the cmovne in the signed key rule.
            (owner_a + 0x5C, 'Pinned instruction changed'),
            # The arm split immediate: == 1 becomes == 0.
            (owner_a + 0x9E + 8, 'Pinned instruction changed'),
            # The order copy size 0x110 in the registration arm.
            (owner_a + 0x10D + 1, 'Pinned instruction changed'),
            # The element size shift 5 in the append store.
            (owner_a + 0x22E + 3, 'Pinned instruction changed'),
            # The panic message text in .rodata.
            (0x91F9EB, 'Panic message changed'),
            # The panic location line field (record + 16).
            (0x64A3508 + 16, 'Entry guard panic location changed'),
            # The caller census: caller 1's E8 opcode becomes a jump.
            (0x5903FAB, 'ring_append_a direct caller census changed'),
        )
        for va, message in cases:
            with self.subTest(va=hex(va)):
                with self.assertRaisesRegex(ValueError, message):
                    analyze(self.mutate_va_byte(va))


if __name__ == '__main__':
    unittest.main()
