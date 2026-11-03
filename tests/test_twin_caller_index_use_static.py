import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))

from twin_caller_index_use_static import (
    PACKET,
    TARGET,
    analyze,
    authenticate,
    flow_verdict,
    generate,
)
from elf_index import sections


def file_offset(data, va):
    for section in sections(data):
        if (section['type'] != 8 and section['address'] <= va
                < section['address'] + section['size']):
            return section['offset'] + va - section['address']
    raise AssertionError(f'VA not mapped: {va:#x}')


LOCAL = ('insert-path-local: register-only, forwarded as call '
         'arguments, never stored in the caller')


class TwinCallerIndexUseStaticTests(unittest.TestCase):
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
            self.report['scope']['measured_denominator_bytes'], 64_148)
        self.assertEqual(
            sum(self.report['frames'][name]['bytes'] for name in
                ('caller_1', 'caller_2', 'caller_3', 'caller_4')),
            64_148,
        )
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'packet'
            generated = generate(TARGET, output)
            self.assertEqual(
                sum(len(windows) for windows in
                    generated['source_exports'].values()),
                10,
            )
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

    def test_census_facts(self):
        boundaries = self.report['boundaries']
        self.assertEqual(
            boundaries['ring_append_a']['direct_e8_call_sites'],
            ['0x5903fab', '0x590bd0b'],
        )
        self.assertEqual(
            boundaries['ring_append_b']['direct_e8_call_sites'],
            ['0x5908216', '0x590ff76'],
        )
        self.assertEqual(
            boundaries['ring_append_a']['direct_callers'],
            ['caller_1', 'caller_3'],
        )
        self.assertEqual(
            boundaries['ring_append_b']['direct_callers'],
            ['caller_2', 'caller_4'],
        )
        diagnostics = self.report['relocation_diagnostics']
        self.assertEqual(diagnostics['body_slot_references'], [])
        self.assertEqual(diagnostics['body_addend_references'], [])
        self.assertEqual(
            diagnostics['excluded_slot_binding'],
            {'0x64df4a0': '0x635de30'},
        )

    def test_trace_facts(self):
        trace = self.report['trace']
        expected = {
            'caller_1': ('ring_append_a', 'r15', ['0x5904088'],
                         '0x59041a2', None),
            'caller_2': ('ring_append_b', 'r12',
                         ['0x59082ee', '0x5908469', '0x5908471'],
                         '0x59085aa', '0x5907e88'),
            'caller_3': ('ring_append_a', 'r15', ['0x590bde8'],
                         '0x590bf02', None),
            'caller_4': ('ring_append_b', 'r12',
                         ['0x591004e', '0x59101c9', '0x59101d1'],
                         '0x591030a', '0x590fbe8'),
        }
        for name, (twin, reg, reads, reassign, pred) in expected.items():
            with self.subTest(caller=name):
                entry = trace[name]
                self.assertEqual(entry['twin'], twin)
                self.assertEqual(entry['capture']['register'], reg)
                self.assertEqual(entry['forward_1']['callee'], '0x4eeed90')
                self.assertEqual(entry['forward_1']['argument'],
                                 'rcx (fourth argument)')
                self.assertEqual(entry['forward_2']['callee'], '0x51d1b00')
                self.assertEqual(entry['forward_2']['argument'],
                                 'rsi (second argument)')
                scan = entry['scan']
                self.assertEqual(
                    scan['capture_register_reads_before_reassignment'],
                    reads)
                self.assertEqual(scan['stores_of_value'], [])
                self.assertEqual(len(scan['rax_reads_to_first_forward']), 2)
                self.assertEqual(
                    entry['capture_reassignment']['site'], reassign)
                self.assertEqual(entry['verdict'], LOCAL)
                excluded = scan['excluded_block']
                if pred is None:
                    self.assertIsNone(excluded)
                else:
                    self.assertEqual(
                        excluded['sole_direct_predecessor'], pred)
                    self.assertTrue(
                        excluded['predecessor_precedes_twin_call'])

    def test_flow_verdict_cases(self):
        self.assertEqual(flow_verdict(2, [], True), LOCAL)
        self.assertEqual(flow_verdict(2, ['0x1'], True),
                         'stored in the caller')
        self.assertEqual(flow_verdict(2, [], False),
                         'capture register never reassigned')
        self.assertEqual(flow_verdict(1, [], True),
                         'unexpected forward count')
        self.assertEqual(flow_verdict(3, [], True),
                         'unexpected forward count')
        # A store dominates the other outcomes.
        self.assertEqual(flow_verdict(1, ['0x1'], False),
                         'stored in the caller')

    def mutate_va_byte(self, va, mask=0x01):
        changed = bytearray(self.data)
        changed[file_offset(self.data, va)] ^= mask
        return bytes(changed)

    def test_counterfactual_pinned_bytes_and_records(self):
        cases = (
            # caller_1's capture move (mov r15, rax).
            (0x5903FB0, 'Pinned instruction changed'),
            # caller_1's first forward call displacement.
            (0x5903FCC + 1, 'Resolved target changed'),
            # caller_1's second forward move (mov rsi, r15).
            (0x5904088, 'Pinned instruction changed'),
            # caller_2's capture move (mov r12, rax).
            (0x590821B, 'Pinned instruction changed'),
            # caller_2's excluded-block predecessor displacement.
            (0x5907E88 + 2, 'Pinned instruction changed'),
            # caller_3's reassignment (mov r15, [rsp+0xc8]).
            (0x590BF02, 'Pinned instruction changed'),
            # caller_4's twin call opcode: E8 becomes E9 and the
            # direct caller census loses the site.
            (0x590FF76, 'direct caller census changed'),
            # caller_4's lookup add (add rax, 0x40).
            (0x5910044, 'Pinned instruction changed'),
        )
        for va, message in cases:
            with self.subTest(va=hex(va)):
                with self.assertRaisesRegex(ValueError, message):
                    analyze(self.mutate_va_byte(va))


if __name__ == '__main__':
    unittest.main()
