import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))

from forward_callee_index_use_static import (
    PACKET,
    TARGET,
    analyze,
    authenticate,
    fwd1_verdict,
    fwd2_verdict,
    generate,
)
from elf_index import sections


def file_offset(data, va):
    for section in sections(data):
        if (section['type'] != 8 and section['address'] <= va
                < section['address'] + section['size']):
            return section['offset'] + va - section['address']
    raise AssertionError(f'VA not mapped: {va:#x}')


FWD1_DURABLE = ('durable: the index is stored as the map entry '
                'value on both the new-key append and the '
                'existing-key overwrite')
FWD2_DURABLE = ('durable: the index is stored as a sorted-set '
                'member key; a duplicate is reported (AL = 1) '
                'without a store')


class ForwardCalleeIndexUseStaticTests(unittest.TestCase):
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
            self.report['scope']['measured_denominator_bytes'], 1_290)
        self.assertEqual(
            sum(self.report['frames'][name]['bytes'] for name in
                ('forward_1', 'forward_2')),
            1_290,
        )
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'packet'
            generated = generate(TARGET, output)
            self.assertEqual(
                sum(len(windows) for windows in
                    generated['source_exports'].values()),
                2,
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
            boundaries['direct_e8_call_sites']['0x4eeed90'],
            ['0x4ed91d4', '0x4edd2bd', '0x5903fcc', '0x5908237',
             '0x590bd2c', '0x590ff97'],
        )
        self.assertEqual(
            boundaries['direct_e8_call_sites']['0x51d1b00'],
            ['0x481fbe2', '0x4a44879', '0x590408b', '0x59082f1',
             '0x590bdeb', '0x5910051'],
        )
        self.assertEqual(
            boundaries['direct_e9_references'],
            {'0x4eeed90': [], '0x51d1b00': []},
        )
        diagnostics = self.report['relocation_diagnostics']
        self.assertEqual(diagnostics['body_slot_references'], [])
        self.assertEqual(diagnostics['body_addend_references'], [])
        self.assertEqual(
            diagnostics['slot_bindings']['0x64df480'], '0x6355830')
        self.assertEqual(
            diagnostics['slot_bindings']['0x64e6258'], '0x43bbf00')

    def test_forward_1_trace_facts(self):
        trace = self.report['trace']['forward_1']
        self.assertEqual(trace['index_argument'],
                         'rcx (fourth argument)')
        self.assertEqual(trace['index_spill']['slot_read_sites'],
                         ['0x4eef005', '0x4eef03d'])
        self.assertEqual(trace['new_key_append']['index_store'],
                         '0x4eef00a')
        self.assertEqual(trace['existing_key_overwrite']['index_store'],
                         '0x4eef042')
        self.assertEqual(trace['entry_layout']['entry_bytes'], 24)
        self.assertEqual(trace['verdict'], FWD1_DURABLE)

    def test_forward_2_trace_facts(self):
        trace = self.report['trace']['forward_2']
        self.assertEqual(trace['index_argument'],
                         'rsi (second argument)')
        self.assertEqual(trace['capture']['register'], 'rbx')
        self.assertEqual(
            trace['capture']['read_sites'],
            ['0x51d1b35', '0x51d1bca', '0x51d1be2', '0x51d1c27'])
        self.assertEqual(trace['empty_handle_insert']['index_store'],
                         '0x51d1bca')
        self.assertEqual(trace['full_leaf_insert']['callee'],
                         '0x4c49f90')
        self.assertEqual(trace['verdict'], FWD2_DURABLE)

    def test_verdict_cases(self):
        self.assertEqual(fwd1_verdict(True, True), FWD1_DURABLE)
        self.assertEqual(fwd1_verdict(True, False),
                         'partial durable store')
        self.assertEqual(fwd1_verdict(False, True),
                         'partial durable store')
        self.assertEqual(fwd1_verdict(False, False), 'not stored')
        self.assertEqual(fwd2_verdict(True, True, True), FWD2_DURABLE)
        self.assertEqual(fwd2_verdict(True, False, False),
                         'partial durable store')
        self.assertEqual(fwd2_verdict(False, False, True),
                         'partial durable store')
        self.assertEqual(fwd2_verdict(False, False, False),
                         'not stored')

    def mutate_va_byte(self, va, mask=0x01):
        changed = bytearray(self.data)
        changed[file_offset(self.data, va)] ^= mask
        return bytes(changed)

    def test_counterfactual_pinned_bytes_and_records(self):
        cases = (
            # forward_1's entry spill of the index.
            (0x4EEED9E, 'Pinned instruction changed'),
            # forward_1's append store of the index.
            (0x4EEF00A, 'Pinned instruction changed'),
            # forward_1's overwrite store of the index.
            (0x4EEF042, 'Pinned instruction changed'),
            # forward_1's grow call displacement.
            (0x4EEEF90 + 1, 'Resolved target changed'),
            # forward_2's capture move (mov rbx, rsi).
            (0x51D1B07, 'Pinned instruction changed'),
            # forward_2's key comparison against the index.
            (0x51D1B35, 'Pinned instruction changed'),
            # forward_2's empty-handle store of the index.
            (0x51D1BCA, 'Pinned instruction changed'),
            # caller_1's forward_1 call opcode: E8 becomes E9 and
            # the direct caller census loses the site.
            (0x5903FCC, 'direct caller census changed'),
        )
        for va, message in cases:
            with self.subTest(va=hex(va)):
                with self.assertRaisesRegex(ValueError, message):
                    analyze(self.mutate_va_byte(va))


if __name__ == '__main__':
    unittest.main()
