import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))

from forward1_map_readback_static import (
    PACKET,
    READBACK,
    TARGET,
    analyze,
    authenticate,
    generate,
    readback_verdict,
)
from elf_index import sections


def file_offset(data, va):
    for section in sections(data):
        if (section['type'] != 8 and section['address'] <= va
                < section['address'] + section['size']):
            return section['offset'] + va - section['address']
    raise AssertionError(f'VA not mapped: {va:#x}')


class Forward1MapReadbackStaticTests(unittest.TestCase):
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
            self.report['scope']['measured_denominator_bytes'], 1_419)
        self.assertEqual(self.report['frames']['contains']['bytes'], 319)
        self.assertEqual(self.report['frames']['remove']['bytes'], 1_100)
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
            len(boundaries['direct_e8_call_sites']['0x4ef4010']), 81)
        self.assertEqual(
            boundaries['direct_e8_call_sites']['0x4e37a10'],
            ['0x58e1503', '0x58e2043', '0x58e2bcd', '0x58e380d'])
        self.assertEqual(
            boundaries['direct_e8_call_sites']['0x4eeed90'],
            ['0x4ed91d4', '0x4edd2bd', '0x5903fcc', '0x5908237',
             '0x590bd2c', '0x590ff97'])
        self.assertEqual(
            boundaries['direct_e9_references'],
            {'0x4e37a10': [], '0x4eeed90': [], '0x4ef4010': []})
        self.assertEqual(
            boundaries['relative_addend_references'],
            {'0x4e37a10': [], '0x4eeed90': [], '0x4ef4010': []})
        census = boundaries['probe_signature_census']
        self.assertEqual(census['hash_constant_raw_hits'], 114)
        self.assertEqual(census['fdes_with_constant'], 84)
        self.assertEqual(
            sorted(census['signature_fdes']),
            ['0x23d4790', '0x23d76c0', '0x23e4c80', '0x4e37a10',
             '0x4eeed90', '0x4ef4010'])
        diagnostics = self.report['relocation_diagnostics']
        self.assertEqual(diagnostics['body_slot_references'], [])
        self.assertEqual(diagnostics['body_addend_references'], [])
        self.assertEqual(
            diagnostics['slot_bindings']['0x64df6d0'], '0x141e2da')
        self.assertEqual(
            diagnostics['slot_bindings']['0x64df520'], '0x1681da0')

    def test_contains_trace_facts(self):
        trace = self.report['trace']['contains']
        self.assertEqual(trace['entry_value_load_sites'], [])
        self.assertEqual(trace['memory_store_sites'], [])
        self.assertEqual(trace['general_path']['key_compare'], '0x4ef40d4')
        self.assertEqual(trace['general_path']['hash_constant'], '0x4ef4042')
        self.assertEqual(trace['found_exit'], {'site': '0x4ef4108', 'eax': 1})
        self.assertEqual(
            trace['not_found_exit'], {'site': '0x4ef4115', 'eax': 0})
        self.assertEqual(trace['direct_call_sites'], 81)

    def test_remove_trace_facts(self):
        trace = self.report['trace']['remove']
        self.assertEqual(
            trace['length_one_path']['hash_computed'], False)
        self.assertEqual(
            trace['length_one_path']['value_loaded_for_return'],
            '0x4e37a4a')
        self.assertEqual(
            trace['found_path']['removed_value_load'], '0x4e37c68')
        self.assertEqual(
            trace['found_path']['value_return_register'], 'rdx')
        self.assertEqual(
            trace['found_path']['exit'], {'site': '0x4e37dd3', 'eax': 1})
        caller = self.report['trace']['remove_caller_a']
        self.assertEqual(caller['removed_index_capture'], '0x58e1512')
        self.assertEqual(caller['slab_stride'], '0x110')
        inline = self.report['trace']['inline_get']
        self.assertEqual(inline['value_load'], '0x23e5454')
        insert = self.report['trace']['insert_caller_1']
        self.assertEqual(insert['value_loads'], ['0x5904adc', '0x5904eab'])
        self.assertEqual(self.report['trace']['verdict'], READBACK)

    def test_verdict_cases(self):
        self.assertEqual(readback_verdict([], False, True), READBACK)
        self.assertEqual(
            readback_verdict(['0x1'], False, True),
            'a standalone get FDE exists')
        self.assertEqual(
            readback_verdict([], True, True),
            'contains reads the entry value')
        self.assertEqual(
            readback_verdict([], False, False),
            'remove does not return the entry value')

    def mutate_va_byte(self, va, mask=0x01):
        changed = bytearray(self.data)
        changed[file_offset(self.data, va)] ^= mask
        return bytes(changed)

    def test_counterfactual_pinned_bytes_and_records(self):
        cases = (
            # contains' hash constant (the movabs opcode byte).
            (0x4EF4042, 'Pinned instruction changed'),
            # contains' general-path key compare.
            (0x4EF40D4, 'Pinned instruction changed'),
            # remove's removed-value load.
            (0x4E37C68, 'Pinned instruction changed'),
            # remove's found exit (mov eax, 1).
            (0x4E37DD3, 'Pinned instruction changed'),
            # insert_caller_1's inlined value load.
            (0x5904ADC, 'Pinned instruction changed'),
            # remove_caller_a's call to remove (pinned call bytes).
            (0x58E1503, 'Pinned instruction changed'),
            # remove_caller_b's call displacement: the pinned
            # call no longer resolves to remove.
            (0x58E2044, 'Pinned call target changed'),
            # an uncited contains call site outside every spec:
            # the direct caller census loses the site first.
            (0x5185C28, 'direct caller census changed'),
            # an uncited byte in a boundary body (forward_1,
            # digest-pinned only): only the body digest catches it.
            (0x4EEED95, 'body changed'),
            # an uncited byte in twin_probe_a (digest-pinned).
            (0x23D4890, 'body changed'),
        )
        for va, message in cases:
            with self.subTest(va=hex(va)):
                with self.assertRaisesRegex(ValueError, message):
                    analyze(self.mutate_va_byte(va))


if __name__ == '__main__':
    unittest.main()
