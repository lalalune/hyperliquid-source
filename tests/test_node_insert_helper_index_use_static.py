import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))

from node_insert_helper_index_use_static import (
    PACKET,
    TARGET,
    analyze,
    authenticate,
    generate,
    helper_verdict,
    lookup_verdict,
)
from elf_index import sections


def file_offset(data, va):
    for section in sections(data):
        if (section['type'] != 8 and section['address'] <= va
                < section['address'] + section['size']):
            return section['offset'] + va - section['address']
    raise AssertionError(f'VA not mapped: {va:#x}')


NO_DIVERGENCE = ('no divergence: the index is stored as a node '
                 'key on every path that returns; forward_2\'s '
                 'unconditional total increment is matched by a '
                 'store on every returning path')
NOT_READBACK = ('not the forward-1 map readback: an array '
                'element resolver (0x58/0x70 strides), with no '
                'scrambled-hash probe')


class NodeInsertHelperIndexUseStaticTests(unittest.TestCase):
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
            self.report['scope']['measured_denominator_bytes'], 1_959)
        self.assertEqual(
            self.report['frames']['node_insert']['bytes'], 1_959)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'packet'
            generated = generate(TARGET, output)
            self.assertEqual(
                sum(len(windows) for windows in
                    generated['source_exports'].values()),
                3,
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
            boundaries['direct_e8_call_sites']['0x4c49f90'],
            ['0x51d1c2a', '0x51d4a4a', '0x51d4baa'],
        )
        self.assertEqual(
            len(boundaries['direct_e8_call_sites']['0x4da81b0']), 14)
        self.assertEqual(
            len(boundaries['direct_e8_call_sites']['0x4da7880']), 12)
        self.assertEqual(
            boundaries['direct_e9_references'],
            {'0x4c49f90': [], '0x4da7880': [], '0x4da81b0': []},
        )
        diagnostics = self.report['relocation_diagnostics']
        self.assertEqual(diagnostics['body_slot_references'], [])
        self.assertEqual(diagnostics['body_addend_references'], [])
        self.assertEqual(
            diagnostics['slot_bindings']['0x64df480'], '0x6355830')
        self.assertEqual(
            diagnostics['glob_dat_bindings']['0x64df568'], 'memmove')
        self.assertEqual(
            diagnostics['glob_dat_bindings']['0x64df508'], 'memcpy')

    def test_helper_trace_facts(self):
        trace = self.report['trace']['node_insert']
        self.assertEqual(trace['index_argument'],
                         'rdx (third argument)')
        self.assertEqual(trace['capture']['site'], '0x4c49f9e')
        self.assertEqual(
            trace['capture']['index_valued_read_sites'],
            ['0x4c49fee', '0x4c4a119'])
        self.assertEqual(
            trace['capture']['compare_sites'],
            ['0x4c4a3fe', '0x4c4a51d', '0x4c4a5c7'])
        self.assertEqual(trace['fast_path']['index_store'], '0x4c49fee')
        self.assertEqual(trace['leaf_split']['index_store'], '0x4c4a119')
        self.assertEqual(
            trace['every_path_store_proof']['store_sites'],
            ['0x4c49fee', '0x4c4a119'])
        self.assertEqual(trace['exits']['ret'], '0x4c4a5f6')
        self.assertEqual(
            trace['exits']['reachable_ud2_terminals'],
            ['0x4c4a6c8', '0x4c4a70c'])
        self.assertEqual(trace['exits']['instruction_count'], 473)
        self.assertEqual(trace['verdict'], NO_DIVERGENCE)

    def test_lookup_trace_facts(self):
        for name, stride58, stride70 in (
                ('lookup_a', '0x4da8289', '0x4da834b'),
                ('lookup_b', '0x4da7959', '0x4da7a1b')):
            trace = self.report['trace'][name]
            self.assertEqual(trace['fast_path']['stride_site'], stride58)
            self.assertEqual(trace['slow_path']['stride_site'], stride70)
            self.assertEqual(
                trace['probe_signature']['hash_constant_present'], False)
            self.assertEqual(trace['probe_signature']['rol_0x14_sites'], [])
            self.assertEqual(trace['verdict'], NOT_READBACK)

    def test_verdict_cases(self):
        self.assertEqual(helper_verdict(True, 0, True), NO_DIVERGENCE)
        self.assertEqual(helper_verdict(False, 0, True),
                         'store-less returning path exists')
        self.assertEqual(helper_verdict(False, 1, False),
                         'store-less returning path exists')
        self.assertEqual(helper_verdict(True, 1, True),
                         'unresolved divergence surface')
        self.assertEqual(helper_verdict(True, 0, False),
                         'unresolved divergence surface')
        self.assertEqual(lookup_verdict(False, True, True), NOT_READBACK)
        self.assertEqual(lookup_verdict(True, True, True),
                         'map readback candidate')
        self.assertEqual(lookup_verdict(True, False, False),
                         'map readback candidate')
        self.assertEqual(lookup_verdict(False, False, True),
                         'inconclusive element resolution')

    def mutate_va_byte(self, va, mask=0x01):
        changed = bytearray(self.data)
        changed[file_offset(self.data, va)] ^= mask
        return bytes(changed)

    def test_counterfactual_pinned_bytes_and_records(self):
        cases = (
            # the helper's capture of the index (mov r12, rdx).
            (0x4C49F9E, 'Pinned instruction changed'),
            # the fast-path store of the index.
            (0x4C49FEE, 'Pinned instruction changed'),
            # the leaf-split store of the index.
            (0x4C4A119, 'Pinned instruction changed'),
            # the rewrite that retires the index register.
            (0x4C4A1F4, 'Pinned instruction changed'),
            # forward_2's helper call displacement: the call
            # no longer resolves to the helper, so the direct
            # caller census loses the site first.
            (0x51D1C2A + 1, 'direct caller census changed'),
            # caller_1's lookup call opcode: E8 becomes E9 and
            # the direct caller census loses the site.
            (0x5904079, 'direct caller census changed'),
            # lookup_a's 0x58 stride multiply.
            (0x4DA8289, 'Pinned instruction changed'),
            # an uncited byte in a downstream body (the alloc
            # helper, which is digest-pinned only): only the
            # body digest catches it.
            (0x6355850, 'body changed'),
        )
        for va, message in cases:
            with self.subTest(va=hex(va)):
                with self.assertRaisesRegex(ValueError, message):
                    analyze(self.mutate_va_byte(va))


if __name__ == '__main__':
    unittest.main()
