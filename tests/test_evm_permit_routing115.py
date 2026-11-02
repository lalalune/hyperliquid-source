import contextlib
import io
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import evm_permit_routing115 as evidence

PACKET = ROOT / 'research/work-items/RE-011-evm-permit-routing-115'


class PermitPathEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # A missing target is an error, never a skip.
        cls.data = evidence.TARGET.read_bytes()
        evidence.check_digest(cls.data)
        cls.sections = evidence.sections(cls.data)
        cls.relocations = evidence.parse_relocations(cls.data, cls.sections)
        cls.outputs = evidence.build(cls.data)
        cls.record = json.loads(cls.outputs['evidence.json'])

    def test_reproduced_evidence_matches_all_generated_files(self):
        self.assertEqual(set(self.outputs), {
            'evidence.json', 'branches.tsv', 'calls.tsv', 'states.tsv',
            'methods.tsv',
        })
        for name, actual in self.outputs.items():
            with self.subTest(name=name):
                self.assertEqual(actual, (PACKET / name).read_bytes())

    def test_corrupt_target_is_rejected_before_output_creation(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            bad, output = root / 'bad.elf', root / 'result'
            bad.write_bytes(b'\x7fELF\x02\x01' + bytes(64))
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(evidence.main(['--binary', str(bad), '--out', str(output)]), 2)
            self.assertFalse(output.exists())
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            evidence.check_digest(b'corrupted capture')

    def test_missing_target_is_an_error(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            output = root / 'result'
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(evidence.main(['--binary', str(root / 'missing'), '--out', str(output)]), 2)
            self.assertFalse(output.exists())

    def test_nobits_and_ambiguous_section_ranges_are_rejected(self):
        disk = bytes(range(32))
        progbits = {'name': 'file', 'type': 1, 'address': 0x1000, 'offset': 4, 'size': 8}
        nobits = {'name': 'no-file', 'type': 8, 'address': 0x1000, 'offset': 0, 'size': 8}
        self.assertEqual(evidence.read_va(disk, [progbits, nobits], 0x1001, 3), b'\x05\x06\x07')
        with self.assertRaises(ValueError):
            evidence.read_va(disk, [nobits], 0x1000, 1)
        with self.assertRaises(ValueError):
            evidence.va_offset([progbits, dict(progbits, name='other')], 0x1000, 1)
        for va, size in [(0x0fff, 1), (0x1007, 2), (0x1000, 0), (-1, 1)]:
            with self.subTest(va=va, size=size), self.assertRaises(ValueError):
                evidence.va_offset([progbits], va, size)

    def test_fde_extent_and_exclusive_end(self):
        fdes = {f['start_va']: f for f in self.record['functions']}
        gate = fdes['0x2a04070']
        self.assertEqual(gate['end_va_exclusive'], '0x2a0465c')
        start, end = int(gate['start_va'], 16), int(gate['end_va_exclusive'], 16)
        body = evidence.read_va(self.data, self.sections, start, end - start)
        self.assertEqual(evidence.digest(body), gate['body_sha256'])
        selected = {start: ({'start': start, 'end': end}, {})}
        self.assertEqual(evidence.owner(selected, end - 1), start)
        for address in (start - 1, end):
            with self.subTest(address=address), self.assertRaises(ValueError):
                evidence.owner(selected, address)

    def test_exact_witness_corruption_and_truncation(self):
        label, site, expected_hex = next(w for w in evidence.WITNESSES if w[0] == 'selector_read')
        expected = bytes.fromhex(expected_hex)
        raw = evidence.read_va(self.data, self.sections, site, len(expected))
        self.assertEqual(evidence.expect_bytes(raw, expected), expected)
        modified = bytearray(raw)
        modified[-1] ^= 1
        for candidate in (bytes(modified), raw[:-1]):
            with self.assertRaises(ValueError):
                evidence.expect_bytes(candidate, expected)

    def test_conditional_displacements_and_corruption(self):
        site = 0x2e38ca2
        raw = evidence.read_va(self.data, self.sections, site, 6)
        item = evidence.decode_branch(raw, site)
        self.assertEqual((item['condition'], item['target'], item['fallthrough']),
                         ('equal', 0x2e38f6c, 0x2e38ca8))
        backwards = evidence.decode_branch(b'\x75\xfc', 0x1000)
        self.assertEqual(backwards['target'], 0x0ffe)
        for invalid in (b'', b'\x0f\x84\x01', b'\xe8\x00\x00\x00\x00'):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                evidence.decode_branch(invalid, 0x1000)

    def test_direct_and_indirect_calls_decode_signed_displacements(self):
        direct = evidence.decode_relative(evidence.read_va(self.data, self.sections, 0x2a2a2dd, 6), 0x2a2a2dd)
        indirect = evidence.decode_relative(evidence.read_va(self.data, self.sections, 0x2a3549a, 6), 0x2a3549a)
        self.assertEqual((direct['kind'], direct['target']), ('call_rel32', 0x2a04070))
        self.assertEqual((indirect['kind'], indirect['target']), ('call_rip_slot', 0x64e22b0))
        for invalid in (b'\xe8\x00\x00\x00', b'\xff\x14\x00\x00\x00\x00'):
            with self.assertRaises(ValueError):
                evidence.decode_relative(invalid, 0x1000)

    def test_relative_relocations_and_dynamic_comparator(self):
        self.assertEqual(evidence.relative_target(self.relocations, 0x64509c0), 0x2d03200)
        self.assertEqual(evidence.relative_target(self.relocations, 0x6445880), 0x2a2a0e0)
        self.assertEqual(evidence.relative_target(self.relocations, 0x64e22b0), 0x175d250)
        comparator = self.relocations[0x64df9f8]
        self.assertEqual((comparator['type'], comparator['symbol']), (6, 11))
        symbol = evidence.dynamic_symbol(self.data, self.sections, comparator['symbol'])
        self.assertEqual((symbol['name'], symbol['section_index']), ('bcmp', 0))
        with self.assertRaises(ValueError):
            evidence.relative_target(self.relocations, 0x64df9f8)
        with self.assertRaises(ValueError):
            evidence.relative_target({}, 0x64509c0)
        altered = {0x64509c0: dict(self.relocations[0x64509c0], type=6)}
        with self.assertRaises(ValueError):
            evidence.relative_target(altered, 0x64509c0)

    def test_duplicate_relocation_slots_fail_closed(self):
        row = struct.pack('<QQq', 0x1000, 8, 0x2000)
        sec = {'name': '.rela.dyn', 'type': 4, 'offset': 0, 'size': len(row) * 2}
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            evidence.parse_relocations(row + row, [sec])
        with self.assertRaises(ValueError):
            evidence.parse_relocations(row, [dict(sec, size=23)])

    def test_concrete_method_tables_and_selected_inner_polls(self):
        rows = {r['method']: r for r in self.record['routes']}
        self.assertEqual(set(rows), {'eth_call', 'eth_estimateGas'})
        self.assertEqual((rows['eth_call']['literal_length'], rows['eth_call']['registration_target'],
                          rows['eth_call']['callback_target'], rows['eth_call']['future_poll_target'],
                          rows['eth_call']['inner_poll_target']),
                         (8, '0x2d02f60', '0x2d03200', '0x2d087e0', '0x2a2a0e0'))
        self.assertEqual((rows['eth_estimateGas']['literal_length'], rows['eth_estimateGas']['registration_target'],
                          rows['eth_estimateGas']['callback_target'], rows['eth_estimateGas']['future_poll_target'],
                          rows['eth_estimateGas']['inner_poll_target']),
                         (15, '0x2d02a20', '0x2d03ba0', '0x2d062f0', '0x2a225c0'))
        self.assertEqual([rows[n]['descriptor_tag'] for n in ('eth_call', 'eth_estimateGas')], [1, 1])
        self.assertEqual([rows[n]['initialisation']['selector'] for n in ('eth_call', 'eth_estimateGas')], [0, 0])
        self.assertEqual(self.record['filter_selector']['selector'], 1)

    def test_merge_precheck_rejects_existing_name_before_writer(self):
        self.assertEqual(evidence.relative_target(self.relocations, 0x64e88b0), 0x2f1bf50)
        self.assertEqual(evidence.call_at(self.data, self.sections, 0x2f1bf6e)['target'], 0x2f1b8e0)
        self.assertEqual(evidence.read_va(self.data, self.sections, 0x2f1baa1, 2), b'\xb0\x01')
        self.assertEqual(evidence.read_va(self.data, self.sections, 0x2f1baec, 2), b'\x31\xc0')
        self.assertEqual(evidence.read_va(self.data, self.sections, 0x2f1bf87, 7),
                         bytes.fromhex('49c70603000000'))
        self.assertEqual(evidence.read_va(self.data, self.sections, 0x2f1bfba, 7),
                         bytes.fromhex('49c70600000000'))
        expected = [(0x2f1baa5, 'equal', 0x2f1baee),
                    (0x2f1bf75, 'equal', 0x2f1bf87),
                    (0x2e37920, 'not equal', 0x2e37ae1),
                    (0x2e37b0a, 'not equal', 0x2e38289),
                    (0x2a32334, 'equal', 0x2a323ca)]
        for site, condition, target in expected:
            with self.subTest(site=site):
                branch = evidence.decode_branch(evidence.read_va(self.data, self.sections, site, 6), site)
                self.assertEqual((branch['condition'], branch['target']), (condition, target))
        anchors = {a['text'] for a in self.record['literal_anchors']}
        self.assertIn('called `Result::unwrap()` on an `Err` value', anchors)

    def test_map_transport_closures_and_pointer_offsets(self):
        transport = self.record['transport']
        self.assertEqual((transport['boxed_vtable_va'], transport['boxed_constructor_va'],
                          transport['state_vtable_va'], transport['request_future_vtable_va']),
                         ('0x6450488', '0x2dd6ae0', '0x6451368', '0x6452f78'))
        targets = {row['role']: row['target_va'] for row in transport['closure_slots']}
        self.assertEqual(targets, {
            'router_box_clone': '0x2cfe810', 'router_box_factory': '0x2cfe4c0',
            'router_box_wrapper': '0x2cfe6a0', 'router_request_factory': '0x2e4c690',
            'router_state_clone': '0x2e332e0', 'request_future_poll': '0x2e3cb60',
        })
        self.assertEqual(transport['map_pointer_offsets'], {
            'final_router_stack': 0x70, 'router_staging_stack': 0x10,
            'box_and_cloned_state': 0x10, 'request_future': 0x120,
            'request_polled_map': 0x318, 'lookup_future_reference': 0xe8,
        })
        selected = evidence.select_fdes(self.data, self.sections)
        modified = dict(self.relocations)
        modified[0x6452f90] = dict(modified[0x6452f90], addend=0x2a04070)
        with self.assertRaisesRegex(ValueError, 'anchored FDE'):
            evidence.transport_record(self.data, self.sections, modified, selected)

    def test_transport_displacement_rejects_wrong_opcode_and_bounds(self):
        raw = bytes.fromhex('488d8318030000')
        section = {'name': 'file', 'type': 1, 'address': 0x1000, 'offset': 0, 'size': len(raw)}
        self.assertEqual(evidence.displacement(raw, [section], 0x1000, b'\x48\x8d\x83', 4), 0x318)
        for opcode, width in ((b'\x48\x8d\x82', 4), (b'\x48\x8d\x83', 2),
                              (b'\x48\x8d\x83\x00', 4)):
            with self.subTest(opcode=opcode, width=width), self.assertRaises(ValueError):
                evidence.displacement(raw, [section], 0x1000, opcode, width)

    def test_selector_instruction_requires_actual_base_and_store(self):
        for site, base in ((0x2a2a2ba, 0x2a2a2c8), (0x2a22780, 0x2a22790)):
            result = evidence.selector_word(self.data, self.sections, site, base)
            self.assertEqual((result['initial_state'], result['state_offset'], result['selector']), (0, 0x1f2, 0))
        self.assertEqual(evidence.selector_word(self.data, self.sections, 0x2a2d502, 0x2a2d50d)['selector'], 1)
        with self.assertRaises(ValueError):
            evidence.selector_word(self.data, self.sections, 0x2a2a2bb, 0x2a2a2c8)
        with self.assertRaises(ValueError):
            evidence.selector_word(self.data, self.sections, 0x2a2a2ba, 0x2a2a2c9)

    def test_state_table_targets_and_out_of_range_corruption(self):
        base = 0x601224
        raw = evidence.read_va(self.data, self.sections, base, 16)
        values = evidence.decode_table(raw, base, 0x2a04070, 0x2a0465c, 4)
        self.assertEqual(values, [0x2a040a1, 0x2a04535, 0x2a04528, 0x2a0416e])
        modified = bytearray(raw)
        modified[:4] = struct.pack('<i', -base - 1)
        for bad, count in ((bytes(modified), 4), (raw[:-1], 4), (raw, 0)):
            with self.assertRaises(ValueError):
                evidence.decode_table(bad, base, 0x2a04070, 0x2a0465c, count)

    def test_selector_capacity_cap_is_read_from_instruction(self):
        cap = self.record['selector_capacity_cap']
        self.assertEqual(cap['site_va'], '0x175d300')
        self.assertEqual(cap['value'], '0x1fffffffffffffff')
        self.assertEqual(bytes.fromhex(cap['bytes'])[2:], struct.pack('<Q', 0x1fffffffffffffff))

    def test_filter_limit_is_unsigned_and_boundary_is_inclusive(self):
        rows = self.record['filter_comparisons']
        self.assertEqual([r['unsigned_limit'] for r in rows], [1000] * 5)
        self.assertEqual([r['object_offset'] for r in rows], [0x410, 0x458, 0x4a0, 0x4e8, 0x530])
        for site in (0x2a2cfb7, 0x2a2cfc5, 0x2a2cfd3, 0x2a2cfe1):
            branch = evidence.decode_branch(evidence.read_va(self.data, self.sections, site, 6), site)
            self.assertEqual((branch['condition'], branch['target']), ('above', 0x2a2cff5))
        last = evidence.decode_branch(evidence.read_va(self.data, self.sections, 0x2a2cfef, 6), 0x2a2cfef)
        self.assertEqual((last['condition'], last['target']), ('below or equal', 0x2a2d2a1))

    def test_location_suffix_is_binary_backed(self):
        row = evidence.location_record(self.data, self.sections, self.relocations, 0x640f7e8)
        self.assertEqual((row['path_suffix'], row['line'], row['column']),
                         ('evm_rpc/src/expensive_call_limiter.rs', 107, 24))
        with self.assertRaises(ValueError):
            evidence.location_record(self.data, self.sections, self.relocations, 0)

    def test_indirect_callback_opcode_mismatch_fails(self):
        self.assertEqual(evidence.indirect_offset(self.data, self.sections, 0x2e3913b,
                                                  b'\x41\xff\x54\x24'), 0x28)
        with self.assertRaises(ValueError):
            evidence.indirect_offset(self.data, self.sections, 0x2e3913b, b'\xff\x50')


if __name__ == '__main__':
    unittest.main()
