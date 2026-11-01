"""Static, target-grounded checks; no subprocesses and no target execution."""
import copy
import hashlib
import json
from pathlib import Path
import struct
import unittest

from tools import aws_json_envelope94 as m


class AwsJsonEnvelopeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = m.Image((m.ROOT / 'artifacts/node/94/hl-node').read_bytes())
        cls.result = m.collect(cls.image)
        cls.at = {r['va']: r for r in cls.result['instructions']}

    def overlay(self, va, raw):
        """Bypass only the outer digest to exercise structural checks on changed bytes."""
        changed = copy.copy(self.image)
        original = self.image.read
        def read(start, size):
            data = bytearray(original(start, size))
            lo, hi = max(start, va), min(start + size, va + len(raw))
            if lo < hi:
                data[lo-start:hi-start] = raw[lo-va:hi-va]
            return bytes(data)
        changed.read = read
        return changed

    def test_identity_and_complete_selected_ranges(self):
        self.assertEqual(hashlib.sha256(self.image.data).hexdigest(), m.DIGEST)
        self.assertEqual(len(self.result['functions']), 21)
        self.assertEqual(sum(f['byte_count'] for f in self.result['functions']), 8092)
        for f in self.result['functions']:
            rows = [r for r in self.result['instructions'] if r['function'] == f['entry']]
            self.assertEqual(rows[0]['va'], f['entry'])
            self.assertEqual(rows[-1]['va'] + rows[-1]['size'], f['end'])
            self.assertEqual(bytes.fromhex(''.join(r['bytes'] for r in rows)),
                             self.image.read(f['entry'], f['byte_count']))

    def test_bad_digest_precedes_elf_parsing(self):
        with self.assertRaisesRegex(m.EvidenceError, 'SHA-256 mismatch'):
            m.Image(b'not an ELF')

    def test_file_backing_controls(self):
        for va, size in [(-1, 1), (0x13f3820, -1), (1 << 64, 1)]:
            with self.subTest(va=va, size=size), self.assertRaises(m.EvidenceError):
                self.image.read(va, size)
        bss = next(s for s in self.image.sections if s['name'] == '.bss')
        with self.assertRaises(m.EvidenceError):
            self.image.read(bss['address'], 1)
        changed = copy.copy(self.image)
        changed.sections = self.image.sections + [next(s for s in self.image.sections
                                                       if s['name'] == '.text')]
        with self.assertRaises(m.EvidenceError):
            changed.read(0x13f3820, 1)

    def test_decoder_rejects_truncation_unknown_and_interior_target(self):
        for raw in (b'\xe8\x00', b'\x0f\xff', b'\xeb\xff', b'\x48'):
            with self.subTest(raw=raw), self.assertRaises(m.EvidenceError):
                m.decode(raw, 0x1000)

    def test_whitespace_delimiters_and_depth_corruption(self):
        cases = [(0x13f3846, b'\x01', 'whitespace'),
                 (0x13f3891, b'\x23', 'delimiters'),
                 (0x13f3966, b'\x3b', 'delimiters'),
                 (0x13f38d0, b'\x49', 'state field'),
                 (0x13f39a7, b'\xfe', 'restore guard')]
        for va, raw, message in cases:
            with self.subTest(va=hex(va)), self.assertRaisesRegex(m.EvidenceError, message):
                m.collect(self.overlay(va, raw), body_gates=False)

    def test_enum_code_table_is_identity_and_closed(self):
        rows = self.result['enum_dispatch']
        self.assertEqual([r['output_tag'] for r in rows], list(range(76)))
        self.assertEqual(len({r['target'] for r in rows}), 76)
        first, second = rows[:2]
        for target in (first['target'] + 1, second['target'], 0):
            raw = struct.pack('<i', target - first['slot'])
            with self.subTest(target=target), self.assertRaises(m.EvidenceError):
                m.collect(self.overlay(first['slot'], raw), body_gates=False)

    def test_classifier_boundary_and_out_of_body_mutation(self):
        rows = self.result['classifier']
        self.assertEqual([r['byte'] for r in rows], list(range(91, 124)))
        self.assertEqual({r['byte']:r['target'] for r in rows if r['byte'] in (91, 123)},
                         {91:0x14a00a6, 123:0x14a009d})
        with self.assertRaisesRegex(m.EvidenceError, 'classifier target'):
            m.collect(self.overlay(rows[0]['slot'], struct.pack('<i', 0)), body_gates=False)

    def test_relocation_and_expected_text_controls(self):
        for slot in (0x576eca0, 0x566e8e8):
            changed = copy.copy(self.image)
            changed.relocations = dict(self.image.relocations)
            changed.relocations[slot] += 1
            with self.subTest(slot=slot), self.assertRaises(m.EvidenceError):
                m.collect(changed, body_gates=False)
        with self.assertRaisesRegex(m.EvidenceError, 'expected-type text'):
            m.collect(self.overlay(0x264f73, b'X'), body_gates=False)

    def test_body_hash_catches_unmodelled_change(self):
        # Push/pop register change has the same instruction length and leaves the
        # semantic-anchor checks intact, but must fail the selected-body gate.
        with self.assertRaisesRegex(m.EvidenceError, 'body bytes changed'):
            m.collect(self.overlay(0x1401120, b'\x51'))

    def test_error_precedence_and_state_restoration_cfg(self):
        queries = {q['proposition']:q for q in m.control_flow(self.result)['propositions']}
        self.assertTrue(queries['unit_failure_to_error_return']['reachable'])
        self.assertFalse(queries['close_error_requires_prior_restore']['reachable'])
        self.assertFalse(queries['object_close_error_rewrites_result_tag']['reachable'])
        changed = copy.deepcopy(self.result)
        at = {r['va']:r for r in changed['instructions']}
        at[0x13f39b1]['kind'] = 'jump'
        at[0x13f39b1]['target'] = 0x13f39b7  # skip restore store
        with self.assertRaises(m.EvidenceError):
            m.control_flow(changed)

    def test_error_routes_preserve_position_constructor_distinction(self):
        routes = {r['role']:r for r in self.result['explicit_errors']}
        self.assertEqual(len(routes), 29)
        self.assertEqual((routes['object_missing_colon_at_eof']['code'],
                          routes['object_missing_colon_at_eof']['constructor']), (3, 0x149edb0))
        self.assertEqual((routes['object_missing_close_at_eof']['code'],
                          routes['object_missing_close_at_eof']['constructor']), (3, 0x14a0130))
        self.assertEqual(routes['object_depth_exhausted']['code'], 24)
        self.assertEqual(routes['unit_invalid_null_suffix']['code'], 9)

    def test_lsda_cleanup_ranges_and_corruption(self):
        tables = m.exception_sites(self.image, self.result)
        self.assertEqual(len(tables), 8)
        self.assertEqual(sum(len(t['sites']) for t in tables), 38)
        repair = next(t for t in tables if t['function'] == 0x14470d0)
        self.assertEqual(repair['sites'][0]['landing'], 0x144710a)
        for va, raw in [(repair['lsda'], b'\x00'), (repair['lsda']+2, b'\x02'),
                        (repair['lsda']+3, b'\x7f'), (repair['lsda']+6, b'\x01')]:
            with self.subTest(va=va), self.assertRaises((m.EvidenceError, ValueError)):
                m.exception_sites(self.overlay(va, raw), self.result)

    def test_literal_consumption_and_position_operand_controls(self):
        rows = {r['role']:r for r in m.contracts(self.result)}
        self.assertEqual(bytes(rows['unit_'+name+'_byte']['observed']
                               for name in ('first','second','third','fourth')), b'null')
        self.assertEqual(rows['at_newline_byte']['observed'], 10)
        for va in (0x14b6f07, 0x14a0198, 0x14ae7cd, 0x144710d):
            changed = copy.deepcopy(self.result)
            next(r for r in changed['instructions'] if r['va']==va)['immediate'] ^= 1
            with self.subTest(va=va), self.assertRaisesRegex(m.EvidenceError, 'semantic operand'):
                m.contracts(changed)

    def test_fde_endpoint_and_duplicate_rejection(self):
        changed = copy.copy(self.image)
        changed.fdes = [dict(f) for f in self.image.fdes]
        next(f for f in changed.fdes if f['start']==0x13f3820)['end'] += 1
        with self.assertRaisesRegex(m.EvidenceError, 'FDE endpoint'):
            m.collect(changed)
        changed.fdes = self.image.fdes + [self.image.fde(0x13f3820)]
        with self.assertRaisesRegex(m.EvidenceError, 'duplicate selected FDE'):
            m.collect(changed)

    def test_entry_byte_partition_does_not_accept_reference_sequence_shape(self):
        routes = m.entry_partition(self.result)['routes']
        self.assertEqual(routes['whitespace'], [9,10,13,32])
        self.assertEqual(routes['quoted_identifier'], [34])
        self.assertEqual(routes['tagged_unit_object'], [123])
        self.assertIn(91, routes['syntax_error'])
        self.assertIn(125, routes['syntax_error'])
        self.assertEqual(sorted(sum(routes.values(), [])), list(range(256)))
        changed = copy.deepcopy(self.result)
        next(r for r in changed['instructions'] if r['va']==0x13f38c7)['target'] = 0x13f3894
        with self.assertRaisesRegex(m.EvidenceError, 'entry byte routing'):
            m.entry_partition(changed)

    def test_map_mutation_and_failure_cleanup_contracts(self):
        rows = {r['role']:r for r in m.contracts(self.result)}
        self.assertEqual(rows['map_key_must_be_quote']['observed'], 34)
        self.assertEqual(rows['optional_error_tag']['observed'], 2)
        self.assertEqual(rows['string_error_sentinel']['observed'], 1 << 63)
        self.assertEqual(rows['leaf_key_byte_store']['observed']['disp'], 276)
        queries = {q['proposition']:q for q in m.control_flow(self.result)['propositions']}
        self.assertTrue(queries['duplicate_key_replacement_bypasses_count_increment']['reachable'])
        for name in ('map_key_error_requires_depth_restore',
                     'map_value_error_requires_depth_restore',
                     'new_map_value_requires_count_increment',
                     'late_close_error_drops_successful_map'):
            self.assertFalse(queries[name]['reachable'])
        changed = copy.deepcopy(self.result)
        at = {r['va']:r for r in changed['instructions']}
        at[0x14caff1]['target'] = 0x14cb0c7
        with self.assertRaisesRegex(m.EvidenceError, 'control-flow proposition'):
            m.control_flow(changed)

    def test_dynamic_symbol_and_map_operand_corruption(self):
        changed = copy.copy(self.image)
        changed.symbols = dict(self.image.symbols, **{})
        changed.symbols[0x576dfe0] = 'memmove'
        with self.assertRaisesRegex(m.EvidenceError, 'external symbol relocation'):
            m.collect(changed, body_gates=False)
        changed_result = copy.deepcopy(self.result)
        next(r for r in changed_result['instructions'] if r['va']==0x14bb39f)['immediate'] = 123
        with self.assertRaisesRegex(m.EvidenceError, 'semantic operand'):
            m.contracts(changed_result)

    def test_selected_register_classes_and_signed_immediate(self):
        # Target bytes 49 c7 c1 ff ff ff ff assign the signed search sentinel.
        sentinel = self.at[0x14caf77]
        self.assertEqual((sentinel['rm'],sentinel['width'],sentinel['immediate']), ('r9',64,-1))
        self.assertNotIn('reg', sentinel)  # ModRM extension is not an operand register.
        self.assertEqual(self.at[0x14cafe5]['reg'], 'xmm0')
        self.assertEqual(self.at[0x14cafe5]['width'], 128)

    def test_generated_evidence_matches_checked_in_bytes(self):
        folder = m.ROOT / 'research/work-items/RE-015-aws-json-envelope-94'
        files = m.outputs(self.image)
        self.assertEqual(len(files), 9)
        for name, raw in files.items():
            with self.subTest(name=name):
                self.assertEqual((folder / name).read_bytes(), raw)
        document = json.loads(files['evidence.json'])
        self.assertEqual(document['metrics']['decoded_instructions'], 2061)
        self.assertNotIn(str(m.ROOT), files['evidence.json'].decode())


if __name__ == '__main__':
    unittest.main()
