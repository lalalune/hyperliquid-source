"""Static controls for the node 94 account-override evidence exporter."""
import copy
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import evm_state_override94 as mod
from elf_index import unwind_index


class OverrideEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = (ROOT / 'artifacts/node/94/hl-node').read_bytes()
        cls.image = mod.Image(cls.data)
        cls.rows = {}
        cls.by_va = {}
        cls.owners = {}
        for start in mod.FUNCTIONS:
            f = cls.image.fde(start)
            rows = mod.decode(cls.image.read(start, f['end'] - start), start)
            cls.rows[start] = rows
            cls.by_va.update((r['va'], r) for r in rows)
            cls.owners.update((r['va'], start) for r in rows)
        cls.fields, cls.lengths, cls.guards = mod.extract_fields(cls.image, cls.by_va)
        cls.specs = mod.comparison_specs(cls.image, cls.fields, cls.by_va)
        cls.export = mod.collect(cls.image)

    def mutated(self, va, xor=1):
        # Isolate a downstream validator after the real constructor has
        # authenticated the artifact; the public constructor rejects mutations.
        mutant = copy.copy(self.image)
        data = bytearray(self.data)
        data[self.image.offset(va, 1)] ^= xor
        mutant.data = data
        return mutant

    def test_sha_authentication(self):
        self.assertEqual(mod.digest(self.data), mod.SHA)

    def test_corrupt_target_hash_fails_before_parsing(self):
        data = bytearray(self.data)
        data[-1] ^= 1
        with self.assertRaisesRegex(ValueError, 'digest mismatch'):
            mod.Image(data)

    def test_out_of_range_address_is_rejected(self):
        with self.assertRaises(ValueError):
            self.image.read(1 << 63, 4)

    def test_negative_and_zero_length_ranges_rejected(self):
        for addr, size in [(-1, 1), (0, 0), (1, -1), (True, 1)]:
            with self.subTest(addr=addr, size=size):
                with self.assertRaises(ValueError):
                    self.image.offset(addr, size)

    def test_nobits_cannot_be_read(self):
        bss = next(s for s in self.image.secs if s['name'] == '.bss' and s['type'] == 8)
        with self.assertRaises(ValueError):
            self.image.read(bss['address'], 1)

    def test_ambiguous_mapping_rejected(self):
        mutant = copy.copy(self.image)
        mutant.secs = self.image.secs + [copy.copy(self.image.section('.text'))]
        with self.assertRaises(ValueError):
            mutant.offset(0x1b2ad60, 1)

    def test_missing_fde_rejected(self):
        with self.assertRaises(ValueError):
            self.image.fde(0x1b2ad61)

    def test_duplicate_fde_rejected(self):
        mutant = copy.copy(self.image)
        mutant.fdes = dict(self.image.fdes)
        mutant.fdes[0x1b2ad60] = mutant.fdes[0x1b2ad60] * 2
        with self.assertRaises(ValueError):
            mutant.fde(0x1b2ad60)

    def test_extent_outside_text_rejected(self):
        mutant = copy.copy(self.image)
        mutant.fdes = dict(self.image.fdes)
        f = dict(self.image.fde(0x1b2ad60))
        f['end'] = 1 << 62
        mutant.fdes[0x1b2ad60] = [f]
        with self.assertRaises(ValueError):
            mutant.fde(0x1b2ad60)

    def test_changed_body_fails_pin(self):
        with self.assertRaisesRegex(ValueError, 'function byte mismatch'):
            mod.collect(self.mutated(0x1b2ad60))

    def test_unwind_index_disagrees_with_fde(self):
        _, index = unwind_index(self.data)
        item = next(x for x in index if x['start'] == 0x1b2ad60)
        hdr = self.image.section('.eh_frame_hdr')
        fde_word = hdr['address'] + 12 + 8 * item['index'] + 4
        with self.assertRaises(ValueError):
            mod.collect(self.mutated(fde_word))

    def test_relative_relocation_kind_is_checked(self):
        mutant = copy.copy(self.image)
        mutant.relas = dict(self.image.relas)
        _, value, off = mutant.relas[0x56a67f0]
        mutant.relas[0x56a67f0] = (7, value, off)
        with self.assertRaises(ValueError):
            mod.extract_fields(mutant, self.by_va)

    def test_missing_relative_relocation_is_rejected(self):
        with self.assertRaises(ValueError):
            self.image.relative(0x56a67f1)

    def test_field_descriptor_rejects_nobits_pointer(self):
        mutant = copy.copy(self.image)
        mutant.relas = dict(self.image.relas)
        _, _, off = mutant.relas[0x56a67f0]
        bss = next(s for s in self.image.secs if s['name'] == '.bss' and s['type'] == 8)
        mutant.relas[0x56a67f0] = (8, bss['address'], off)
        with self.assertRaises(ValueError):
            mod.extract_fields(mutant, self.by_va)

    def test_field_descriptor_length_corruption(self):
        with self.assertRaises(ValueError):
            mod.extract_fields(self.mutated(0x56a67f8, 0xff), self.by_va)

    def test_field_string_corruption(self):
        with self.assertRaises(ValueError):
            mod.extract_fields(self.mutated(int(self.fields[0]['name_va'], 16)), self.by_va)

    def test_long_comparison_constant_corruption(self):
        with self.assertRaises(ValueError):
            mod.extract_fields(self.mutated(0x2068d0), self.by_va)

    def test_visitor_table_corruption(self):
        with self.assertRaises(ValueError):
            mod.extract_fields(self.mutated(0x3b71c4), self.by_va)

    def test_length_table_corruption(self):
        with self.assertRaises(ValueError):
            mod.extract_fields(self.mutated(0x3e21ec), self.by_va)

    def test_field_tables_and_names(self):
        self.assertEqual([r['name'] for r in self.fields],
            ['balance', 'nonce', 'code', 'state', 'stateDiff', 'movePrecompileToAddress'])
        self.assertEqual([r['tag'] for r in self.fields], list(range(6)))
        self.assertEqual([r['visitor_target'] for r in self.fields],
            [hex(x) for x in mod.FIELD_GUARDS])
        self.assertEqual(len(self.lengths), 20)
        self.assertEqual(len(self.guards), 6)

    def test_field_model_accepts_six_binary_names(self):
        for f in self.fields:
            self.assertEqual(mod.classify_decoded_bytes(bytes.fromhex(f['name_hex']), self.specs), f['tag'])

    def test_field_model_424_single_bit_mutations_fall_back(self):
        count = 0
        for f in self.fields:
            word = bytes.fromhex(f['name_hex'])
            for i in range(len(word)):
                for bit in range(8):
                    bad = bytearray(word)
                    bad[i] ^= 1 << bit
                    self.assertIsNone(mod.classify_decoded_bytes(bytes(bad), self.specs))
                    count += 1
        self.assertEqual(count, 424)

    def test_field_model_length_and_type_controls(self):
        for f in self.fields:
            word = bytes.fromhex(f['name_hex'])
            self.assertIsNone(mod.classify_decoded_bytes(word + b'!', self.specs))
            self.assertIsNone(mod.classify_decoded_bytes(word[:-1], self.specs))
        with self.assertRaises(ValueError):
            mod.classify_decoded_bytes('state', self.specs)

    def test_branch_predicate_corruption(self):
        changed = dict(self.by_va)
        changed[0x2440274] = dict(changed[0x2440274], bytes='4d85f7')
        with self.assertRaises(ValueError):
            mod.selected_predicates(changed, self.owners)

    def test_branch_target_corruption(self):
        changed = dict(self.by_va)
        changed[0x2440277] = dict(changed[0x2440277], target=0x244071e)
        with self.assertRaises(ValueError):
            mod.selected_predicates(changed, self.owners)

    def test_storage_truth_table_and_nonzero_values(self):
        expected = {(0,0):'none', (0,1):'delta', (1,0):'replacement', (1,1):'conflict'}
        for pair, result in expected.items():
            self.assertEqual(mod.storage_choice(*pair), result)
        self.assertEqual(mod.storage_choice((1 << 64)-1, 9), 'conflict')
        self.assertEqual(mod.storage_choice(0, (1 << 64)-1), 'delta')

    def test_storage_model_bad_words(self):
        for a,b in [(-1,0), (0,-1), (1<<64,0), (0,1<<64), (True,0), (0,'1')]:
            with self.subTest(a=a,b=b):
                with self.assertRaises(ValueError):
                    mod.storage_choice(a,b)

    def test_record_layout_and_writer_direct_scan(self):
        layout, stack = mod.derive_layout(self.by_va, self.rows[0x243fd20])
        self.assertEqual(layout['record_size'], 192)
        self.assertEqual(layout['bucket_stride'], 216)
        self.assertEqual(layout['fields']['move_tag'], 168)
        self.assertEqual(layout['direct_rsp_audit']['entries'], [])
        self.assertTrue(any(r['displacement']==0x318 for r in stack))
        self.assertEqual(layout['result_tags'], {'success':33, 'conflict':15})

    def test_writer_direct_scan_detects_tampered_operand(self):
        fake = dict(self.rows[0x243fd20][0], sib=0x24, rex=0, modrm=0x44, displacement=0x368)
        with self.assertRaises(ValueError):
            mod.derive_layout(self.by_va, self.rows[0x243fd20] + [fake])

    def test_writer_guard_detects_wrong_result_tag(self):
        changed = dict(self.by_va)
        changed[0x244085f] = dict(changed[0x244085f], bytes='c60110')
        with self.assertRaises(ValueError):
            mod.derive_layout(changed, self.rows[0x243fd20])

    def test_swap_sequence_in_both_arms(self):
        layout, _ = mod.derive_layout(self.by_va, self.rows[0x243fd20])
        self.assertEqual(len(layout['slot_swaps']['replacement']), 8)
        self.assertEqual(len(layout['slot_swaps']['delta']), 8)
        self.assertEqual([x['bytes'] for x in layout['slot_swaps']['replacement']],
                         [x['bytes'] for x in layout['slot_swaps']['delta']])

    def test_truncated_and_unsupported_instruction(self):
        for bad in [b'\x0f', b'\x0f\x38', b'\xe8\x00']:
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    mod.decode(bad, 0x1000)

    def test_branch_to_instruction_interior_fails(self):
        with self.assertRaises(ValueError):
            mod.decode(bytes.fromhex('e9fcffffff'), 0x1000)

    def test_lsda_corruption_fails(self):
        f = self.image.fde(0x1b2ad60)
        mutant = self.mutated(f['lsda'])
        boundaries = {r['va'] for r in self.rows[0x1b2ad60]}
        with self.assertRaises(ValueError):
            mod.call_sites(mutant, 0x1b2ad60, boundaries)

    def test_address_09_anchor_and_single_bit_controls(self):
        obj = self.image.read(0x574f0c0, 20)
        self.assertEqual(obj, bytes(19) + b'\x09')
        for i in range(20):
            for bit in range(8):
                candidate = bytearray(obj)
                candidate[i] ^= 1 << bit
                self.assertNotEqual(bytes(candidate), obj)
                self.assertFalse(mod.address_key_equal(bytes(candidate), obj))
        self.assertTrue(mod.address_key_equal(obj, obj))
        with self.assertRaises(ValueError):
            mod.address_key_equal(obj[:-1], obj)

    def test_duplicate_error_labels(self):
        rows = mod.duplicate_fields(self.image, self.by_va, self.fields)
        self.assertEqual([r['name'] for r in rows], [r['name'] for r in self.fields])
        self.assertTrue(all(r['call_target']=='0x1ebaee0' for r in rows))

    def test_duplicate_error_label_corruption(self):
        rows = mod.duplicate_fields(self.image, self.by_va, self.fields)
        mutant = self.mutated(int(rows[5]['label_va'], 16))
        with self.assertRaises(ValueError):
            mod.duplicate_fields(mutant, self.by_va, self.fields)

    def test_connecting_calls(self):
        rows = mod.boundary_calls(self.image)
        self.assertEqual([r['target'] for r in rows], ['0x1b2ad60', '0x243fd20'])

    def test_corrupt_connecting_call_fails(self):
        with self.assertRaises(ValueError):
            mod.boundary_calls(self.mutated(0x1e67b5e))

    def test_address_decoder_route(self):
        route = mod.address_route(self.image, self.by_va)
        self.assertEqual(route['key_width'], 20)
        self.assertEqual(route['decoder_success_status'], 3)
        self.assertEqual(route['precompile_09_key'], '00'*19 + '09')
        self.assertEqual(route['address_output_offsets'], [1,17])

    def test_wrong_address_width_fails(self):
        changed = dict(self.by_va)
        changed[0x2806ff0] = dict(changed[0x2806ff0], immediate=21)
        with self.assertRaises(ValueError):
            mod.address_route(self.image, changed)

    def test_wrong_decoder_success_status_fails(self):
        changed = dict(self.by_va)
        changed[0x2806ffc] = dict(changed[0x2806ffc], immediate=4)
        with self.assertRaises(ValueError):
            mod.address_route(self.image, changed)

    def test_wrong_key_comparison_width_fails(self):
        changed = dict(self.by_va)
        changed[0x27c5daa] = dict(changed[0x27c5daa], bytes='66410f6e5c2411')
        with self.assertRaises(ValueError):
            mod.address_route(self.image, changed)

    def test_wrong_value_replacement_size_fails(self):
        changed = dict(self.by_va)
        changed[0x27c5e2e] = dict(changed[0x27c5e2e], immediate=191)
        with self.assertRaises(ValueError):
            mod.address_route(self.image, changed)

    def test_wrong_decoder_relocation_fails(self):
        mutant = copy.copy(self.image)
        mutant.relas = dict(self.image.relas)
        info, target, off = mutant.relas[0x57705c0]
        mutant.relas[0x57705c0] = (info, target+1, off)
        with self.assertRaises(ValueError):
            mod.address_route(mutant, self.by_va)

    def test_request_map_copy_and_seventh_argument(self):
        result = mod.request_flow(self.by_va, self.rows)
        self.assertEqual(result['map_copy_bytes'], 40)
        self.assertEqual(result['first_adapter_stack'], 0xa88)
        self.assertEqual(result['second_adapter_stack'], 0x110)
        self.assertEqual(result['callee_stack_allocation'], 0x5a8)
        self.assertEqual(result['stack_argument_displacement'], 0x5e0)

    def test_request_wrong_parser_result_staging_rejected(self):
        changed = dict(self.by_va)
        changed[0x1f6dd06] = dict(changed[0x1f6dd06], bytes='0f29842488000000')
        with self.assertRaises(ValueError):
            mod.request_flow(changed, self.rows)

    def test_request_wrong_map_copy_bytes_rejected(self):
        changed = dict(self.by_va)
        changed[0x27b8a79] = dict(changed[0x27b8a79], bytes='660f7f842418010000')
        with self.assertRaises(ValueError):
            mod.request_flow(changed, self.rows)

    def test_request_wrong_map_displacement_rejected(self):
        changed = dict(self.by_va)
        changed[0x27b8a5c] = dict(changed[0x27b8a5c], displacement=0x138)
        with self.assertRaises(ValueError):
            mod.request_flow(changed, self.rows)

    def test_request_wrong_seventh_argument_offset_rejected(self):
        changed = dict(self.by_va)
        changed[0x24810bc] = dict(changed[0x24810bc], displacement=0x5d8)
        with self.assertRaises(ValueError):
            mod.request_flow(changed, self.rows)

    def test_request_wrong_prologue_rejected(self):
        changed = dict(self.rows)
        body = list(changed[0x2480f00])
        body[0] = dict(body[0], opcode='50')
        changed[0x2480f00] = body
        with self.assertRaises(ValueError):
            mod.request_flow(self.by_va, changed)

    def test_request_wrong_call_target_rejected(self):
        changed = dict(self.by_va)
        changed[0x1f6dd86] = dict(changed[0x1f6dd86], target=0x27b86f1)
        with self.assertRaises(ValueError):
            mod.request_flow(changed, self.rows)

    def test_engine_override_and_builder_use_same_stack_object(self):
        result = mod.engine_flow(self.by_va)
        self.assertEqual(result['cache_stack_displacement'], 0x4d8)
        self.assertEqual(result['apply_function'], '0x243fd20')
        self.assertEqual(result['builder_function'], '0x247fd20')
        self.assertEqual(result['override_result_success'], 0x21)
        self.assertEqual(result['error_target'], '0x24812cd')

    def test_engine_wrong_cache_pointer_rejected(self):
        changed = dict(self.by_va)
        changed[0x24817bb] = dict(changed[0x24817bb], displacement=0x4e0)
        with self.assertRaises(ValueError):
            mod.engine_flow(changed)

    def test_engine_wrong_argument_register_rejected(self):
        changed = dict(self.by_va)
        changed[0x24817bb] = dict(changed[0x24817bb], bytes='488d8c24d8040000')
        with self.assertRaises(ValueError):
            mod.engine_flow(changed)

    def test_engine_wrong_failure_target_rejected(self):
        changed = dict(self.by_va)
        changed[0x2481103] = dict(changed[0x2481103], target=0x2481719)
        with self.assertRaises(ValueError):
            mod.engine_flow(changed)

    def test_engine_wrong_success_tag_rejected(self):
        changed = dict(self.by_va)
        changed[0x24810fb] = dict(changed[0x24810fb], immediate=0x20)
        with self.assertRaises(ValueError):
            mod.engine_flow(changed)

    def test_engine_sse_instruction_shapes(self):
        for raw in ['660f5cc3', 'f20f5eca', '660f2ec1', '660f15c8']:
            decoded = mod.decode(bytes.fromhex(raw), 0x1000)
            self.assertEqual(len(decoded), 1)
            self.assertEqual(decoded[0]['bytes'], raw)

    def test_publication_bypass_table_corruption(self):
        with self.assertRaises(ValueError):
            mod.collect(self.mutated(0x3bf248))

    def test_output_is_equal_to_export(self):
        folder = ROOT / 'research/work-items/RE-021-state-override-94'
        for name, content in self.export.items():
            with self.subTest(name=name):
                self.assertEqual((folder / name).read_bytes(), content.encode('utf-8'))

    def test_summary_denominators_are_selected_extents(self):
        summary = json.loads(self.export['summary.json'])
        self.assertEqual(summary['functions'], 18)
        self.assertEqual(summary['function_bytes'], 33680)
        self.assertEqual(summary['fields'], 6)
        self.assertEqual(summary['table_entries'], 35)


if __name__ == '__main__':
    unittest.main()
