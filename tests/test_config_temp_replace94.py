"""Static controls for the node 94 configuration-rooted replacement packet."""
import csv
import io
from pathlib import Path
import struct
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import config_temp_replace94 as subject


def records(text):
    return list(csv.DictReader(io.StringIO(text), delimiter='\t'))


class ConfigTempReplacementTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = subject.ARTIFACT.read_bytes()
        subject.check_digest(cls.data)
        cls.image = subject.Image(cls.data)
        cls.outputs = subject.collect(cls.data)
        cls.functions = records(cls.outputs['functions.tsv'])
        cls.decodes = {}
        cls.instructions = {}
        for row in cls.functions:
            start, end = int(row['start_va'], 16), int(row['end_va'], 16)
            decoded = subject.decode_body(cls.image.read(start, end - start, executable=True), start)
            cls.decodes[start] = decoded
            cls.instructions.update((r['va'], r) for r in decoded)
        slots = {r['target'] for row in cls.decodes.values() for r in row
                 if r['kind'] in ('indirect_call', 'indirect_jump') and r['rip_relative']}
        cls.relocations = cls.image.relocations(slots)

    def test_artifact_identity_and_target_grounding(self):
        subject.check_digest(self.data)
        self.assertEqual(len(self.data), 91774280)
        self.assertEqual(len(self.functions), 13)
        self.assertEqual(len(self.instructions), 1439)
        self.assertEqual(self.outputs['summary.json'].count(subject.DIGEST), 1)

    def test_corrupt_digest_rejected(self):
        changed = bytearray(self.data)
        changed[-1] ^= 1
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            subject.check_digest(changed)

    def test_short_or_wrong_artifact_rejected(self):
        for bad in (b'', b'\x7fELF', self.data[:1024]):
            with self.subTest(length=len(bad)):
                with self.assertRaises(ValueError):
                    subject.check_digest(bad)

    def test_file_backing_and_coordinate_mapping(self):
        self.assertEqual(self.image.offset(0x144d0d0, 1, True), 0x144c0d0)
        self.assertEqual(self.image.read(0x1f04e5, 8), bytes.fromhex('c0012fc0012fc000'))
        for va, size, executable in ((0x5788300, 1, False), (0, 1, True),
                                     (-1, 1, False), (0x144d0d0, 0, True),
                                     (0x1343c7f, 2, True)):
            with self.subTest(va=va, size=size):
                with self.assertRaises(ValueError):
                    self.image.offset(va, size, executable)

    def test_ambiguous_file_backing_rejected(self):
        original = self.image.loaded
        duplicate = next(s.copy() for s in original if s['name'] == '.text')
        self.image.loaded = original + [duplicate]
        try:
            with self.assertRaises(ValueError):
                self.image.offset(0x144d0d0, 4, True)
        finally:
            self.image.loaded = original

    def test_truncated_and_unsupported_instructions_rejected(self):
        for raw in (b'\x0f', b'\xe8\x00\x00', b'\x48\x8b\x05\x00', b'\x0f\x38', b'\x67\x90'):
            with self.subTest(raw=raw.hex()):
                with self.assertRaises(ValueError):
                    subject.decode_body(raw, 0x1000)

    def test_branch_into_operand_rejected(self):
        valid = subject.decode_body(bytes.fromhex('7403 4889c0 c3'), 0x1000)
        self.assertEqual(valid[0]['target'], 0x1005)
        with self.assertRaisesRegex(ValueError, 'branch into'):
            subject.decode_body(bytes.fromhex('7401 4889c0 c3'), 0x1000)

    def test_relative_instruction_targets_and_sizes(self):
        r = subject.decode_one(bytes.fromhex('488d05fbffffff'), 0, 0x1000)
        self.assertEqual((r['end'], r['target']), (0x1007, 0x1002))
        self.assertTrue(r['rip_relative'])
        branch = subject.decode_one(bytes.fromhex('0f85f4ffffff'), 0, 0x1000)
        self.assertEqual((branch['end'], branch['target']), (0x1006, 0x0ffa))
        call = subject.decode_one(bytes.fromhex('ff1504000000'), 0, 0x1000)
        self.assertEqual((call['kind'], call['target']), ('indirect_call', 0x100a))

    def test_all_local_transfer_targets_are_instruction_starts(self):
        for start, rows in self.decodes.items():
            addresses = {r['va'] for r in rows}
            end = rows[-1]['end']
            for r in rows:
                if r['kind'] in ('jump', 'conditional') and start <= r['target'] < end:
                    self.assertIn(r['target'], addresses)

    def test_selected_byte_call_and_branch_contracts(self):
        subject.validate_contracts(self.image, self.instructions, self.relocations)
        self.assertEqual(len(records(self.outputs['branches.tsv'])), len(subject.BRANCH_CONTRACTS))
        self.assertEqual(len(records(self.outputs['witnesses.tsv'])), len(subject.WITNESSES))

    def test_reversed_branch_polarity_rejected(self):
        altered = dict(self.instructions)
        original = altered[0x144d221]
        changed = dict(original)
        changed['bytes'] = bytes.fromhex('0f84') + original['bytes'][2:]
        altered[0x144d221] = changed
        with self.assertRaisesRegex(ValueError, 'branch contract'):
            subject.validate_contracts(self.image, altered, self.relocations)

    def test_retargeted_branch_to_valid_instruction_rejected(self):
        start = 0x144d0d0
        rows = self.decodes[start]
        code = bytearray(self.image.read(start, rows[-1]['end'] - start, True))
        site = 0x144d221
        struct.pack_into('<i', code, site - start + 2, 0)
        decoded = subject.decode_body(code, start)
        altered = dict(self.instructions)
        altered.update((r['va'], r) for r in decoded)
        with self.assertRaisesRegex(ValueError, 'branch contract'):
            subject.validate_contracts(self.image, altered, self.relocations)

    def test_corrupt_witness_rejected_below_digest(self):
        image = self.image
        class Corrupted:
            def read(self, va, size, executable=False):
                result = image.read(va, size, executable)
                if va == 0x144d227:
                    return bytes([result[0] ^ 1]) + result[1:]
                return result
        with self.assertRaisesRegex(ValueError, 'instruction contract'):
            subject.validate_contracts(Corrupted(), self.instructions, self.relocations)

    def test_retargeted_call_rejected(self):
        altered = dict(self.instructions)
        row = dict(altered[0x37eab8d])
        row['target'] = 0x576ea68
        altered[row['va']] = row
        with self.assertRaisesRegex(ValueError, 'call contract'):
            subject.validate_contracts(self.image, altered, self.relocations)

    def test_corrupt_fde_length_is_not_a_valid_extent(self):
        changed = bytearray(self.data)
        fde_va = int(next(row['fde_va'] for row in self.functions if row['role'] == 'configured_temporary_path'), 16)
        fde_off = self.image.offset(fde_va, 16)
        old_range = struct.unpack_from('<i', changed, fde_off + 12)[0]
        struct.pack_into('<i', changed, fde_off + 12, old_range - 1)
        with mock.patch.object(subject, 'check_digest', return_value=None):
            with self.assertRaises(ValueError):
                subject.collect(changed)

    def test_corrupt_relocation_addend_rejected(self):
        changed = bytearray(self.data)
        offset = self.relocations[0x576e928]['file_offset']
        struct.pack_into('<q', changed, offset + 16, 0x577b289)
        with self.assertRaisesRegex(ValueError, 'relocation contract'):
            subject.Image(changed).relocations()

    def test_corrupt_dynamic_symbol_rejected(self):
        changed = bytearray(self.data)
        offset = self.relocations[0x57772e8]['file_offset']
        slot, info, addend = struct.unpack_from('<QQq', changed, offset)
        struct.pack_into('<QQq', changed, offset, slot, (154 << 32) | (info & 0xffffffff), addend)
        with self.assertRaisesRegex(ValueError, 'relocation contract'):
            subject.Image(changed).relocations()

    def test_import_and_static_global_bindings(self):
        self.assertEqual(self.relocations[0x57772e8]['symbol'], 'linkat')
        self.assertEqual(self.relocations[0x57772d8]['symbol'], 'stat64')
        self.assertEqual(self.relocations[0x576e928]['addend'], 0x577b288)
        self.assertEqual(self.relocations[0x577b288]['addend'], 0x164ff00)
        self.assertEqual(self.relocations[0x576ebe0]['addend'], 0x144d0d0)

    def test_template_parser_boundaries(self):
        raw = bytes.fromhex('c0012fc0012fc000')
        self.assertEqual(subject.parse_template(raw), [('argument', ''), ('literal', '2f'),
                                                       ('argument', ''), ('literal', '2f'), ('argument', '')])
        for bad in (raw[:-1], raw + b'\0', bytes.fromhex('03787900'), bytes.fromhex('8000')):
            with self.subTest(raw=bad.hex()):
                with self.assertRaises(ValueError):
                    subject.parse_template(bad)

    def test_global_temp_literals_are_length_bound(self):
        rows = {r['label']: r for r in records(self.outputs['templates.tsv'])}
        self.assertEqual(rows['replacement_token_path']['bytes'][:2], '1c')
        self.assertEqual(rows['temporary_component']['bytes'], '746d70')
        self.assertEqual(rows['fallback_prefix']['bytes'], '052f746d702fc000')
        self.assertEqual(rows['three_argument_path']['pieces'].count('argument'), 3)

    def test_component_discriminant_boundary_is_byte_derived(self):
        rows = records(self.outputs['component-tags.tsv'])
        self.assertEqual(len(rows), 512)
        for path in ('primary', 'fallback'):
            hits = [int(r['tag_byte']) for r in rows
                    if r['path'] == path and r['route'] == 'inspect_slice']
            self.assertEqual(hits, [7, 8, 9])
        self.assertFalse(subject.component_tag_gate(bytes.fromhex('04f9'), bytes.fromhex('3c03'), 6))
        self.assertTrue(subject.component_tag_gate(bytes.fromhex('04f9'), bytes.fromhex('3c03'), 7))
        self.assertTrue(subject.component_tag_gate(bytes.fromhex('04f9'), bytes.fromhex('3c03'), 9))
        self.assertFalse(subject.component_tag_gate(bytes.fromhex('04f9'), bytes.fromhex('3c03'), 10))
        self.assertFalse(subject.component_tag_gate(bytes.fromhex('04f9'), bytes.fromhex('3c03'), 255))

    def test_component_gate_rejects_bad_opcodes_and_domain(self):
        for add, cmp, tag in ((b'\x05\xf9',b'\x3c\x03',7),
                              (b'\x04\xf9',b'\x3d\x03',7),
                              (b'\x04\xf9',b'\x3c\x03',256)):
            with self.subTest(add=add.hex(), compare=cmp.hex(), tag=tag):
                with self.assertRaises(ValueError):
                    subject.component_tag_gate(add, cmp, tag)

    def test_adapter_short_buffer_boundaries(self):
        rows = records(self.outputs['adapter-lengths.tsv'])
        self.assertEqual(len(rows), 24)
        for adapter in ('metadata', 'link_source', 'link_destination', 'long_callback_destination'):
            by_length = {int(r['length']): r['route'] for r in rows if r['adapter'] == adapter}
            self.assertEqual(by_length[383], 'short_buffer')
            self.assertEqual(by_length[384], 'long_helper')
        self.assertTrue(subject.adapter_length_gate(bytes.fromhex('4881fa7f010000'), 383))
        self.assertFalse(subject.adapter_length_gate(bytes.fromhex('4881fa7f010000'), 384))
        with self.assertRaises(ValueError):
            subject.adapter_length_gate(bytes.fromhex('4881fa7f010000'), -1)
        with self.assertRaises(ValueError):
            subject.adapter_length_gate(bytes.fromhex('4881ea7f010000'), 383)

    def test_cfg_structural_claims(self):
        rows = subject.verify_cfg(self.decodes)
        self.assertEqual(len(rows), 37)
        self.assertTrue(all(row[-1] == row[-2] for row in rows))
        self.assertFalse(subject.reachable(self.decodes[0x37eaa70], 0x37eaae4, 0x37eab8d))
        self.assertTrue(subject.reachable(self.decodes[0x144d0d0], 0x144d349, 0x144d37e))

    def test_cfg_retarget_into_valid_instruction_is_rejected(self):
        start = 0x37eaa70
        rows = self.decodes[start]
        code = bytearray(self.image.read(start, rows[-1]['end'] - start, True))
        site = 0x37eabaa
        code[site - start + 1] = 0  # keep a valid aligned target but enter the success route
        altered = dict(self.decodes)
        altered[start] = subject.decode_body(code, start)
        with self.assertRaisesRegex(ValueError, 'CFG contract'):
            subject.verify_cfg(altered)

    def test_cfg_invalid_endpoints_rejected(self):
        with self.assertRaises(ValueError):
            subject.reachable(self.decodes[0x37eaa70], 0x37eaa72, 0x37eab8d)

    def test_model_same_words_never_builds_path(self):
        trace, result = subject.predict_route('ok','ok','yes','yes','-','-','-','-','-')
        self.assertEqual((trace, result), ('stat_source>stat_destination>return_zero', 'zero'))

    def test_model_metadata_error_and_word_boundaries(self):
        source, _ = subject.predict_route('error','-','-','-','present','-','ok','ok','ok')
        dest, _ = subject.predict_route('ok','error','-','-','present','-','ok','ok','ok')
        unequal, _ = subject.predict_route('ok','ok','yes','no','present','-','ok','ok','ok')
        self.assertNotIn('stat_destination', source)
        self.assertIn('metadata_error_callback', source)
        self.assertIn('stat_destination>metadata_error_callback', dest)
        self.assertIn('select_primary>link_ok', unequal)

    def test_model_primary_and_fallback_selection(self):
        args = ('ok','ok','no','-')
        first, _ = subject.predict_route(*args,'created','-','ok','ok','ok')
        second, _ = subject.predict_route(*args,'failed','created','ok','ok','ok')
        both, _ = subject.predict_route(*args,'failed','failed','ok','ok','ok')
        self.assertIn('select_primary', first)
        self.assertIn('select_fallback', second)
        self.assertIn('two_error_callbacks>select_primary', both)

    def test_model_link_and_parent_failures_stop_later_actions(self):
        args = ('ok','ok','no','-','present','-')
        link_trace, link_result = subject.predict_route(*args,'error','-','-')
        parent_trace, parent_result = subject.predict_route(*args,'ok','error','-')
        self.assertNotIn('destination_parent', link_trace)
        self.assertNotIn('move_', parent_trace)
        self.assertEqual(link_result, 'link_error_boundary')
        self.assertEqual(parent_result, 'parent_error_boundary')

    def test_model_rejects_impossible_and_unknown_states(self):
        bad = [
            ('error','ok','-','-','present','-','ok','ok','ok'),
            ('ok','ok','yes','yes','present','-','ok','ok','ok'),
            ('ok','ok','no','yes','present','-','ok','ok','ok'),
            ('ok','ok','no','-','present','failed','ok','ok','ok'),
            ('ok','ok','no','-','failed','-','ok','ok','ok'),
            ('ok','ok','no','-','present','-','error','ok','ok'),
            ('ok','ok','no','-','present','-','ok','error','ok'),
            ('unknown','-','-','-','present','-','ok','ok','ok'),
        ]
        for values in bad:
            with self.subTest(values=values):
                with self.assertRaises(ValueError):
                    subject.predict_route(*values)

    def test_model_case_set_is_unique_and_bounded(self):
        rows = records(self.outputs['cases.tsv'])
        self.assertEqual(len(rows), 25)
        self.assertEqual(len({r['scenario'] for r in rows}), len(rows))
        self.assertEqual(sum(r['result_boundary'] == 'zero' for r in rows), 1)
        self.assertEqual(sum(r['result_boundary'] == 'link_error_boundary' for r in rows), 5)

    def test_callback_address_and_direct_call_edges(self):
        rows = {r['label']: r for r in records(self.outputs['callback-edges.tsv'])}
        self.assertEqual(rows['source_long_callback']['target_va'], '0x4ee0300')
        self.assertEqual(rows['destination_long_callback']['target_va'], '0x4ee04b0')
        self.assertEqual(rows['both_long_second_callback']['target_va'], '0x4ee04b0')
        self.assertEqual(rows['second_long_input_adapter']['target_va'], '0x4ee60a0')

    def test_retargeted_callback_rejected(self):
        altered = dict(self.instructions)
        row = dict(altered[0x4ee02cf])
        row['target'] += 1
        altered[row['va']] = row
        with self.assertRaisesRegex(ValueError, 'callback address'):
            subject.validate_contracts(self.image, altered, self.relocations)

    def test_long_link_route_all_length_combinations(self):
        cases = [
            ((383,383,'-','-',383), ('direct_short','0x4ee0297')),
            ((384,383,'sentinel','-',383), ('long_source_callback','0x4ee0453')),
            ((383,384,'-','sentinel',383), ('long_destination_callback','0x4ee04cb')),
            ((384,384,'sentinel','sentinel',383), ('long_destination_callback','0x4ee04cb')),
            ((384,384,'non_sentinel','-',383), ('source_conversion_boundary','')),
            ((384,384,'sentinel','non_sentinel',383), ('destination_conversion_boundary','')),
        ]
        for inputs, expected in cases:
            with self.subTest(inputs=inputs):
                self.assertEqual(subject.predict_link_route(*inputs), expected)
        self.assertEqual(len(records(self.outputs['long-link-cases.tsv'])), 15)

    def test_long_link_rejects_unreachable_converter_states(self):
        bad = [(383,383,'sentinel','-',383), (384,383,'-','-',383),
               (383,384,'-','-',383), (384,384,'non_sentinel','sentinel',383),
               (384,383,'sentinel','sentinel',383), (-1,0,'-','-',383)]
        for inputs in bad:
            with self.subTest(inputs=inputs):
                with self.assertRaises(ValueError):
                    subject.predict_link_route(*inputs)

    def test_converter_nul_branch_polarity_is_checked(self):
        altered = dict(self.instructions)
        original = altered[0x1346546]
        changed = dict(original)
        changed['bytes'] = bytes.fromhex('0f85') + original['bytes'][2:]
        altered[changed['va']] = changed
        with self.assertRaisesRegex(ValueError, 'branch contract'):
            subject.validate_contracts(self.image, altered, self.relocations)

    def test_converter_word_zero_test_against_independent_byte_oracle(self):
        high = int.from_bytes(self.image.read(0x134656e, 8, True), 'little')
        subtract = int.from_bytes(self.image.read(0x1346578, 8, True), 'little')
        mask64 = (1 << 64) - 1
        def detects(word):
            value = int.from_bytes(word, 'little')
            return (((((subtract - value) & mask64) | value) & high) != high)
        for pair in range(65536):
            word = pair.to_bytes(2, 'little') + bytes([0x35]) * 6
            if detects(word) != (0 in word):
                self.fail(f'word-byte oracle disagrees at pair {pair}')
        for fill in range(1, 256):
            for pos in range(8):
                word = bytearray([fill] * 8)
                word[pos] = 0
                if not detects(word):
                    self.fail(f'zero not detected at position {pos}')
        self.assertFalse(detects(bytes([0xff]) * 8))

    def test_tail_component_boundaries(self):
        rows = {r['component_hex']: int(r['predicted_tag']) for r in records(self.outputs['tail-components.tsv'])}
        self.assertEqual(rows[''], 10)
        self.assertEqual(rows['2e'], 10)
        self.assertEqual(rows['2e2e'], 8)
        for value in ('2e2e2e', '61', '2e61', '612e', '00', 'ff'):
            self.assertEqual(rows[value], 9)

    def test_tail_classifier_one_and_two_byte_domain(self):
        dot, slash = self.image.read(0x4ee9c2b, 1, True)[0], self.image.read(0x4ee9bf4, 1, True)[0]
        skip, parent, ordinary = (self.image.read(site, 1, True)[0]
                                  for site in (0x4ee9c17, 0x4ee9c30, 0x4ee9c61))
        for first in range(256):
            if first == slash:
                continue
            one = bytes([first])
            expected = skip if first == dot else ordinary
            self.assertEqual(subject.classify_tail(one,dot,slash,skip,parent,ordinary), expected)
            for second in range(256):
                if second == slash:
                    continue
                two = bytes([first, second])
                expected = parent if first == dot and second == dot else ordinary
                if subject.classify_tail(two,dot,slash,skip,parent,ordinary) != expected:
                    self.fail(f'tail mismatch for {two.hex()}')

    def test_tail_rejects_separator_and_invalid_parameters(self):
        for segment, dot, slash in ((b'a/b', 0x2e, 0x2f), (b'a', 0x2e, 0x2e), (b'a', 256, 0x2f)):
            with self.subTest(segment=segment.hex(), dot=dot, slash=slash):
                with self.assertRaises(ValueError):
                    subject.classify_tail(segment,dot,slash,10,8,9)

    def test_tail_dot_branch_polarity_is_checked(self):
        altered = dict(self.instructions)
        original = altered[0x4ee9c35]
        changed = dict(original)
        changed['bytes'] = bytes.fromhex('75') + original['bytes'][1:]
        altered[changed['va']] = changed
        with self.assertRaisesRegex(ValueError, 'branch contract'):
            subject.validate_contracts(self.image, altered, self.relocations)

    def test_component_slice_classifier_call_is_checked(self):
        altered = dict(self.instructions)
        row = dict(altered[0x4ee9de6])
        row['target'] += 1
        altered[row['va']] = row
        with self.assertRaisesRegex(ValueError, 'direct call'):
            subject.validate_contracts(self.image, altered, self.relocations)


if __name__ == '__main__':
    unittest.main()
