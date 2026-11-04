"""Static controls for the node-115 scaled-precompile evidence generator."""
import hashlib
import json
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import evm_scaled_precompile115 as p


class RouteEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = p.TARGET.read_bytes()
        p.authenticate(cls.data)
        cls.sec = p.sections(cls.data)
        cls.evidence = p.collect(cls.data)
        private_count = p.routing_limits(cls.data, cls.sec)[2]
        slots = (set(p.RELA_SLOTS)
                 | {0x6492f30 + 40 * i + 24 for i in range(p.scaled_count(cls.data, cls.sec))}
                 | {0x646e4e0 + 32 * i + 24 for i in range(private_count)})
        cls.relocations = p.relative_relocations(cls.data, cls.sec, slots)
        cls.scaled = cls.evidence['scaled-records.json']
        cls.iterator = cls.evidence['iterator-cases.json']
        cls.private = cls.evidence['private-records.json']

    def altered_read(self, location, replacement):
        original = p.read_va

        def wrapper(data, sec, va, size):
            raw, offset, name = original(data, sec, va, size)
            lo = max(va, location)
            hi = min(va + size, location + len(replacement))
            if lo < hi:
                raw = bytearray(raw)
                raw[lo - va:hi - va] = replacement[lo - location:hi - location]
                raw = bytes(raw)
            return raw, offset, name

        return patch.object(p, 'read_va', side_effect=wrapper)

    def test_digest_and_corruption(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), p.TARGET_SHA256)
        with patch.object(p, 'TARGET_SHA256', '0' * 64), self.assertRaises(ValueError):
            p.authenticate(self.data)
        with self.assertRaises(ValueError):
            p.authenticate(b'corrupt')

    def test_fde_raw_bytes_and_unique_extents(self):
        fs = self.evidence['functions.json']
        self.assertEqual(len(fs), len(p.FUNCTIONS))
        self.assertEqual(len({r['start_va'] for r in fs}), len(fs))
        for r in fs:
            start, end = int(r['start_va'], 16), int(r['end_va'], 16)
            raw, off, section = p.read_va(self.data, self.sec, start, end - start)
            self.assertEqual(section, '.text')
            self.assertEqual(r['file_offset'], hex(off))
            self.assertEqual(r['raw_hex'], raw.hex())
            self.assertEqual(r['sha256'], hashlib.sha256(raw).hexdigest())
            self.assertEqual(r['byte_count'], end - start)
            self.assertTrue(r['fde_raw_hex'])
            self.assertTrue(r['cie_raw_hex'])

    def test_fde_missing_and_duplicate_are_rejected(self):
        with patch.object(p, 'eh_frame_records', return_value=({}, [])):
            with self.assertRaises(ValueError):
                p.selected_fdes(self.data, self.sec)
        one = {'start':0x46a0eb0,'end':0x46a0fa1,'fde':0xef38d0,'cie':0xca6ed8,'lsda':None}
        with patch.object(p, 'eh_frame_records', return_value=({}, [one,one])):
            with self.assertRaises(ValueError):
                p.selected_fdes(self.data, self.sec)

    def test_out_of_range_and_nobits_rejected(self):
        bss = next(s for s in self.sec if s['name'] == '.bss')
        with self.assertRaises(ValueError):
            p.read_va(self.data, self.sec, bss['address'], 1)
        with self.assertRaises(ValueError):
            p.read_va(self.data, self.sec, -1, 1)
        with self.assertRaises(ValueError):
            p.read_va(self.data, self.sec, 0, 0)
        text = next(s for s in self.sec if s['name'] == '.text')
        with self.assertRaises(ValueError):
            p.read_va(self.data, self.sec, text['address'] + text['size'] - 1, 2)

    def test_ambiguous_section_rejected(self):
        sec = [{'type':1,'size':4,'address':10,'offset':0,'name':'a'},
               {'type':1,'size':4,'address':10,'offset':4,'name':'b'}]
        with self.assertRaises(ValueError):
            p.read_va(b'abcdefgh', sec, 10, 1)
        sec[1]['type'] = 8
        self.assertEqual(p.read_va(b'abcdefgh', sec, 10, 4)[0], b'abcd')

    def test_windows_match_and_mutation_is_rejected(self):
        self.assertEqual(len(p.check_windows(self.data, self.sec)), len(p.WINDOWS))
        va = 0x2a6ab64
        original = p.read_va(self.data, self.sec, va, 1)[0][0]
        with self.altered_read(va, bytes([original ^ 1])):
            with self.assertRaises(ValueError):
                p.check_windows(self.data, self.sec)
        for raw, expected in [(b'', b'a'), (b'a', b'b'), (b'aa', b'ab')]:
            with self.assertRaises(ValueError):
                p.need(raw, expected, 'negative control')

    def test_relative_edges_and_mutated_target(self):
        self.assertEqual(len(p.check_edges(self.data, self.sec)), len(p.EDGES))
        va = 0x2984373
        old = p.read_va(self.data, self.sec, va + 1, 1)[0][0]
        with self.altered_read(va + 1, bytes([old ^ 1])):
            with self.assertRaises(ValueError):
                p.check_edges(self.data, self.sec)

    def test_relative_decoder_fail_closed(self):
        self.assertEqual(p.relative_target(0x100, bytes.fromhex('e801000000'), 'call'), 0x106)
        self.assertEqual(p.relative_target(0x100, bytes.fromhex('75fe'), 'jcc'), 0x100)
        with self.assertRaises(ValueError):
            p.relative_target(0x100, bytes.fromhex('e800000000'), 'jmp')
        with self.assertRaises(ValueError):
            p.relative_target(0x100, bytes.fromhex('e80100'), 'call')
        with self.assertRaises(ValueError):
            p.relative_target(0x100, bytes.fromhex('90'), 'jmp')

    def test_rip_references_and_corruption(self):
        self.assertEqual(len(p.check_rip(self.data, self.sec)), len(p.RIP))
        va = 0x2a6ab70
        with self.altered_read(va, b'\x90'):
            with self.assertRaises(ValueError):
                p.check_rip(self.data, self.sec)
        with self.assertRaises(ValueError):
            p.rip_target(0x100, b'\xff\x15\x00', b'\xff\x15')

    def test_relocation_missing_duplicate_type_and_symbol(self):
        slot = 0x1234
        entry = struct.pack('<QQq', slot, 8, 0x4567)
        section = [{'type':4,'offset':0,'size':24,'name':'.rela.dyn'}]
        got = p.relative_relocations(entry, section, {slot})
        self.assertEqual(got[slot]['addend_va'], '0x4567')
        for bad in (struct.pack('<QQq', slot, 7, 0x4567),
                    struct.pack('<QQq', slot, (1 << 32) | 8, 0x4567),
                    struct.pack('<QQq', slot, 8, -1)):
            with self.assertRaises(ValueError):
                p.relative_relocations(bad, section, {slot})
        with self.assertRaises(ValueError):
            p.relative_relocations(entry, section, {slot + 1})
        duplicate = [{'type':4,'offset':0,'size':48,'name':'.rela.dyn'}]
        with self.assertRaises(ValueError):
            p.relative_relocations(entry * 2, duplicate, {slot})
        section[0]['size'] = 23
        with self.assertRaises(ValueError):
            p.relative_relocations(entry, section, {slot})

    def test_symbol_relocation_resolves_and_rejects_corruption(self):
        slot = 0x1234
        entry = struct.pack('<QQq', slot, (1 << 32) | 6, 0)
        null_symbol = bytes(24)
        symbol = struct.pack('<IBBHQQ', 1, 0x12, 0, 0, 0, 0)
        strings = b'\x00memcpy\x00'
        blob = entry + null_symbol + symbol + strings
        secs = [{'type':4, 'offset':0, 'size':24, 'name':'.rela.dyn'},
                {'type':11, 'offset':24, 'size':48, 'name':'.dynsym'},
                {'type':3, 'offset':72, 'size':len(strings), 'name':'.dynstr'}]
        self.assertEqual(p.dynamic_symbol_relocation(blob, secs, slot, 'memcpy')['symbol_name'], 'memcpy')
        with self.assertRaises(ValueError):
            p.dynamic_symbol_relocation(blob, secs, slot, 'memcmp')
        bad_type = struct.pack('<QQq', slot, (1 << 32) | 8, 0) + blob[24:]
        with self.assertRaises(ValueError):
            p.dynamic_symbol_relocation(bad_type, secs, slot, 'memcpy')
        jump_slot = struct.pack('<QQq', slot, (1 << 32) | 7, 0) + blob[24:]
        self.assertEqual(p.dynamic_symbol_relocation(jump_slot, secs, slot, 'memcpy', 7)['relocation_type'], 7)
        with self.assertRaises(ValueError):
            p.dynamic_symbol_relocation(jump_slot, secs, slot, 'memcpy', 6)
        bad_index = struct.pack('<QQq', slot, (3 << 32) | 6, 0) + blob[24:]
        with self.assertRaises(ValueError):
            p.dynamic_symbol_relocation(bad_index, secs, slot, 'memcpy')
        bad_name = blob[:-1] + b'x'
        with self.assertRaises(ValueError):
            p.dynamic_symbol_relocation(bad_name, secs, slot, 'memcpy')

    def test_real_external_symbols(self):
        records = self.evidence['dynamic-symbols.json']
        self.assertEqual([r['symbol_name'] for r in records], ['memcpy', 'memcmp', '_Unwind_Resume'])
        self.assertEqual([r['relocation_type'] for r in records], [6, 6, 7])

    def test_exception_site_for_scaled_callback(self):
        rows = self.evidence['exception-sites.tsv']
        matches = [r for r in rows if r['function_va'] == '0x2a6ab20'
                   and int(r['start_va'], 16) <= 0x2a6b07d < int(r['end_va'], 16)]
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]['landing_pad_va'], '0x2a6b73f')
        self.assertEqual(matches[0]['action_index'], 0)

    def test_exception_cleanup_instruction_corruption(self):
        with self.altered_read(0x2a6b74d, b'\x90'):
            with self.assertRaises(ValueError):
                p.check_windows(self.data, self.sec)
        with self.altered_read(0x2a6b74c, b'\x00'):
            with self.assertRaises(ValueError):
                p.check_edges(self.data, self.sec)

    def test_exception_table_rejects_corruption_and_outside_fde(self):
        section = [{'type':1,'size':8,'address':0x2000,'offset':0,'name':'.gcc_except_table'}]
        fde = {'lsda_va':'0x2000','start_va':'0x1000','end_va':'0x1010'}
        good = bytes.fromhex('ffff010400020400')
        header, rows = p.parse_lsda(good, section, fde)
        self.assertEqual(header['callsite_count'], 1)
        self.assertEqual(rows[0]['start_va'], '0x1000')
        self.assertEqual(rows[0]['end_va'], '0x1002')
        self.assertEqual(rows[0]['landing_pad_va'], '0x1004')
        for bad in (bytes.fromhex('feff010400020400'),
                    bytes.fromhex('ffff020400020400'),
                    bytes.fromhex('ffff010400110000'),
                    bytes.fromhex('ffff010400011100'),
                    bytes.fromhex('ffff010480808080')):
            with self.assertRaises(ValueError):
                p.parse_lsda(bad, section, fde)
        with self.assertRaises(ValueError):
            p.parse_lsda(good[:-1], section, fde)

    def test_scaled_selector_binds_full_key_and_divisor(self):
        self.assertEqual([int(r['key_hex'], 16) for r in self.scaled], [1,5,6,7,8,9,10])
        self.assertEqual([r['divisor'] for r in self.scaled], [5,10,10,10,10,10,40])
        row = self.scaled[5]
        self.assertEqual(row['callback_addend_va'], '0x5c16650')
        self.assertEqual(row['record_va'], '0x6492ff8')
        self.assertEqual(row['callback_slot_va'], '0x6493010')

    def test_selector_rejects_changed_key_or_divisor(self):
        with self.altered_read(0x46a0f0f, b'\x08'):
            with self.assertRaises(ValueError):
                p.scaled_selector(self.data, self.sec, self.relocations)
        with self.altered_read(0x6493018, b'\x00'):
            with self.assertRaises(ValueError):
                p.scaled_selector(self.data, self.sec, self.relocations)

    def test_scaled_selector_rejects_missing_terminator(self):
        with self.altered_read(0x46a0f2e, b'\x90'):
            with self.assertRaises(ValueError):
                p.scaled_count(self.data, self.sec)

    def test_corrupt_scaled_relocation_is_rejected(self):
        altered = {k:dict(v) for k,v in self.relocations.items()}
        altered[0x6493010]['addend_va'] = '0x5c16651'
        with self.assertRaises(ValueError):
            p.scaled_selector(self.data, self.sec, altered)

    def test_30_case_iteration_and_private_range(self):
        n, adjustment, private_n = p.routing_limits(self.data, self.sec)
        self.assertEqual((n, adjustment, private_n), (30, 249, 21))
        self.assertEqual(len(self.iterator), n)
        actual = [r['key_hex'] for r in self.iterator if r['private_index_accepted']]
        self.assertEqual(actual, [r['key_hex'] for r in self.private])
        self.assertNotIn(p.ADDR09.hex(), [r['key_hex'] for r in self.iterator])
        self.assertEqual(actual[0][-4:], '0800')
        self.assertEqual(actual[1][-4:], '0813')
        self.assertEqual(actual[-1][-4:], '0814')

    def test_iterator_rejects_invalid_table_and_case(self):
        with self.altered_read(0x7c7548, b'\x00\x00\x00\x80'):
            with self.assertRaises(ValueError):
                p.iterator_cases(self.data, self.sec)
        with self.altered_read(0x4200a67, b'\x90'):
            with self.assertRaises(ValueError):
                p.iterator_cases(self.data, self.sec)
        with self.altered_read(0x2a6abe3, b'\x00'):
            with self.assertRaises(ValueError):
                p.routing_limits(self.data, self.sec)

    def test_private_records_match_constructor_and_relocations(self):
        copied = self.evidence['constructor-copies.json']
        self.assertEqual([r['key_hex'] for r in self.private], [r['key_hex'] for r in copied])
        for r in self.private:
            self.assertEqual(r['callback_addend_va'], self.relocations[int(r['callback_slot_va'], 16)]['addend_va'])

    def test_private_comparison_or_copy_corruption(self):
        with self.altered_read(0x38be070, b'\x90'):
            with self.assertRaises(ValueError):
                p.private_cases(self.data, self.sec, self.relocations)
        with self.altered_read(0x38be051, b'\x90'):
            with self.assertRaises(ValueError):
                p.private_cases(self.data, self.sec, self.relocations)
        with self.altered_read(0x38be870, b'\x90'):
            with self.assertRaises(ValueError):
                p.constructor_private_copies(self.data, self.sec)
        with self.altered_read(0x38be870 + 2, b'\x00'):
            with self.assertRaises(ValueError):
                p.constructor_private_copies(self.data, self.sec)

    def test_private_tree_equal_and_callback_boundaries(self):
        targets = {row['label']: row['target_va'] for row in self.evidence['edges.tsv']}
        self.assertEqual(targets['private_tree_equal'], '0x38be438')
        self.assertEqual(targets['private_tree_empty'], '0x38be455')
        with self.altered_read(0x38be41c, b'\x00'):
            with self.assertRaises(ValueError):
                p.check_edges(self.data, self.sec)
        with self.altered_read(0x38be477, b'\x90'):
            with self.assertRaises(ValueError):
                p.check_windows(self.data, self.sec)

    def test_route_09_and_all_private_cases(self):
        self.assertEqual(p.select_route(p.ADDR09, True, self.scaled, self.iterator), 'scaled')
        self.assertEqual(p.select_route(p.ADDR09, False, self.scaled, self.iterator), 'registry')
        for r in self.private:
            key = bytes.fromhex(r['key_hex'])
            self.assertEqual(p.select_route(key, True, self.scaled, self.iterator), 'private')
            self.assertEqual(p.select_route(key, False, self.scaled, self.iterator), 'private')
        for r in self.scaled:
            key = bytes.fromhex(r['key_hex'])
            self.assertEqual(p.select_route(key, True, self.scaled, self.iterator), 'scaled')
            self.assertEqual(p.select_route(key, False, self.scaled, self.iterator), 'registry')

    def test_every_address_bit_is_compared(self):
        for bit in range(160):
            key = bytearray(p.ADDR09)
            key[bit // 8] ^= 1 << (bit % 8)
            selected = [r for r in self.scaled if bytes.fromhex(r['key_hex']) == key]
            self.assertFalse(any(r['callback_addend_va'] == '0x5c16650' for r in selected))
        with self.assertRaises(ValueError):
            p.select_route(b'\x09', True, self.scaled, self.iterator)
        with self.assertRaises(ValueError):
            p.select_route(p.ADDR09, 1, self.scaled, self.iterator)

    def test_reserved_enumerated_addresses_use_registry(self):
        for row in self.iterator:
            if not row['private_index_accepted']:
                self.assertEqual(p.select_route(bytes.fromhex(row['key_hex']), True, self.scaled, self.iterator), 'registry')

    @staticmethod
    def payload(rounds, final=0, length=213):
        result = bytearray(length)
        if length >= 4:
            result[:4] = rounds.to_bytes(4, 'big')
        if length == 213:
            result[212] = final
        return bytes(result)

    def test_scaled_gas_boundaries_and_rounds(self):
        for rounds in (0,1,12,0xffffffff):
            cost = 10 * rounds
            for gas in {cost, min(cost + 1, p.U64_MAX), p.U64_MAX}:
                self.assertEqual(p.model_scaled_09(gas, self.payload(rounds), 10), ('success', cost))
            if cost:
                self.assertEqual(p.model_scaled_09(cost - 1, self.payload(rounds), 10), ('gas', None))

    def test_scaled_input_error_precedence(self):
        self.assertEqual(p.model_scaled_09(0, self.payload(1, length=212), 10), ('length', None))
        self.assertEqual(p.model_scaled_09(9, self.payload(1, final=2), 10), ('gas', None))
        self.assertEqual(p.model_scaled_09(10, self.payload(1, final=2), 10), ('flag', None))
        self.assertEqual(p.model_scaled_09(0, self.payload(0, final=1), 10), ('success', 0))
        with self.assertRaises(ValueError):
            p.model_scaled_09(1, self.payload(0), 0)
        with self.assertRaises(ValueError):
            p.model_scaled_09(-1, self.payload(0), 10)
        with self.assertRaises(ValueError):
            p.model_scaled_09(1 << 64, self.payload(0), 10)

    def test_scaled_division_width_and_saturation(self):
        for gas in ((1 << 32) - 1, 1 << 32, (1 << 32) + 1):
            rounds = gas // 10
            self.assertEqual(p.model_scaled_09(gas, self.payload(rounds), 10), ('success', 10 * rounds))
        self.assertEqual(p.saturating_scale(p.U64_MAX // 10, 10), (p.U64_MAX // 10) * 10)
        self.assertEqual(p.saturating_scale(p.U64_MAX // 10 + 1, 10), p.U64_MAX)
        with self.assertRaises(ValueError):
            p.saturating_scale(0, 0)

    def test_inspected_revision_mapping(self):
        rows = self.evidence['modes.json']['inspected_bytes']
        self.assertEqual([r['mode'] for r in rows], [0,0,0,0,1,1,2,3,3,3,3,4,5,6,6])
        self.assertEqual(rows[13]['mode'], 6)
        self.assertEqual(len(rows), 15)

    def test_activation_flag_copy_lineage(self):
        item = self.evidence['activation-lineage.json']
        self.assertEqual(item['upstream_state_subobject_offset'], '0x1c78')
        self.assertEqual(item['counter_offset_in_state_subobject'], '0x1d60')
        self.assertEqual(item['option_tag_offset_in_state_subobject'], '0x1eb8')
        self.assertEqual(item['option_tag_required'], 1)
        self.assertEqual(item['threshold_offset_in_state_subobject'], '0x1ec0')
        self.assertEqual(item['activation_output_byte_offset'], '0x200')
        self.assertEqual(item['driver_second_argument_flag_offset'], '0x58')
        self.assertEqual(item['provider_flag_output_offset'], '0x88')
        self.assertEqual(item['frame_flag_context_offset'], '0x468')

    def test_activation_copy_corruption_rejected(self):
        with self.altered_read(0x2a071de + 4, b'\x51'):
            with self.assertRaises(ValueError):
                p.activation_lineage(self.data, self.sec)

    def test_activation_boundary_and_overflow(self):
        self.assertFalse(p.model_activation(0, 9, 10))
        self.assertFalse(p.model_activation(2, 9, 10))
        self.assertTrue(p.model_activation(1, 9, 10))
        self.assertFalse(p.model_activation(1, 8, 10))
        self.assertTrue(p.model_activation(1, 0, 0))
        self.assertTrue(p.model_activation(1, p.U64_MAX - 1, p.U64_MAX))
        with self.assertRaises(OverflowError):
            p.model_activation(1, p.U64_MAX, 0)
        with self.assertRaises(ValueError):
            p.model_activation(1, -1, 0)

    def test_generated_evidence_matches_saved_bytes(self):
        folder = p.ROOT / 'research/work-items/RE-021-scaled-precompile-route-115'
        for name, value in self.evidence.items():
            self.assertEqual((folder / name).read_bytes(), p.render(name, value), name)
        self.assertEqual(json.loads((folder / 'summary.json').read_text())['selected_fde_intervals'], 9)


if __name__ == '__main__':
    unittest.main()
