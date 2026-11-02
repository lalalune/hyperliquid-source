"""Static and negative controls for the selected node #94 block-result evidence."""
import bisect
import mmap
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from tools import abci_block_results94 as evidence
from tools.elf_index import sections, unwind_index


def byte_comparison(a, b):
    """Synthetic interpretation of the selected cmp/seta/sbb instruction bytes."""
    if not (0 <= a < 1 << 64 and 0 <= b < 1 << 64):
        raise ValueError('unsigned 64-bit inputs required')
    above = int(a > b)
    below = int(a < b)
    return (above - below) & 0xff


def leaf_model(keys, values, key, value):
    """Bounded explanatory model, not target execution or a full tree model."""
    if (len(keys) != len(values) or len(keys) > 11 or
            keys != sorted(set(keys)) or len(value) != 56 or
            any(len(v) != 56 for v in values)):
        raise ValueError('invalid synthetic leaf')
    byte_comparison(key, key)
    index = 0
    while index < len(keys) and byte_comparison(key, keys[index]) == 1:
        index += 1
    out_keys, out_values = list(keys), list(values)
    if index < len(keys) and byte_comparison(key, keys[index]) == 0:
        old = out_values[index]
        out_values[index] = value
        return 'replace', out_keys, out_values, old
    if len(keys) == 11:
        return 'nonempty-helper', out_keys, out_values, None
    out_keys.insert(index, key)
    out_values.insert(index, value)
    return 'insert', out_keys, out_values, None


def counter_mode_model(mode, counter, height):
    """Model the selected 32-bit mode and wrapping 64-bit locked increment."""
    if not (0 <= mode < 1 << 32 and 0 <= counter < 1 << 64 and 0 <= height < 1 << 64):
        raise ValueError('invalid synthetic word')
    if mode != 2:
        return 'state-map-arm', counter
    counter = (counter + 1) & ((1 << 64)-1)
    return ('bypass-arm' if counter == height else 'failure-arm'), counter


def serial_prefix_model(words, capacity):
    """Model only the sentinel and capacity decisions in the serial loop."""
    if capacity < 0:
        raise ValueError('negative capacity')
    output = []
    for word in words:
        if not 0 <= word < 1 << 64:
            raise ValueError('invalid synthetic header word')
        if word == 1 << 63:
            return 'sentinel-stop', output
        if len(output) >= capacity:
            return 'capacity-failure', output
        output.append(word)
    return 'input-end', output


def status_cleanup_model(tags):
    """Select indices whose observed 16-bit tag takes the helper path."""
    if any(not 0 <= tag < 1 << 16 for tag in tags):
        raise ValueError('invalid synthetic tag')
    return [i for i, tag in enumerate(tags) if tag != 0x186]


class StaticEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.input_file = evidence.BINARY.open('rb')
        cls.data = mmap.mmap(cls.input_file.fileno(), 0, access=mmap.ACCESS_COPY)
        cls.secs = sections(cls.data)
        cls.records = evidence.collect(cls.data)

    @classmethod
    def tearDownClass(cls):
        cls.data.close()
        cls.input_file.close()

    def mutate_and_reject(self, va, action, offset=0, executable=True):
        off, _ = evidence.file_offset(self.secs, va, offset + 1, executable=executable)
        off += offset
        old = self.data[off]
        try:
            self.data[off] = old ^ 1
            with self.assertRaises(ValueError):
                action()
        finally:
            self.data[off] = old

    def test_digest_accepts_target_and_rejects_corruption(self):
        evidence.verify_sha(self.data)
        self.mutate_and_reject(0x47f60d0, lambda: evidence.verify_sha(self.data))
        with self.assertRaises(ValueError):
            evidence.verify_sha(b'not the target')

    def test_missing_or_wrong_target_never_writes_output(self):
        with TemporaryDirectory() as temp:
            base = Path(temp)
            fake = base / 'wrong-node'
            output = base / 'evidence'
            fake.write_bytes(b'not the authenticated node')
            with patch.object(evidence, 'BINARY', fake):
                with self.assertRaises(ValueError):
                    evidence.generate(output)
            self.assertFalse(output.exists())
            with patch.object(evidence, 'BINARY', base / 'missing-node'):
                with self.assertRaises(FileNotFoundError):
                    evidence.generate(output)
            self.assertFalse(output.exists())

    def test_selected_fdes_and_indices(self):
        funcs = self.records[0]
        self.assertEqual(len(funcs), 21)
        self.assertEqual({x[1] for x in funcs}, {x[1] for x in evidence.OWNED})
        for name, start, end, fde, index, sec, off, digest, raw in funcs:
            with self.subTest(name=name):
                self.assertGreater(end, start)
                self.assertEqual(len(raw), end-start)
                self.assertEqual(sec, '.text')
                self.assertGreater(fde, 0)
                self.assertGreaterEqual(index, 0)
                self.assertEqual(evidence.file_offset(self.secs, start, end-start)[0], off)

    def test_selected_fde_range_corruption_is_detected(self):
        secs, table = unwind_index(self.data)
        fde_va = self.records[0][0][3]
        self.mutate_and_reject(fde_va, lambda: evidence.selected_fdes(self.data, secs, table),
                               offset=12, executable=False)

    def test_selected_unwind_index_corruption_is_detected(self):
        header = next(s for s in self.secs if s['name'] == '.eh_frame_hdr')
        index = self.records[0][0][4]
        va = header['address'] + 12 + index*8 + 4
        def parse():
            secs, table = unwind_index(self.data)
            evidence.selected_fdes(self.data, secs, table)
        self.mutate_and_reject(va, parse, executable=False)

    def test_each_body_pin_detects_corruption(self):
        for name, start, end, sha in evidence.OWNED:
            with self.subTest(name=name):
                self.mutate_and_reject(start,
                    lambda: evidence.pinned_bytes(self.data, self.secs, start, end, sha))

    def test_each_window_pin_detects_corruption(self):
        for name, start, end, sha in evidence.WINDOWS:
            with self.subTest(name=name):
                self.mutate_and_reject(start,
                    lambda: evidence.pinned_bytes(self.data, self.secs, start, end, sha))

    def test_each_branch_opcode_and_displacement_corruption(self):
        for name, va, condition, target in evidence.BRANCHES:
            with self.subTest(name=name):
                off, _ = evidence.file_offset(self.secs, va, 2)
                near = self.data[off] == 0x0f
                check = lambda: evidence.branch(self.data, self.secs, va, condition, target)
                self.mutate_and_reject(va, check, offset=1 if near else 0)
                self.mutate_and_reject(va, check, offset=2 if near else 1)

    def test_each_guard_corruption_and_adjacency(self):
        branches = {name: va for name, va, _, _ in evidence.BRANCHES}
        self.assertEqual(len(self.records[10]), len(evidence.GUARDS))
        for name, va, expected in evidence.GUARDS:
            with self.subTest(name=name):
                site = branches[name]
                check = lambda: evidence.guard(self.data, self.secs, va, expected, site)
                self.mutate_and_reject(va, check)
                with self.assertRaises(ValueError):
                    evidence.guard(self.data, self.secs, va, expected, site+1)

    def test_each_direct_transfer_opcode_and_displacement_corruption(self):
        for name, va, kind, target in evidence.TRANSFERS:
            with self.subTest(name=name):
                check = lambda: evidence.transfer(self.data, self.secs, va, kind, target)
                self.mutate_and_reject(va, check, offset=0)
                self.mutate_and_reject(va, check, offset=1)

    def test_each_indirect_transfer_opcode_and_displacement_corruption(self):
        for name, va, slot in evidence.INDIRECT:
            with self.subTest(name=name):
                check = lambda: evidence.indirect(self.data, self.secs, va, slot)
                self.mutate_and_reject(va, check, offset=0)
                self.mutate_and_reject(va, check, offset=2)

    def test_each_indirect_tail_opcode_and_displacement_corruption(self):
        self.assertEqual(len(self.records[13]), len(evidence.INDIRECT_TAILS))
        for name, va, slot in evidence.INDIRECT_TAILS:
            with self.subTest(name=name):
                check = lambda: evidence.indirect_tail(self.data, self.secs, va, slot)
                self.mutate_and_reject(va, check, offset=0)
                self.mutate_and_reject(va, check, offset=2)

    def test_each_operand_prefix_and_value_corruption(self):
        for name, va, prefix, width, expected in evidence.OPERANDS:
            with self.subTest(name=name):
                check = lambda: evidence.operand(self.data, self.secs, va, prefix, width, expected)
                self.mutate_and_reject(va, check, offset=0)
                self.mutate_and_reject(va, check, offset=len(bytes.fromhex(prefix)))

    def test_every_jump_table_bound_reference_and_data_corruption(self):
        self.assertEqual(len(self.records[11]), 7)
        self.assertEqual(len(self.records[12]), 296)
        for spec in evidence.TABLES:
            name, lea_va, prefix, base, bound_va, bound_prefix, width, bound, sha = spec
            with self.subTest(name=name):
                check = lambda: evidence.jump_table(self.data, self.secs, spec)
                self.mutate_and_reject(lea_va, check, offset=0)
                self.mutate_and_reject(lea_va, check, offset=3)
                self.mutate_and_reject(bound_va, check, offset=len(bytes.fromhex(bound_prefix)))
                self.mutate_and_reject(base, check, executable=False)
        primary = evidence.TABLES[0]
        secondary = evidence.TABLES[1]
        self.mutate_and_reject(0x47e3948, lambda: evidence.jump_table(self.data, self.secs, primary), offset=2)
        self.mutate_and_reject(0x47e3981, lambda: evidence.jump_table(self.data, self.secs, secondary), offset=1)

    def test_dispatch_tables_encode_selected_nested_paths(self):
        tables = {}
        for name, index, selector, va, off, displacement, target, raw in self.records[12]:
            tables.setdefault(name, {})[selector] = target
            self.assertEqual(self.data[off:off+4], raw)
            self.assertEqual(va + displacement - index*4, target)
        self.assertEqual(len(tables['primary']), 193)
        self.assertEqual(len(tables['secondary']), 40)
        self.assertEqual(sum(target == 0x47e3b10 for target in tables['primary'].values()), 172)
        self.assertEqual(sum(target == 0x47e3b10 for target in tables['secondary'].values()), 36)
        self.assertEqual([len(tables[name]) for name in ('nested32','nested14','nested7','nested5a','nested5b')],
                         [32, 14, 7, 5, 5])
        self.assertEqual(tables['primary'][0x3a], 0x47e3a15)
        self.assertEqual(tables['primary'][0x3b], 0x47e3963)
        self.assertEqual(tables['primary'][0xbb], 0x47e3aab)
        self.assertEqual(tables['nested7'][0], 0x47e3ac5)
        self.assertEqual(tables['nested7'][2], 0x47e3b10)
        self.assertEqual(tables['secondary'][0x14b], 0x47e399f)
        self.assertEqual(tables['nested32'][3], 0x47e39bd)
        self.assertEqual(tables['nested14'][9], 0x47e39db)
        self.assertEqual(tables['nested32'][16], 0x47e3be4)
        self.assertEqual(tables['nested5a'][4], 0x47e3c29)
        self.assertEqual(tables['nested5b'][1], 0x47e3b10)
        self.assertEqual(tables['secondary'][0x159], 0x47e3963)
        self.assertEqual(tables['secondary'][0x172], 0x47e3a15)
        self.assertNotIn(0x186, tables['primary'])
        self.assertNotIn(0x186, tables['secondary'])

    def test_all_u16_tags_follow_the_two_pinned_unsigned_bounds(self):
        mask = (1 << 32)-1
        table_names = {row[0] for row in self.records[11]}
        self.assertIn('primary', table_names)
        self.assertIn('secondary', table_names)
        for tag in range(1 << 16):
            first_index = (tag - 0x3a) & mask
            second_index = (tag - 0x14b) & mask
            route = ('primary' if first_index <= 0xc0 else
                     'secondary' if second_index <= 0x27 else 'return')
            expected = ('primary' if 0x3a <= tag <= 0xfa else
                        'secondary' if 0x14b <= tag <= 0x172 else 'return')
            self.assertEqual(route, expected)
        off, _ = evidence.file_offset(self.secs, 0x47e3b10, 6)
        self.assertEqual(self.data[off:off+6], bytes.fromhex('5b415e415fc3'))

    def test_each_literal_and_reference_corruption(self):
        for name, va, expected, ref_va, length_va in evidence.LITERALS:
            with self.subTest(name=name):
                check = lambda: evidence.literal(self.data, self.secs, va, expected, ref_va, length_va)
                self.mutate_and_reject(va, check, executable=False)
                self.mutate_and_reject(ref_va, check, offset=3)
                self.mutate_and_reject(length_va, check, offset=1)

    def test_each_lsda_header_and_row_corruption(self):
        funcs = {row[0]: row for row in self.records[0]}
        for item in self.records[7]:
            name, start, va, off, sec, upper, encoding, type_base, header_size, size, sha, raw, count = item
            with self.subTest(name=name):
                fde = {'start': start, 'end': funcs[name][2], 'lsda': va}
                check = lambda: evidence.lsda_table(self.data, self.secs, fde, upper, va, sha)
                self.assertEqual(sec, '.gcc_except_table')
                self.assertEqual(len(raw), header_size + size)
                self.assertGreater(count, 0)
                self.mutate_and_reject(va, check, executable=False)
                self.mutate_and_reject(va, check, offset=header_size, executable=False)
                with self.assertRaises(ValueError):
                    evidence.lsda_table(self.data, self.secs, fde, va+1, va, sha)
                with self.assertRaises(ValueError):
                    evidence.lsda_table(self.data, self.secs, fde, upper, va+1, sha)

    def test_lsda_ranges_and_selected_call_associations(self):
        funcs = {row[0]: row for row in self.records[0]}
        self.assertEqual(len(self.records[7]), 18)
        self.assertEqual(len(self.records[8]), 127)
        for name, start, end, landing, action, off, raw in self.records[8]:
            with self.subTest(name=name, start=start):
                self.assertLessEqual(funcs[name][1], start)
                self.assertLessEqual(start, end)
                self.assertLessEqual(end, funcs[name][2])
                if landing is not None:
                    self.assertLessEqual(funcs[name][1], landing)
                    self.assertLess(landing, funcs[name][2])
                self.assertGreaterEqual(action, 0)
                self.assertEqual(self.data[off:off+len(raw)], raw)
        associations = {row[0]: row for row in self.records[9]}
        self.assertEqual(associations['orchestrator_descriptors'][3:], ('covered', 0x446d8ee, 0))
        self.assertEqual(associations['orchestrator_result_headers'][3:], ('covered', 0x446d8d9, 0))
        self.assertEqual(associations['partition_serial'][3:], ('no_lsda', None, None))
        self.assertEqual(associations['delayed_allocation'][3:], ('no_covering_record', None, None))

    def test_nobits_nonexec_out_of_bounds_and_ambiguity_rejected(self):
        fixture = [dict(type=8, size=8, flags=4, address=100, offset=10, name='nobits')]
        with self.assertRaises(ValueError):
            evidence.file_offset(fixture, 100, 1)
        fixture[0]['type'] = 1
        fixture[0]['flags'] = 0
        with self.assertRaises(ValueError):
            evidence.file_offset(fixture, 100, 1)
        self.assertEqual(evidence.file_offset(fixture, 100, 1, executable=False), (10, 'nobits'))
        with self.assertRaises(ValueError):
            evidence.file_offset(fixture, 107, 2, executable=False)
        with self.assertRaises(ValueError):
            evidence.file_offset(fixture, -1, 1, executable=False)
        with self.assertRaises(ValueError):
            evidence.file_offset(fixture, 100, 0, executable=False)
        with self.assertRaises(ValueError):
            evidence.file_offset(fixture + [dict(fixture[0])], 100, 1, executable=False)
        bss = next(s for s in self.secs if s['name'] == '.bss')
        self.assertEqual(bss['type'], 8)
        with self.assertRaises(ValueError):
            evidence.file_offset(self.secs, bss['address'], 1, executable=False)
        with self.assertRaises(ValueError):
            evidence.file_offset(self.secs, (1 << 64)-1, 8, executable=False)

    def test_invalid_instruction_encodings_rejected(self):
        fixture = [dict(type=1, size=8, flags=4, address=100, offset=0, name='code')]
        for raw in (b'\x90'*8, b'\x0f\x1f'+b'\0'*6):
            with self.subTest(raw=raw):
                with self.assertRaises(ValueError):
                    evidence.branch(raw, fixture, 100, 'e', 102)
                with self.assertRaises(ValueError):
                    evidence.transfer(raw, fixture, 100, 'call', 105)
                with self.assertRaises(ValueError):
                    evidence.indirect(raw, fixture, 100, 106)
        with self.assertRaises(ValueError):
            evidence.operand(b'\x90'*8, fixture, 100, '90', 3, 0)

    def test_branch_and_transfer_targets_are_executable(self):
        for _, _, _, _, _, _, target, _ in self.records[2]:
            evidence.file_offset(self.secs, target, 1)
        for _, _, _, _, _, target, _ in self.records[3]:
            evidence.file_offset(self.secs, target, 1)

    def test_operand_values_bind_reconstructed_layout(self):
        values = {name:value for name, _, _, _, value, _ in self.records[5]}
        self.assertEqual(values['delayed_input_stride'], 328)
        self.assertEqual(values['zip_record_stride'], 64)
        self.assertEqual(values['temporary_key_value_stride'], 56)
        self.assertEqual(values['state_key_value_stride'], 56)
        self.assertEqual(values['result_value_stride'], 56)
        self.assertEqual(values['state_map_offset'], 0x3b10)
        self.assertEqual(values['zip_sentinel'], 1 << 63)
        self.assertEqual(values['temporary_node_capacity'], 11)
        self.assertEqual(values['state_node_capacity'], 11)
        self.assertEqual(values['serial_input_pointer_stride'], 8)
        self.assertEqual(values['serial_output_record_stride'], 32)
        self.assertEqual(values['nested_result_record_stride'], 112)
        self.assertEqual(values['descriptor_item_stride'], 112)
        self.assertEqual(values['descriptor_item_status_tag'], values['action_status_tag'])
        self.assertEqual(values['serial_item_status_tag'], values['action_status_tag'])
        self.assertEqual(1 << values['descriptor_range_shift'], 32)
        self.assertEqual(1 << values['zip_output_range_shift'], 64)
        self.assertEqual(1 << values['state_input_range_shift'], 64)
        self.assertEqual((3 * values['result_header_inverse_three']) & ((1 << 64)-1), 1)

    def test_comparator_machine_bytes(self):
        expected = bytes.fromhex('483b54f810410f97c34180db00')
        for va in (0x4936805, 0x4929e55):
            off, _ = evidence.file_offset(self.secs, va, len(expected))
            self.assertEqual(self.data[off:off+len(expected)], expected)


class SyntheticModelTests(unittest.TestCase):
    def test_unsigned_comparison_against_bisect_boundaries(self):
        keys = [0, 1, (1 << 63)-1, 1 << 63, (1 << 64)-1]
        cases = [0, 1, 2, (1 << 63)-2, (1 << 63)-1,
                 1 << 63, (1 << 63)+1, (1 << 64)-2, (1 << 64)-1]
        for key in cases:
            cursor = 0
            while cursor < len(keys) and byte_comparison(key, keys[cursor]) == 1:
                cursor += 1
            self.assertEqual(cursor, bisect.bisect_left(keys, key))
        self.assertEqual(byte_comparison(0, (1 << 64)-1), 0xff)
        self.assertEqual(byte_comparison((1 << 64)-1, 0), 1)
        with self.assertRaises(ValueError):
            byte_comparison(-1, 0)
        with self.assertRaises(ValueError):
            byte_comparison(1 << 64, 0)

    def test_leaf_insert_replace_and_full_leaf(self):
        keys = [0, 3, 1 << 63]
        values = [bytes([i])*56 for i in (1, 2, 3)]
        action, new_keys, new_values, old = leaf_model(keys, values, 3, b'N'*56)
        self.assertEqual((action, new_keys, old), ('replace', keys, b'\x02'*56))
        self.assertEqual(new_values, [values[0], b'N'*56, values[2]])
        self.assertEqual(values[1], b'\x02'*56)
        action, new_keys, new_values, old = leaf_model(keys, values, 2, b'I'*56)
        self.assertEqual((action, new_keys, old), ('insert', [0, 2, 3, 1 << 63], None))
        self.assertEqual(new_values[1], b'I'*56)
        full = list(range(0,22,2))
        result = leaf_model(full, [b'A'*56]*11, 3, b'B'*56)
        self.assertEqual(result[0], 'nonempty-helper')
        self.assertEqual(result[1], full)
        self.assertEqual(leaf_model(full, [b'A'*56]*11, 4, b'B'*56)[0], 'replace')
        with self.assertRaises(ValueError):
            leaf_model([1, 1], [b'A'*56]*2, 1, b'B'*56)
        with self.assertRaises(ValueError):
            leaf_model([], [], 1, b'wrong-size')

    def test_allocation_limits_and_modular_factors(self):
        range_limit = 0x749f49f49f49f498
        allocation_factor = 0xf3831f3831f38328
        count_factor = 0x8f9c18f9c18f9c19
        mask = (1 << 64)-1
        maximum = ((1 << 63)-1)//0x168
        self.assertEqual(range_limit, maximum*0x148)
        for n in (0, 1, 2, maximum-1, maximum):
            delta = n*0x148
            self.assertLessEqual(delta, range_limit)
            self.assertEqual(((delta >> 3)*count_factor) & mask, n)
            self.assertEqual(((delta >> 3)*allocation_factor) & mask, n*0x168)
        self.assertGreater((maximum+1)*0x148, range_limit)
        limit = 0x249249249249249
        self.assertEqual(limit, ((1 << 63)-1)//56)
        self.assertLessEqual(limit*56, (1 << 63)-1)
        self.assertGreater((limit+1)*56, (1 << 63)-1)
        for n in (0, 1, 2, 127, ((1 << 63)-1)//24):
            self.assertEqual((((n*24) >> 3)*0xaaaaaaaaaaaaaaab) & mask, n)

    def test_neg_overflow_sentinel_is_unique_for_boundary_words(self):
        mask = (1 << 64)-1
        signed_min = 1 << 63
        for word in (0, 1, signed_min-1, signed_min, signed_min+1, mask):
            result = (-word) & mask
            overflow = word != 0 and result == word
            self.assertEqual(overflow, word == signed_min)

    def test_mode_branch_increment_equality_and_wrap(self):
        self.assertEqual(counter_mode_model(0, 4, 5), ('state-map-arm', 4))
        self.assertEqual(counter_mode_model(3, 4, 5), ('state-map-arm', 4))
        self.assertEqual(counter_mode_model(2, 4, 5), ('bypass-arm', 5))
        self.assertEqual(counter_mode_model(2, 4, 6), ('failure-arm', 5))
        self.assertEqual(counter_mode_model(2, (1 << 64)-1, 0), ('bypass-arm', 0))
        self.assertEqual(counter_mode_model(2, (1 << 64)-1, 1), ('failure-arm', 0))
        with self.assertRaises(ValueError):
            counter_mode_model(2, -1, 0)

    def test_serial_sentinel_and_capacity_are_distinct(self):
        sentinel = 1 << 63
        self.assertEqual(serial_prefix_model([], 0), ('input-end', []))
        self.assertEqual(serial_prefix_model([sentinel, 7], 0), ('sentinel-stop', []))
        self.assertEqual(serial_prefix_model([1, sentinel, 9], 2), ('sentinel-stop', [1]))
        self.assertEqual(serial_prefix_model([1, 2], 2), ('input-end', [1, 2]))
        self.assertEqual(serial_prefix_model([1, 2], 1), ('capacity-failure', [1]))
        self.assertEqual(serial_prefix_model([(1 << 64)-1], 1), ('input-end', [(1 << 64)-1]))
        with self.assertRaises(ValueError):
            serial_prefix_model([-1], 1)

    def test_cleanup_tag_neighbors_and_repeated_entries(self):
        self.assertEqual(status_cleanup_model([]), [])
        self.assertEqual(status_cleanup_model([0x186, 0x186]), [])
        self.assertEqual(status_cleanup_model([0, 0x185, 0x186, 0x187, 0xffff]), [0, 1, 3, 4])
        with self.assertRaises(ValueError):
            status_cleanup_model([1 << 16])


if __name__ == '__main__':
    unittest.main()
