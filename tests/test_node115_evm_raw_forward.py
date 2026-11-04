"""Static controls for the node 115 raw-transaction forwarding evidence."""
import csv
import hashlib
from pathlib import Path
import struct
import tempfile
import unittest

from tools import node115_evm_raw_forward as m


class ModifiedImage:
    def __init__(self, base, changed_va):
        self.base = base
        self.changed_va = changed_va

    def read(self, va, length, required_flags=2):
        data = bytearray(self.base.read(va, length, required_flags))
        if va <= self.changed_va < va + length:
            data[self.changed_va - va] ^= 1
        return bytes(data)


def section(name, va, off, size, flags=2, typ=1):
    return {'name': name, 'address': va, 'offset': off, 'size': size,
            'flags': flags, 'type': typ}


class StaticForwardEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = m.TARGET.read_bytes()
        m.check_digest(cls.data)
        cls.image = m.Image(cls.data)
        cls.hex_table = cls.image.read(0x46d50c, 256)
        cls.constants = [cls.image.read(x, 16) for x in
                         (0x455d80, 0x455a20, 0x4536c0, 0x453ac0, 0x4566a0)]
        cls.alphabet = cls.image.read(0x455d40, 16)

    def test_target_digest(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), m.TARGET_SHA256)
        with self.assertRaises(m.EvidenceError):
            m.check_digest(b'wrong binary')
        with self.assertRaises(m.EvidenceError):
            m.check_digest(self.data, '0' * 64)

    def test_digest_failure_precedes_output_creation(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / 'generated'
            with self.assertRaises(m.EvidenceError):
                m.generate(b'wrong binary', target)
            self.assertFalse(target.exists())

    def test_instruction_window_rejects_corruption(self):
        name, va, encoded = m.PINNED_WINDOWS[0]
        self.assertTrue(name)
        expected = bytes.fromhex(encoded)
        m.verify_pin(self.image, va, expected)
        with self.assertRaises(m.EvidenceError):
            m.verify_pin(ModifiedImage(self.image, va + len(expected) // 2), va, expected)
        with self.assertRaises(m.EvidenceError):
            m.verify_pin(self.image, va, b'')

    def test_invalid_virtual_addresses_are_rejected(self):
        for va, size in ((-1, 1), (0, 1), (1 << 64, 1), ((1 << 64) - 1, 2), (0, 0)):
            with self.subTest(va=va, size=size), self.assertRaises(m.EvidenceError):
                self.image.read(va, size)

    def test_nobits_and_ambiguous_sections_are_rejected(self):
        memory = b'abcd'
        nobits = m.Image(memory, [section('.bss', 0x1000, 0, 4, typ=8)])
        with self.assertRaises(m.EvidenceError):
            nobits.read(0x1000, 1)
        duplicate = m.Image(memory, [section('a', 0x1000, 0, 4), section('b', 0x1000, 0, 4)])
        with self.assertRaises(m.EvidenceError):
            duplicate.read(0x1000, 1)
        truncated = m.Image(memory, [section('a', 0x1000, 0, 10)])
        with self.assertRaises(m.EvidenceError):
            truncated.read(0x1003, 2)

    def test_branch_bounds_and_opcode_controls(self):
        good = m.Image(b'\x75\x00\x90', [section('code', 0x1000, 0, 3, flags=6)])
        op, target, raw = m.decode_branch(good, 0x1000, 0x1000, 0x1003)
        self.assertEqual((op, target, raw), ('jne', 0x1002, b'\x75\x00'))
        bad = m.Image(b'\x75\x7f', [section('code', 0x1000, 0, 2, flags=6)])
        with self.assertRaises(m.EvidenceError):
            m.decode_branch(bad, 0x1000, 0x1000, 0x1002)
        not_branch = m.Image(b'\x90', [section('code', 0x1000, 0, 1, flags=6)])
        with self.assertRaises(m.EvidenceError):
            m.decode_branch(not_branch, 0x1000, 0x1000, 0x1001)

    def test_jump_table_rejects_target_outside_owner(self):
        code = b'\x48\x8d\x0d' + struct.pack('<i', 0x2000 - 0x1007)
        secs = [section('code', 0x1000, 0, 7, flags=6), section('table', 0x2000, 7, 4)]
        good = m.Image(code + struct.pack('<i', 0x1010 - 0x2000), secs)
        owner = {'start': 0x1000, 'end': 0x1100}
        self.assertEqual(m.read_jump_table(good, 0x1000, 0x2000, 1, owner), [0x1010])
        bad = m.Image(code + struct.pack('<i', 0x3000 - 0x2000), secs)
        with self.assertRaises(m.EvidenceError):
            m.read_jump_table(bad, 0x1000, 0x2000, 1, owner)
        with self.assertRaises(m.EvidenceError):
            m.read_jump_table(good, 0x1000, 0x2001, 1, owner)

    def test_extent_ownership_rejects_outside_or_overlap(self):
        extents = {1: {'start': 0x1000, 'end': 0x1010}}
        self.assertEqual(m.owner_for(extents, 0x1000, 16), extents[1])
        with self.assertRaises(m.EvidenceError):
            m.owner_for(extents, 0x100f, 2)
        with self.assertRaises(m.EvidenceError):
            m.owner_for({1: extents[1], 2: dict(extents[1])}, 0x1000)

    def test_relocation_type_addend_duplicates_and_missing(self):
        spec = (('slot', 0x2000, 0x1010),)
        def image(records):
            data = b''.join(records)
            return m.Image(data, [section('.rela.dyn', 0, 0, len(data), flags=0, typ=4)])
        valid = struct.pack('<QQq', 0x2000, 8, 0x1010)
        found = m.find_relocations(image([valid]), spec)
        self.assertEqual(found[0x2000][1:3], (8, 0x1010))
        for records in ([struct.pack('<QQq', 0x2000, 7, 0x1010)],
                        [struct.pack('<QQq', 0x2000, 8, 0x1011)],
                        [valid, valid], [struct.pack('<QQq', 0x2008, 8, 0x1010)]):
            with self.subTest(records=records), self.assertRaises(m.EvidenceError):
                m.find_relocations(image(records), spec)

    def test_selected_actual_relocations(self):
        found = m.find_relocations(self.image)
        self.assertEqual(set(found), {site for _, site, _ in m.RELOCATIONS})
        self.assertEqual(found[0x640e958][2], 0x17480e0)
        self.assertEqual(found[0x64e1e50][2], 0x167afd0)

    def test_named_and_positional_dispatch_call_sites(self):
        checks = ((0x16b3f57, 0x16ffb20), (0x16b3feb, 0x173f540),
                  (0x1702da3, 0x16ef140), (0x16ef1a6, 0x1705750),
                  (0x1702f17, 0x16ef310))
        for site, target in checks:
            with self.subTest(site=site):
                self.assertEqual(m.relative_target(self.image, site, b'\xe8', 5), target)
        with self.assertRaises(m.EvidenceError):
            m.relative_target(ModifiedImage(self.image, 0x16b3feb), 0x16b3feb, b'\xe8', 5)

    def test_hex_lookup_all_256_bytes(self):
        self.assertEqual(m.require_hex_table(self.hex_table), self.hex_table)
        for byte in range(256):
            if ord('0') <= byte <= ord('9'):
                expected = byte - ord('0')
            elif ord('A') <= byte <= ord('F'):
                expected = byte - ord('A') + 10
            elif ord('a') <= byte <= ord('f'):
                expected = byte - ord('a') + 10
            else:
                expected = 255
            self.assertEqual(self.hex_table[byte], expected, f'{byte:02x}')
        corrupt = bytearray(self.hex_table)
        corrupt[ord('0')] = 255
        with self.assertRaises(m.EvidenceError):
            m.require_hex_table(bytes(corrupt))

    def test_hex_error_order_and_prefix(self):
        decode = lambda value: m.decode_hex(value, self.hex_table)
        self.assertEqual(decode(b''), ('ok', b'', None))
        self.assertEqual(decode(b'0x'), ('ok', b'', None))
        self.assertEqual(decode(b'z'), ('odd', None, None))
        self.assertEqual(decode(b'0x0'), ('odd', None, None))
        self.assertEqual(decode(b'0X'), ('invalid', 1, ord('X')))
        self.assertEqual(decode(b'0xzz'), ('invalid', 0, ord('z')))
        self.assertEqual(decode(b'0x01g0'), ('invalid', 2, ord('g')))
        self.assertEqual(decode(b'ABCDef'), ('ok', bytes.fromhex('abcdef'), None))

    def test_hex_all_byte_roundtrip_and_lengths(self):
        for size in (0, 1, 2, 15, 16, 17, 31, 32, 33, 63, 64, 65, 256):
            data = bytes(n % 256 for n in range(size))
            encoded = m.encode_hex(data, self.alphabet)
            self.assertEqual(encoded, ('0x' + data.hex()).encode('ascii'))
            self.assertEqual(m.decode_hex(encoded, self.hex_table), ('ok', data, None))
        with self.assertRaises(m.EvidenceError):
            m.encode_hex(b'\xff', b'0123456789abcdeF')

    def test_vector_validator_all_lanes_and_corruption(self):
        for byte in range(256):
            for lane in range(16):
                self.assertEqual(m.vector_invalid(byte, lane, self.constants),
                                 self.hex_table[byte] == 255)
        bad = list(self.constants)
        bad[0] = bytes([0]) + bad[0][1:]
        self.assertTrue(any(m.vector_invalid(x, 0, bad) != (self.hex_table[x] == 255)
                            for x in range(256)))
        with self.assertRaises(m.EvidenceError):
            m.vector_invalid(0, 16, self.constants)
        with self.assertRaises(m.EvidenceError):
            m.vector_invalid(0, 0, self.constants[:-1])

    def test_vector_decode_arithmetic_all_valid_pairs(self):
        valid = [b for b in range(256) if self.hex_table[b] != 255]
        self.assertEqual(len(valid), 22)
        for high in valid:
            for low in valid:
                vector_high = (high & 15) + 9 * (high >> 6)
                vector_low = (low & 15) + 9 * (low >> 6)
                self.assertEqual(vector_high * 16 + vector_low,
                                 self.hex_table[high] * 16 + self.hex_table[low])

    def test_array_delimiter_first_and_later_states(self):
        mask = struct.unpack('<Q', self.image.read(0x1705647, 8, 4))[0]
        next_item = lambda first, data: m.array_delimiter_case(first, data, mask)
        self.assertEqual(next_item(True, b''), ('error', 0, 2))
        self.assertEqual(next_item(True, b' \t]'), ('end', 2, None))
        self.assertEqual(next_item(True, b' 12'), ('item', 1, None))
        self.assertEqual(next_item(False, b' 12'), ('error', 1, 7))
        self.assertEqual(next_item(False, b','), ('error', 1, 5))
        self.assertEqual(next_item(False, b', \t]'), ('error', 3, 21))
        self.assertEqual(next_item(False, b', 255'), ('item', 2, None))
        self.assertEqual(next_item(False, b']'), ('end', 0, None))
        self.assertEqual(next_item(False, b'\x0b]'), ('error', 0, 7))
        with self.assertRaises(m.EvidenceError):
            m.array_delimiter_case(True, b']', mask ^ 1)
        with self.assertRaises(m.EvidenceError):
            m.array_delimiter_case(1, b']', mask)

    def test_numeric_item_result_boundaries(self):
        for kind in (1, 2):
            for number in (0, 1, 254, 255):
                self.assertEqual(m.numeric_item_case(kind, number), ('byte', number))
            for number in (256, (1 << 64) - 1):
                self.assertEqual(m.numeric_item_case(kind, number), ('error', None))
        for kind in (0, 3, 255):
            self.assertEqual(m.numeric_item_case(kind, 0), ('error', None))
        for invalid in (-1, 1 << 64):
            with self.assertRaises(m.EvidenceError):
                m.numeric_item_case(1, invalid)

    def test_selector_full_domain_and_invalid(self):
        actual = [m.chain_case(i) for i in range(256)]
        self.assertEqual(actual[:4], ['unsupported', 'unsupported', 'testnet_endpoint', 'mainnet_endpoint'])
        self.assertEqual(actual[4:], ['mainnet_endpoint'] * 252)
        for invalid in (-1, 256, True):
            with self.assertRaises(m.EvidenceError):
                m.chain_case(invalid)

    def test_selector_machine_branches_and_endpoints(self):
        self.assertEqual(self.image.read(0x1748153, 3, 4), b'\x83\xf8\x02')
        op, target, _ = m.decode_branch(self.image, 0x1748156, 0x17480e0, 0x174bd5e)
        self.assertEqual((op, target), ('jae', 0x1748377))
        op, target, _ = m.decode_branch(self.image, 0x1748377, 0x17480e0, 0x174bd5e)
        self.assertEqual((op, target), ('jne', 0x174842e))
        self.assertEqual(m.relative_target(self.image, 0x174837d, b'\x48\x8d\x05', 7), 0x4806a1)
        self.assertEqual(m.relative_target(self.image, 0x174842e, b'\x48\x8d\x05', 7), 0x4806c8)
        with self.assertRaises(m.EvidenceError):
            m.relative_target(ModifiedImage(self.image, 0x174837d), 0x174837d, b'\x48\x8d\x05', 7)

    def test_captured_layout_and_poll_state(self):
        layout = m.selector_layout(self.image)
        self.assertEqual(len(layout), 8)
        self.assertEqual(layout[-1][-1], '0xc8')
        states = m.selected_state_writes(self.image)
        self.assertEqual(states[:4], [('outer_pending', '0x16b40b9', 'nested_state', 3),
                                     ('outer_pending', '0x16b40c6', 'output_tag', 2),
                                     ('outer_pending', '0x16b40cd', 'outer_state', 3),
                                     ('outer_ready', '0x16b43d1', 'outer_state', 1)])
        with self.assertRaises(m.EvidenceError):
            m.selector_layout(ModifiedImage(self.image, 0x174814b))
        with self.assertRaises(m.EvidenceError):
            m.selected_state_writes(ModifiedImage(self.image, 0x16b40bd))

    def test_body_poll_state_and_error_handoff(self):
        rows = m.selected_body_writes(self.image)
        self.assertEqual([r[3] for r in rows], [3, 4, 5, 2, 1, 1, 0])
        self.assertEqual(self.image.read(0x174a7ad, 4, 4), b'\x48\x83\xfb\x01')
        branch, target, _ = m.decode_branch(self.image, 0x174a7b1, 0x17480e0, 0x174bd5e)
        self.assertEqual((branch, target), ('jne', 0x174a806))
        with self.assertRaises(m.EvidenceError):
            m.selected_body_writes(ModifiedImage(self.image, 0x16fc3a5))

    def test_body_length_addition_and_overflow_branch(self):
        top = (1 << 64) - 1
        self.assertEqual(m.checked_sum_u64(top, 0), (top, 0))
        self.assertEqual(m.checked_sum_u64(top - 7, 7), (top, 0))
        self.assertEqual(m.checked_sum_u64(top - 7, 8), (0, 1))
        self.assertEqual(m.checked_sum_u64(top, 1), (0, 1))
        for left, right in ((-1, 1), (0, 1 << 64), (True, 0)):
            with self.assertRaises(m.EvidenceError):
                m.checked_sum_u64(left, right)
        branch, target, _ = m.decode_branch(self.image, 0x16fc072, 0x16fbea0, 0x16fc517)
        self.assertEqual((branch, target), ('jb', 0x16fc1ff))

    def test_response_boundary_markers(self):
        rows = m.response_markers(self.image)
        self.assertEqual(rows, [('forward_error_equal', '0x174a99a', '0x8000000000000000'),
                                ('decode_error_equal', '0x174ab69', '0x8000000000000001'),
                                ('decoded_copy_equal', '0x174ade1', '0x8000000000000000'),
                                ('decoded_copy_output_tag', '0x174ae0a', '3')])
        with self.assertRaises(m.EvidenceError):
            m.response_markers(ModifiedImage(self.image, 0x174ae12))
        with self.assertRaises(m.EvidenceError):
            m.response_markers(ModifiedImage(self.image, 0x1748101))

    def test_request_immediate_stores_and_corruption(self):
        values = dict(m.instruction_stores(self.image))
        self.assertEqual(values, {'jsonrpc_key': b'jsonrpc', 'jsonrpc_value': b'2.0',
                                  'method_key': b'method', 'params_key': b'params', 'id_key': b'id'})
        with self.assertRaises(m.EvidenceError):
            m.instruction_stores(ModifiedImage(self.image, 0x17484cd))

    def test_full_generation(self):
        with tempfile.TemporaryDirectory() as temp:
            result = m.generate(self.data, Path(temp))
            self.assertEqual(result['target_sha256'], m.TARGET_SHA256)
            self.assertEqual(result['hex_character_cases'], 256)
            self.assertEqual(result['vector_classifier_lane_cases'], 4096)
            self.assertEqual(result['valid_vector_arithmetic_pairs'], 484)
            with (Path(temp) / 'outcomes.tsv').open(encoding='utf-8', newline='') as f:
                rows = {r['path']: r for r in csv.DictReader(f, delimiter='\t')}
            self.assertEqual(rows['missing_positional_input']['signed_code'], '-32602')
            self.assertEqual(rows['missing_positional_input']['detail'], 'No more params')
            self.assertEqual(rows['response_decode_error']['signed_code'], '-32000')
            self.assertEqual(rows['response_decode_error']['literal_or_format'], 'Invalid transaction response.')
            with (Path(temp) / 'request-helper-calls.tsv').open(encoding='utf-8', newline='') as f:
                request_calls = list(csv.DictReader(f, delimiter='\t'))
            self.assertEqual([r['field'] for r in request_calls], ['jsonrpc', 'method', 'params', 'id'])
            self.assertEqual({r['target_va'] for r in request_calls}, {'0x172d810'})
            with (Path(temp) / 'chain-selectors.tsv').open(encoding='utf-8', newline='') as f:
                selectors = list(csv.DictReader(f, delimiter='\t'))
            self.assertEqual(len(selectors), 256)
            self.assertEqual(selectors[2]['selected_case'], 'testnet_endpoint')
            self.assertEqual(selectors[3]['selected_case'], 'mainnet_endpoint')


if __name__ == '__main__':
    unittest.main()
