"""Target-grounded controls for the selected multisignature snapshot path."""
from contextlib import contextmanager
import mmap
import struct
import unittest

from tools import multisig_snapshot94 as m


class MiniMessagePack:
    """Independent, deliberately small parser for the published model fixtures."""
    def __init__(self, data):
        self.data, self.pos = data, 0

    def take(self, count):
        if count < 0 or self.pos + count > len(self.data):
            raise ValueError('truncated modeled fixture')
        start = self.pos
        self.pos += count
        return self.data[start:self.pos]

    def value(self):
        marker = self.take(1)[0]
        if marker < 0x80:
            return marker
        if 0x80 <= marker <= 0x8f:
            result = {}
            for _ in range(marker & 15):
                key, val = self.value(), self.value()
                if key in result:
                    raise ValueError('duplicate modeled map field')
                result[key] = val
            return result
        if 0x90 <= marker <= 0x9f:
            return [self.value() for _ in range(marker & 15)]
        if 0xa0 <= marker <= 0xbf:
            return self.take(marker & 31)
        if marker == 0xd9:
            return self.take(self.take(1)[0])
        widths = {0xcc: 1, 0xcd: 2, 0xce: 4, 0xcf: 8}
        if marker in widths:
            return int.from_bytes(self.take(widths[marker]), 'big')
        raise ValueError('unsupported modeled marker')

    def complete(self):
        value = self.value()
        if self.pos != len(self.data):
            raise ValueError('trailing modeled fixture bytes')
        return value


class MultisigSnapshot94Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # ACCESS_COPY mutates private memory pages only; the target remains read-only.
        cls.file = m.TARGET.open('rb')
        cls.data = mmap.mmap(cls.file.fileno(), 0, access=mmap.ACCESS_COPY)
        m.check_hash(cls.data)
        cls.secs, cls.header = m.unwind_index(cls.data)
        cls.records, cls.fixtures = m.analyze(cls.data)
        cls.compact = m.field_classifier(cls.data, cls.secs, 0x26bfe00)
        cls.json_classifier = m.field_classifier(cls.data, cls.secs, 0x26bfea0)
        cls.fields, _ = m.collect_fields(cls.data, cls.secs)
        cls.params = m.marker_parameters(cls.data, cls.secs)
        cls.tracker, _, _ = m.tracker_name(cls.data, cls.secs)

    @classmethod
    def tearDownClass(cls):
        cls.data.close()
        cls.file.close()

    @contextmanager
    def altered(self, va, replacement):
        pos = m.va_offset(self.secs, va, len(replacement))
        original = self.data[pos:pos + len(replacement)]
        self.data[pos:pos + len(replacement)] = replacement
        try:
            yield
        finally:
            self.data[pos:pos + len(replacement)] = original

    def test_target_and_selected_unwind_bodies(self):
        self.assertEqual(m.check_hash(self.data), m.SHA256)
        self.assertEqual(len(self.records['functions']), 30)
        self.assertEqual(len({row['start_va'] for row in self.records['functions']}), 30)
        for row in self.records['functions']:
            self.assertGreater(row['byte_count'], 0)
            self.assertEqual(int(row['end_va_exclusive'], 16) - int(row['start_va'], 16), row['byte_count'])
        selected = {row['role']: row for row in self.records['functions']}
        self.assertEqual(selected['tracker_compact_reader']['start_va'], '0x1716c90')
        self.assertEqual(selected['signer_field_compact_classifier']['end_va_exclusive'], '0x26bfe95')

    def test_wrong_digest_is_rejected(self):
        original = self.data[0]
        try:
            self.data[0] = original ^ 1
            with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
                m.check_hash(self.data)
        finally:
            self.data[0] = original

    def test_selected_body_corruption_fails_below_digest_gate(self):
        site = 0x26ce281
        off = m.va_offset(self.secs, site, 1, True)
        with self.altered(site, bytes([self.data[off] ^ 1])):
            with self.assertRaisesRegex(ValueError, 'body mismatch'):
                m.analyze(self.data, authenticate=False)

    def test_fde_extent_corruption_is_rejected(self):
        # The chosen FDE starts with length, CIE displacement, PC start, PC range.
        record = next(row for row in self.records['functions'] if row['role'] == 'tracker_compact_writer')
        range_va = int(record['fde_va'], 16) + 12
        raw = m.va_bytes(self.data, self.secs, range_va, 4)
        changed = struct.pack('<I', struct.unpack('<I', raw)[0] + 1)
        with self.altered(range_va, changed):
            with self.assertRaisesRegex(ValueError, 'FDE mismatch'):
                m.analyze(self.data, authenticate=False)

    def test_unmapped_nobits_and_cross_section_ranges_fail(self):
        bss = next(s for s in self.secs if s['name'] == '.bss')
        text = next(s for s in self.secs if s['name'] == '.text')
        with self.assertRaises(ValueError):
            m.va_offset(self.secs, bss['address'], 1)
        with self.assertRaises(ValueError):
            m.va_offset(self.secs, text['address'] + text['size'] - 1, 2, True)
        for va, size in ((0, 1), (-1, 1), ((1 << 64) - 1, 2), (text['address'], -1)):
            with self.subTest(va=va, size=size), self.assertRaises(ValueError):
                m.va_offset(self.secs, va, size, True)

    def test_call_and_branch_opcode_controls(self):
        target, raw = m.direct_call(self.data, self.secs, 0x26ce2a4)
        self.assertEqual(target, 0x25dfa30)
        with self.altered(0x26ce2a4, b'\x90'):
            with self.assertRaisesRegex(ValueError, 'opcode'):
                m.direct_call(self.data, self.secs, 0x26ce2a4)
        target, branch, _ = m.conditional_branch(self.data, self.secs, 0x1717742)
        self.assertEqual(target, 0x1717e6d)
        with self.altered(0x1717742, b'\x90\x90'):
            with self.assertRaisesRegex(ValueError, 'conditional branch'):
                m.conditional_branch(self.data, self.secs, 0x1717742)
        # A valid opcode with a corrupted displacement must also change the target.
        changed = branch[:-1] + bytes([branch[-1] ^ 1])
        with self.altered(0x1717742, changed):
            new_target, _, _ = m.conditional_branch(self.data, self.secs, 0x1717742)
            self.assertNotEqual(new_target, target)
            with self.assertRaisesRegex(ValueError, 'body mismatch'):
                m.analyze(self.data, authenticate=False)
        self.assertEqual(len(raw), 5)

    def test_rip_and_relocation_controls(self):
        target, _ = m.rip_ref(self.data, self.secs, 0x1e0d198, 'ff15')
        self.assertEqual(target, 0x5773120)
        with self.altered(0x1e0d198, b'\x90'):
            with self.assertRaisesRegex(ValueError, 'opcode'):
                m.rip_ref(self.data, self.secs, 0x1e0d198, 'ff15')
        rela = next(s for s in self.secs if s['name'] == '.rela.dyn')
        pos = next(i for i in range(rela['offset'], rela['offset'] + rela['size'], 24)
                   if struct.unpack_from('<Q', self.data, i)[0] == 0x5773120)
        original = self.data[pos + 8:pos + 16]
        try:
            self.data[pos + 8:pos + 16] = struct.pack('<Q', 0x108)
            with self.assertRaisesRegex(ValueError, 'relative relocation'):
                m.relocation(self.data, self.secs, 0x5773120)
        finally:
            self.data[pos + 8:pos + 16] = original

    def test_classifier_jump_table_and_literal_corruption(self):
        self.assertEqual(self.compact['first_length'], 2)
        self.assertEqual(len(self.compact['table_targets']), 15)
        table = self.compact['table']
        current = m.va_bytes(self.data, self.secs, table, 4)
        with self.altered(table, struct.pack('<i', struct.unpack('<i', current)[0] + 1)):
            with self.assertRaisesRegex(ValueError, 'table target'):
                m.field_classifier(self.data, self.secs, 0x26bfe00)
        addr = self.compact['snake_va']
        current = m.va_bytes(self.data, self.secs, addr, 1)
        with self.altered(addr, bytes([current[0] ^ 1])):
            with self.assertRaisesRegex(ValueError, 'spellings'):
                m.field_classifier(self.data, self.secs, 0x26bfe00)
        with self.altered(0x26bfe26, b'\x90'):
            with self.assertRaisesRegex(ValueError, 'pattern'):
                m.field_classifier(self.data, self.secs, 0x26bfe00)
        with self.altered(0x26bfe06, b'\xfd'):
            with self.assertRaisesRegex(ValueError, 'pattern'):
                m.field_classifier(self.data, self.secs, 0x26bfe00)

    def test_signer_aliases_and_all_single_byte_mutations(self):
        accepted = ((b'au', 0), (b'authorizedUsers', 0), (b'authorized_users', 0), (b'threshold', 1))
        checked = 0
        for classifier in (self.compact, self.json_classifier):
            for value, tag in accepted:
                self.assertEqual(m.classify_signer(classifier, value), tag)
                for i, original in enumerate(value):
                    for replacement in range(256):
                        if replacement == original:
                            continue
                        changed = value[:i] + bytes([replacement]) + value[i + 1:]
                        self.assertEqual(m.classify_signer(classifier, changed), 2)
                        checked += 1
        self.assertEqual(checked, 21420)
        for value in (b'', b'a', b'authorizedusers', b'Threshold', b'thresholds', b'authorize'):
            self.assertEqual(m.classify_signer(self.compact, value), 2)

    def test_tracker_name_overlapping_chunks_all_mutations(self):
        self.assertEqual(self.tracker, b'user_to_multi_sig_signers')
        self.assertEqual(m.classify_tracker(self.tracker, self.tracker), 0)
        checked = 0
        for i, original in enumerate(self.tracker):
            for replacement in range(256):
                if replacement == original:
                    continue
                changed = self.tracker[:i] + bytes([replacement]) + self.tracker[i + 1:]
                self.assertEqual(m.classify_tracker(changed, self.tracker), 1)
                checked += 1
        self.assertEqual(checked, 6375)
        for value in (b'', self.tracker[:-1], self.tracker + b'x'):
            self.assertEqual(m.classify_tracker(value, self.tracker), 1)

    def test_field_presence_and_alias_duplicate_controls(self):
        canonical = (b'authorizedUsers', b'threshold')
        cases = (
            ([], 'missing authorizedUsers'),
            ([b'threshold'], 'missing authorizedUsers'),
            ([b'au'], 'missing threshold'),
            ([b'unknown', b'authorized_users', b'threshold'], 'fields present'),
            ([b'au', b'authorizedUsers', b'threshold'], 'duplicate authorizedUsers'),
            ([b'authorized_users', b'au', b'threshold'], 'duplicate authorizedUsers'),
            ([b'authorizedUsers', b'threshold', b'threshold'], 'duplicate threshold'),
        )
        for names, expected in cases:
            with self.subTest(names=names):
                self.assertEqual(m.assess_map(names, self.compact, canonical), expected)
        self.assertEqual(self.records['duplicate_diagnostics'], ['duplicate key'] * 3)

    def test_field_error_names_and_template_corruption(self):
        records = m.collect_field_diagnostics(self.data, self.secs, self.fields)
        self.assertEqual(len(records), 9)
        self.assertEqual(records[0]['field'], 'user_to_multi_sig_signers')
        self.assertEqual(records[0]['template_prefix'], 'missing field `')
        self.assertEqual(records[-1]['field'], 'threshold')
        self.assertEqual(records[-1]['template_prefix'], 'duplicate field `')
        name_va = int(records[0]['field_va'], 16)
        template_va = int(records[0]['template_va'], 16)
        for address, expected in ((name_va, 'diagnostic field'), (template_va, 'diagnostic template')):
            original = m.va_bytes(self.data, self.secs, address, 1)
            with self.subTest(address=address), self.altered(address, bytes([original[0] ^ 1])):
                with self.assertRaisesRegex(ValueError, expected):
                    m.collect_field_diagnostics(self.data, self.secs, self.fields)

    def test_native_map_key_label_corruption(self):
        record = m.native_map_key_label(self.data, self.secs)
        self.assertEqual((record['label'], record['length']), ('User', 4))
        address = int(record['value_va'], 16)
        original = m.va_bytes(self.data, self.secs, address, 1)
        with self.altered(address, bytes([original[0] ^ 1])):
            with self.assertRaisesRegex(ValueError, 'key label mismatch'):
                m.native_map_key_label(self.data, self.secs)

    def test_duplicate_key_comparison_and_dynamic_symbol(self):
        symbol = m.imported_symbol(self.data, self.secs, 0x576e488)
        self.assertEqual(symbol['symbol_name'], 'memcmp')
        self.assertEqual(symbol['relocation_type'], 6)
        self.assertEqual(self.records['key_comparison']['width'], 20)
        self.assertEqual(self.records['key_comparison']['equal_result_tag'], 1)
        target, _, _ = m.conditional_branch(self.data, self.secs, 0x286062f)
        self.assertEqual(target, 0x2860662)
        # A changed comparator slot is rejected even when its bytes remain valid ELF.
        rela = next(s for s in self.secs if s['name'] == '.rela.dyn')
        pos = next(i for i in range(rela['offset'], rela['offset'] + rela['size'], 24)
                   if struct.unpack_from('<Q', self.data, i)[0] == 0x576e488)
        original = self.data[pos + 8:pos + 16]
        try:
            self.data[pos + 8:pos + 16] = struct.pack('<Q', 6)
            with self.assertRaisesRegex(ValueError, 'dynamic relocation'):
                m.imported_symbol(self.data, self.secs, 0x576e488)
        finally:
            self.data[pos + 8:pos + 16] = original

    def test_unsigned_writer_boundaries_and_domain(self):
        expected = {
            0: '00', 127: '7f', 128: 'cc80', 255: 'ccff', 256: 'cd0100',
            65535: 'cdffff', 65536: 'ce00010000', 0xffffffff: 'ceffffffff',
            0x100000000: 'cf0000000100000000', 0xffffffffffffffff: 'cfffffffffffffffff',
        }
        for value, result in expected.items():
            with self.subTest(value=value):
                self.assertEqual(m.encode_uint(value, self.params).hex(), result)
        for invalid in (-1, 1 << 64, True, 1.0):
            with self.subTest(value=invalid), self.assertRaises(ValueError):
                m.encode_uint(invalid, self.params)

    def test_empty_and_single_row_model_fixtures(self):
        empty_named = bytes.fromhex('81b9757365725f746f5f6d756c74695f7369675f7369676e65727390')
        self.assertEqual(bytes.fromhex(self.fixtures['messagepack_hex']['empty_named']), empty_named)
        self.assertEqual(bytes.fromhex(self.fixtures['messagepack_hex']['empty_positional']), b'\x91\x90')
        one = bytes.fromhex(self.fixtures['messagepack_hex']['one_named'])
        key = b'0x000102030405060708090a0b0c0d0e0f10111213'
        member = b'0x1415161718191a1b1c1d1e1f2021222324252627'
        expected = {b'user_to_multi_sig_signers': [[key, {b'authorizedUsers': [member], b'threshold': 1}]]}
        self.assertEqual(MiniMessagePack(one).complete(), expected)
        positional = bytes.fromhex(self.fixtures['messagepack_hex']['one_positional'])
        self.assertEqual(MiniMessagePack(positional).complete(), [[[key, [[member], 1]]]])
        for bad in (one[:-1], b'\xc1' + one[1:], one + b'\x00'):
            with self.subTest(bad=bad[:3]), self.assertRaises(ValueError):
                MiniMessagePack(bad).complete()
        for rows in ([(bytes(19), [], 1)], [(bytes(20), [bytes(21)], 1)]):
            with self.assertRaises(ValueError):
                m.snapshot_example(True, rows, self.fields, self.params)

    def test_actual_chain_and_mode_branch_records(self):
        edges = {(x['site_va'], x['target_va']) for x in self.records['calls']}
        for edge in (('0x27b3b58', '0x25aa7f0'), ('0x27b3b6c', '0x25dfa30'),
                     ('0x26ce2a4', '0x25dfa30'), ('0x25dfaa8', '0x1e1eb10'),
                     ('0x1e1ecfe', '0x1dde0d0'), ('0x1dde265', '0x26cdbc0'),
                     ('0x1717750', '0x1901890'), ('0x1901daa', '0x266f210'),
                     ('0x263c17a', '0x1699080'), ('0x170fa1c', '0x190f5b0'),
                     ('0x266f27e', '0x170f470'), ('0x170fb7e', '0x18325a0'),
                     ('0x1832cd1', '0x17932f0'), ('0x1833c39', '0x1684530'),
                     ('0x1833a9c', '0x26bfe00'), ('0x1c0f44e', '0x26bfea0'),
                     ('0x1c0f5b0', '0x1be3a70'), ('0x1c0f643', '0x1b2fae0')):
            self.assertIn(edge, edges)
        self.assertEqual(self.fields['exchange_field'], b'multi_sig_tracker')
        self.assertEqual(self.fields['tracker_field_exchange'], self.fields['tracker_field'])
        self.assertEqual(self.params['tracker_arity'], 1)
        self.assertEqual(self.params['row_arity'], 2)
        self.assertEqual(self.params['signer_arity'], 2)
        self.assertEqual(self.params['key_width'], 20)
        self.assertEqual(self.fixtures['sequence_counts_after_successful_children']['signers'], [
            {'count': 0, 'outcome': 'missing first'}, {'count': 1, 'outcome': 'missing second'},
            {'count': 2, 'outcome': 'join'}, {'count': 3, 'outcome': 'extra element'}])


if __name__ == '__main__':
    unittest.main()
