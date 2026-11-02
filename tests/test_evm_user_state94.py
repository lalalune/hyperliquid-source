from pathlib import Path
import sys
import struct
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import evm_user_state94 as m


class EvmUserStateEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = m.BINARY.read_bytes()
        cls.secs, cls.index = m.unwind_index(cls.data)
        _, cls.fdes = m.eh_frame_records(cls.data, cls.secs)
        cls.record = m.analyze(cls.data)

    def changed(self, va, replacement):
        data = bytearray(self.data)
        off = m.file_offset(self.secs, va, len(replacement))
        data[off:off + len(replacement)] = replacement
        return data

    def test_identity_and_extents(self):
        self.assertEqual(self.record['binary_sha256'], m.DIGEST)
        self.assertEqual(len(self.record['functions']), 16)
        by_start = {x['start']: x for x in self.record['functions']}
        self.assertEqual(by_start['0x3157280']['end_exclusive'], '0x3157bc1')
        self.assertEqual(by_start['0x1a51b00']['end_exclusive'], '0x1a53030')
        self.assertEqual(self.record['type_record']['name'], 'struct EvmUserState')
        self.assertEqual(self.record['type_record']['formatter'], '0x37609b0')
        with self.assertRaises(ValueError):
            m.admit(self.changed(0x275d847, b'\x00'))
        with self.assertRaises(ValueError):
            m.admit(b'not an ELF')

    def test_body_corruption_is_rejected_even_if_reparsed(self):
        data = self.changed(0x275d847, b'\x00')
        with self.assertRaisesRegex(ValueError, 'function body'):
            m.inspect_functions(data, self.secs, self.index, self.fdes)
        data = self.changed(0x3157560, b'\x90')
        with self.assertRaisesRegex(ValueError, 'window bytes'):
            m.inspect_windows(data, self.secs)

    def test_index_and_fde_disagreement(self):
        idx = [dict(x) for x in self.index]
        target = next(x for x in idx if x['start'] == 0x1a51b00)
        target['fde'] += 4
        with self.assertRaisesRegex(ValueError, 'unwind index'):
            m.inspect_functions(self.data, self.secs, idx, self.fdes)
        fdes = [dict(x) for x in self.fdes]
        target = next(x for x in fdes if x['start'] == 0x3157280)
        target['end'] -= 1
        with self.assertRaisesRegex(ValueError, 'unwind index'):
            m.inspect_functions(self.data, self.secs, self.index, fdes)

    def test_file_backed_bounds_and_ambiguity(self):
        bss = next(s for s in self.secs if s['name'] == '.bss' and s['type'] == 8 and s['size'])
        with self.assertRaises(ValueError):
            m.read_va(self.data, self.secs, bss['address'], 1)
        for address, size in ((-1, 1), (0, 0), (1 << 64, 1), (0, -1)):
            with self.subTest(address=address, size=size), self.assertRaises(ValueError):
                m.read_va(self.data, self.secs, address, size)
        text = next(s for s in self.secs if s['name'] == '.text')
        with self.assertRaises(ValueError):
            m.read_va(self.data, self.secs, text['address'] + text['size'] - 1, 2)
        with self.assertRaises(ValueError):
            m.file_offset(self.secs + [dict(text)], text['address'], 1)

    def test_four_names_and_object_offsets(self):
        fields = self.record['fields']
        self.assertEqual([f['name'] for f in fields], ['g', 't', 'b', 'T'])
        self.assertEqual([f['input_offset'] for f in fields], ['0x0', '0x8', '0x1c', '0x10'])
        with self.assertRaises(ValueError):
            m.field_names(self.changed(0x3ef1b4, b'G'), self.secs)
        with self.assertRaises(ValueError):
            m.field_names(self.changed(0x275dcf6, b'B'), self.secs)
        with self.assertRaises(ValueError):
            m.field_names(self.changed(0x275d84d, b'\x09'), self.secs)

    def test_both_key_tables_and_unknowns(self):
        for name in ('compact_key_table', 'json_key_table'):
            table = self.record[name]
            self.assertEqual(len(table), 33)
            self.assertEqual([x['input'] for x in table if x['recognized']], ['T', 'b', 'g', 't'])
            fallback = {x['target'] for x in table if not x['recognized']}
            self.assertEqual(len(fallback), 1)
            self.assertNotEqual(next(x['target'] for x in table if x['input'] == 'T'),
                                next(x['target'] for x in table if x['input'] == 't'))
        table_va = 0x57c60c
        bad = self.changed(table_va, b'\xff\xff\xff\x7f')
        with self.assertRaises(ValueError):
            m.read_table(bad, self.secs, table_va, (0x3157280, 0x3157bc1),
                         {'g': 0x3157560, 't': 0x3157628, 'b': 0x31575d2, 'T': 0x315746f})
        # A changed previously unrecognized key must not acquire a field arm.
        table_va = 0x3aaddc
        original = m.read_va(self.data, self.secs, table_va, 4)
        bad = self.changed(table_va + 4, original)
        with self.assertRaises(ValueError):
            m.read_table(bad, self.secs, table_va, (0x1a51b00, 0x1a53030),
                         {'g': 0x1a52b21, 't': 0x1a52bc2, 'b': 0x1a52c83, 'T': 0x1a52c40})

    def test_calls_and_corruption(self):
        calls = {x['site']: x['target'] for x in self.record['calls']}
        self.assertEqual(calls['0x265568d'], '0x1a51b00')
        self.assertEqual(calls['0x3619b94'], '0x3023060')
        self.assertEqual(calls['0x1dd2bd6'], '0x275db60')
        self.assertEqual(calls['0x1dd2cb0'], '0x275d830')
        self.assertEqual(calls['0x18b6dda'], '0x26a5e90')
        self.assertEqual(calls['0x275d91e'], calls['0x275d964'])
        with self.assertRaises(ValueError):
            m.inspect_calls(self.changed(0x265568d, b'\x90'), self.secs)
        original = m.read_va(self.data, self.secs, 0x265568e, 1)
        with self.assertRaises(ValueError):
            m.inspect_calls(self.changed(0x265568e, bytes([original[0] ^ 1])), self.secs)

    def test_fresh_byte_container_headers(self):
        rows = m.fixed_headers(self.data, self.secs)
        self.assertEqual(len(rows), 32)
        for marker, route, count in ((0x80, 'map', 0), (0x8f, 'map', 15),
                                     (0x90, 'row-array', 0), (0x9f, 'row-array', 15)):
            row = rows[marker - 0x80]
            self.assertEqual((row['byte'], row['route'], row['count']), (hex(marker), route, count))
        for site, changed in ((0x18b6c56, b'\x91'), (0x18b6d9a, b'\xa1'),
                              (0x18b6c96, b'\x90')):
            with self.subTest(site=site), self.assertRaises(ValueError):
                m.fixed_headers(self.changed(site, changed), self.secs)

    def test_duplicate_guards_and_transfer_corruption(self):
        b = {x['site']: x['target'] for x in self.record['branches']}
        diagnostics = self.record['duplicate_field_diagnostics']
        self.assertEqual(diagnostics['format_va'], '0x1e0fd5')
        self.assertEqual([x['name'] for x in diagnostics['fields']], ['g', 't', 'b', 'T'])
        for site, target in (('0x1a52b2a', '0x1a52f90'), ('0x1a52bcb', '0x1a52f75'),
                             ('0x1a52c87', '0x1a52f87'), ('0x1a52c48', '0x1a52f7e'),
                             ('0x3157566', '0x3157adf'), ('0x315762e', '0x3157ac4'),
                             ('0x31575d6', '0x3157acd'), ('0x3157474', '0x3157ad6')):
            self.assertEqual(b[site], target)
        with self.assertRaises(ValueError):
            m.inspect_branches(self.changed(0x3157566, b'\x90'), self.secs)
        byte = m.read_va(self.data, self.secs, 0x1a52b2c, 1)
        with self.assertRaises(ValueError):
            m.inspect_branches(self.changed(0x1a52b2c, bytes([byte[0] ^ 1])), self.secs)
        with self.assertRaises(ValueError):
            m.duplicate_fields(self.changed(0x3b0a9d, b'G'), self.secs)
        with self.assertRaises(ValueError):
            m.duplicate_fields(self.changed(0x1e0fd6, b'D'), self.secs)

    def test_duplicate_map_key_paths(self):
        key = self.record['key_evidence']
        self.assertEqual((key['key_type'], key['literal_length']), ('User', 4))
        self.assertEqual([x['length'] for x in key['comparisons']], [20, 20])
        self.assertEqual([x['slot'] for x in key['comparisons']], ['0x576e488', '0x576e488'])
        self.assertEqual(m.read_va(self.data, self.secs, 0x2655877, 8), b'duplicat')
        self.assertEqual(m.read_va(self.data, self.secs, 0x3619ca0, 8), b'duplicat')
        branches = {x['site']: x['target'] for x in self.record['branches']}
        self.assertEqual(branches['0x265584d'], '0x26555c0')
        self.assertEqual(branches['0x3619c76'], '0x3619b60')
        # The alternative branch after each insertion constructs the diagnostic.
        with self.assertRaises(ValueError):
            m.inspect_windows(self.changed(0x3619ca0, b'D'), self.secs)
        for site, replacement in ((0x20a020, b'u'), (0x28567a1, b'\x15'), (0x3396d88, b'\x90')):
            with self.subTest(site=site), self.assertRaises(ValueError):
                m.key_evidence(self.changed(site, replacement), self.secs)

    def test_relocation_identity_and_missing(self):
        r = self.record['relocations']
        self.assertEqual([(x['type'], x['symbol']) for x in r],
                         [(8, None), (6, 'memcmp'), (8, None), (8, None)])
        rel = next(s for s in self.secs if s['name'] == '.rela.dyn')
        pos = next(p for p in range(rel['offset'], rel['offset'] + rel['size'], 24)
                   if struct.unpack_from('<Q', self.data, p)[0] == 0x576e488)
        data = bytearray(self.data)
        struct.pack_into('<Q', data, pos, 0)
        with self.assertRaisesRegex(ValueError, 'missing or duplicate'):
            m.relocations(data, self.secs, (0x56de3c8, 0x576e488, 0x576e890, 0x5770e28))
        # A second entry for the same slot must not be silently overwritten.
        data = bytearray(self.data)
        other = next(p for p in range(rel['offset'], rel['offset'] + rel['size'], 24)
                     if struct.unpack_from('<Q', self.data, p)[0] not in (0x56de3c8, 0x576e488, 0x576e890, 0x5770e28))
        struct.pack_into('<Q', data, other, 0x576e488)
        with self.assertRaisesRegex(ValueError, 'missing or duplicate'):
            m.relocations(data, self.secs, (0x56de3c8, 0x576e488, 0x576e890, 0x5770e28))

    def test_positional_count_and_child_error_transfers(self):
        branches = {x['site']: x['target'] for x in self.record['branches']}
        for site, target in (('0x1a5219a', '0x1a521d0'), ('0x1a521bf', '0x1a5221c'),
                             ('0x1a5224a', '0x1a52250'), ('0x1a52277', '0x1a521e7'),
                             ('0x1a522bc', '0x1a521ff'), ('0x1a521b0', '0x1a52335'),
                             ('0x1a52230', '0x1a52335'), ('0x1a52269', '0x1a5233a')):
            self.assertEqual(branches[site], target)
        with self.assertRaises(ValueError):
            m.inspect_windows(self.changed(0x1a521bf, b'\x74'), self.secs)

    def test_writer_predicate_and_error_transfers(self):
        branches = {x['site']: x['target'] for x in self.record['branches']}
        for site, target in (('0x275d8ee', '0x275d931'), ('0x275d934', '0x275d977'),
                             ('0x275d979', '0x275d9d6'), ('0x275da01', '0x275da52'),
                             ('0x275d90f', '0x275da60'), ('0x275d92b', '0x275da5b')):
            self.assertEqual(branches[site], target)
        with self.assertRaises(ValueError):
            m.inspect_windows(self.changed(0x275d8ee, b'\x75'), self.secs)

    def test_unknown_fields_use_separate_children(self):
        calls = {x['site']: x['target'] for x in self.record['calls']}
        branches = {x['site']: x['target'] for x in self.record['branches']}
        self.assertEqual(calls['0x1a52c17'], '0x19682d0')
        self.assertEqual(calls['0x315753a'], '0x2fe3390')
        self.assertEqual(branches['0x1a52c21'], '0x1a52cad')
        self.assertEqual(branches['0x3157542'], '0x3157966')
        with self.assertRaises(ValueError):
            m.inspect_calls(self.changed(0x315753a, b'\x90'), self.secs)

    def test_artifacts_are_deterministic(self):
        first = m.render(self.data)
        second = m.render(self.data)
        self.assertEqual(first, second)
        self.assertEqual(sorted(first), ['evidence.json', 'fields.tsv', 'fixed-headers.tsv'])
        self.assertTrue(first['fields.tsv'].endswith(b'0x315746f\n'))


if __name__ == '__main__':
    unittest.main()
