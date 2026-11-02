"""Target-grounded and corruption controls for the selected static flow."""
import hashlib
from pathlib import Path
import unittest

from tools import re015_static_config_115 as flow


class StaticConfigEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = flow.BINARY.read_bytes()
        cls.secs = flow.sections(cls.data)
        cls.relocs = flow.relative_relocations(cls.data, cls.secs)
        cls.files, cls.summary = flow.collect(cls.data)
        cls.names, cls.marker_va, cls.marker = flow.name_rows(cls.data, cls.secs, cls.relocs)
        cls.rules = {kind: flow.nv_rule(cls.data, cls.secs, kind)
                     for kind in ('plain9', 'plain10', 'serde9')}

    def test_authenticated_target_and_wrong_digest(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), flow.TARGET_SHA256)
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            flow.authenticate(self.data, '0' * 64)
        changed = bytearray(self.data)
        changed[-1] ^= 1
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            flow.authenticate(changed)

    def test_historical_comparison_rejects_wrong_release(self):
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            flow.compare_94(self.data, self.names)

    def test_file_backed_span_excludes_bss_and_crossing(self):
        bss = next(s for s in self.secs if s['name'] == '.bss')
        self.assertEqual(bss['type'], 8)
        with self.assertRaisesRegex(ValueError, 'file-backed'):
            flow.span(self.data, self.secs, bss['address'], 1)
        text = next(s for s in self.secs if s['name'] == '.text')
        with self.assertRaisesRegex(ValueError, 'file-backed'):
            flow.span(self.data, self.secs, text['address'] + text['size'] - 1, 2)
        for addr, size in ((0, 0), (-1, 1), (0, -1)):
            with self.subTest(addr=addr, size=size), self.assertRaises(ValueError):
                flow.span(self.data, self.secs, addr, size)
        ambiguous = [dict(type=1,size=2,address=1,offset=0,name='a'),
                     dict(type=1,size=2,address=1,offset=0,name='b')]
        with self.assertRaisesRegex(ValueError, 'uniquely'):
            flow.span(b'ab', ambiguous, 1, 1)

    def test_full_template_entry_and_negative_controls(self):
        for label, target, site, literal in flow.LITERALS:
            with self.subTest(label=label):
                _, raw, _ = flow.span(self.data, self.secs, target, len(literal) + 3)
                _, lea, _ = flow.span(self.data, self.secs, site, 7)
                self.assertEqual(flow.parse_template(raw), literal)
                self.assertEqual(flow.decode_lea(site, lea), target)
                self.assertNotEqual(flow.decode_lea(site, lea), target + 2)
                for bad in (raw[1:], raw[:-1], raw[:-1] + b'\x01',
                            raw[:1] + bytes([raw[1] + 1]) + raw[2:]):
                    with self.assertRaises(ValueError):
                        flow.parse_template(bad)
        with self.assertRaises(ValueError):
            flow.decode_lea(0, bytes.fromhex('488b3500000000'))

    def test_dynamic_relocation_binding_and_absent_relocation(self):
        slots = {0x64e23e8:0x17782e0, 0x64e23f0:0x17780c0,
                 0x64e2418:0x17783e0, 0x64e23f8:0x1773fd0,
                 0x64e2400:0x1775500}
        for slot,target in slots.items():
            self.assertEqual(self.relocs[slot][0], target)
        with self.assertRaisesRegex(ValueError, 'relocation'):
            flow.pair(self.data, self.secs, {}, 0x6410ce8)
        missing = dict(self.relocs)
        missing.pop(0x64f06c0)
        with self.assertRaisesRegex(ValueError, 'publication relocation'):
            flow.globals_and_stores(self.data, self.secs, missing)
        wrong = dict(self.relocs)
        wrong[0x64f06c0] = (0x17785f1, wrong[0x64f06c0][1])
        with self.assertRaisesRegex(ValueError, 'publication relocation'):
            flow.globals_and_stores(self.data, self.secs, wrong)

    def test_transfer_and_conditional_branch_decoding(self):
        site = 0x17784ae
        _, raw, _ = flow.span(self.data, self.secs, site, 5)
        self.assertEqual(flow.decode_transfer(site, raw), ('direct_call', 0x1775dd0))
        site = 0x1778698
        _, raw, _ = flow.span(self.data, self.secs, site, 6)
        kind, slot = flow.decode_transfer(site, raw)
        self.assertEqual((kind, slot, self.relocs[slot][0]), ('indirect_call', 0x64e2418, 0x17783e0))
        branch_site = 0x1778655
        _, raw, _ = flow.span(self.data, self.secs, branch_site, 6)
        self.assertEqual(flow.decode_branch(branch_site, raw)[:3], ('jne', 0x177865b, 0x17786f0))
        corrupted = bytearray(raw)
        corrupted[-1] ^= 1
        self.assertNotEqual(flow.decode_branch(branch_site, corrupted)[2], 0x17786f0)
        with self.assertRaises(ValueError):
            flow.decode_transfer(site, b'\xff\x14\x00\x00\x00\x00')
        with self.assertRaises(ValueError):
            flow.decode_branch(branch_site, b'\x90' * 6)

    def test_name_table_comes_from_two_arrays_and_executable_arms(self):
        self.assertEqual(self.marker, 'variant index 0 <= i < 79')
        self.assertEqual(self.marker_va, 0x464893)
        self.assertEqual(len(self.names), 79)
        self.assertEqual([self.names[i][10] for i in (12,13,14,32,33,34,36,37,38,39,40,78)],
                         ['EaMm','EaTx','HeavyTestnet','SoloSandbox','NvTestnet',
                          'NvTestnet2','NvMainnet2','NvMainnet3','JoinMainnet',
                          'DummyNv','FBinSpot','EbHlPerp'])
        for row in self.names:
            self.assertEqual(row[18], '0x167fa70')
            self.assertEqual(row[9], len(row[10]))
        self.assertEqual(len({row[10] for row in self.names}), len(self.names))

    def test_formatter_arm_rejects_corruption(self):
        site = int(self.names[33][4], 16)
        _, raw, _ = flow.span(self.data, self.secs, site, 21)
        self.assertEqual(flow.arm_data(site, raw), (0x481e30, 9, 0x64df720))
        for pos in (0, 7, 12, 15):
            changed = bytearray(raw)
            changed[pos] ^= 1
            with self.subTest(byte=pos), self.assertRaises(ValueError):
                flow.arm_data(site, changed)
        with self.assertRaises(ValueError):
            flow.arm_data(site, raw[1:])

    def test_selected_table_references_resolve_from_instruction_bytes(self):
        for site,target in ((0x1773177,0x481928),(0x1774111,0x481ba0),
                            (0x1774947,0x6410ce8),(0x1774e66,0x481bd0),
                            (0x1775510,0x481d0c)):
            _,raw,_=flow.span(self.data,self.secs,site,7)
            with self.subTest(site=site):
                self.assertEqual(flow.decode_rip_lea(site,raw),target)
                changed=bytearray(raw)
                changed[3] ^= 1
                self.assertNotEqual(flow.decode_rip_lea(site,changed),target)
        with self.assertRaises(ValueError):
            flow.decode_rip_lea(0,bytes.fromhex('488b0500000000'))

    def test_classifier_and_formatter_agree_at_nv_boundaries(self):
        for kind, text, index in (('plain9',b'NvTestnet',33),
                                  ('plain10',b'NvTestnet2',34),
                                  ('serde9',b'NvTestnet',33)):
            rule = self.rules[kind]
            with self.subTest(kind=kind):
                self.assertEqual(rule['bytes'], text)
                self.assertEqual(rule['value'], index)
                self.assertTrue(flow.rule_match(rule, text))
                self.assertEqual(self.names[index][10].encode(), text)
                self.assertFalse(flow.rule_match(rule, text[:-1]))
                self.assertFalse(flow.rule_match(rule, text+b'2'))
                for i in range(len(text)):
                    altered = bytearray(text)
                    altered[i] ^= 1
                    self.assertFalse(flow.rule_match(rule, altered), (kind, i))
                for byte in range(256):
                    changed = text[:-1] + bytes([byte])
                    self.assertEqual(flow.rule_match(rule, changed), byte == text[-1])
        # A failed nine-byte predicate is not necessarily a global name error.
        self.assertFalse(flow.rule_match(self.rules['plain9'], b'NvTestnet2'))
        self.assertTrue(flow.rule_match(self.rules['plain10'], b'NvTestnet2'))

    def test_quoted_value_dispatch_preserves_each_selected_index(self):
        rows = flow.value_dispatch_rows(self.data,self.secs,self.names)
        self.assertEqual(len(rows),79)
        self.assertEqual((rows[33][1],rows[33][5],rows[33][8],rows[33][9]),
                         ('NvTestnet','0x1773284',33,'0x1773f2d'))
        self.assertEqual([row[8] for row in rows],list(range(79)))
        changed = bytearray(self.data)
        leaf_offset = int(rows[33][6],16)
        changed[leaf_offset+3] ^= 1
        with self.assertRaisesRegex(ValueError, 'dispatch output'):
            flow.value_dispatch_rows(changed,self.secs,self.names)
        with self.assertRaisesRegex(ValueError, 'dispatch leaf'):
            flow.value_dispatch_leaf(0,b'\x90'*9)

    def test_mutated_classifier_immediate_changes_predicate(self):
        changed = bytearray(self.data)
        offset = self.rules['plain9']['file_offset']
        changed[offset + 2] ^= 1
        corrupted = flow.nv_rule(changed, self.secs, 'plain9')
        self.assertNotEqual(corrupted['bytes'], self.rules['plain9']['bytes'])
        self.assertFalse(flow.rule_match(corrupted, b'NvTestnet'))
        self.assertTrue(flow.rule_match(corrupted, corrupted['bytes']))
        self.assertNotEqual(self.names[corrupted['value']][10].encode(), corrupted['bytes'])
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            flow.collect(changed)

    def test_mutated_equality_branch_cannot_select_the_same_leaf(self):
        changed = bytearray(self.data)
        offset, _, _ = flow.span(self.data, self.secs, self.rules['plain9']['branch_site'], 6)
        changed[offset + 2] ^= 1
        with self.assertRaises(ValueError):
            flow.nv_rule(changed, self.secs, 'plain9')

    def test_fallback_marker_and_context_corruption(self):
        fallback, sentinel, checks = flow.check_contexts(self.data, self.secs, len(self.names))
        self.assertEqual((fallback, sentinel), (33, 79))
        self.assertGreaterEqual(checks, 30)
        self.assertEqual(self.names[fallback][10], 'NvTestnet')
        changed = bytearray(self.data)
        offset, _, _ = flow.span(self.data, self.secs, 0x177735f, 10)
        changed[offset + 2] ^= 1
        with self.assertRaisesRegex(ValueError, 'context'):
            flow.check_contexts(changed, self.secs, len(self.names))
        with self.assertRaisesRegex(ValueError, 'sentinel'):
            flow.check_contexts(self.data, self.secs, len(self.names)-1)

    def test_publication_stores_cover_object_and_reject_shift(self):
        globals_, stores = flow.globals_and_stores(self.data, self.secs, self.relocs)
        self.assertEqual(globals_[0][-1], '0x64f06c0')
        self.assertEqual(globals_[1][-1], '0x17785f0')
        self.assertEqual(globals_[-1][-1], '3')
        for name in ('publication_callback_a', 'publication_callback_b'):
            self.assertEqual(sorted((r[4],r[5]) for r in stores if r[0] == name),
                             [(0,16),(16,16),(32,16),(48,16),(64,16)])
        with self.assertRaises(ValueError):
            flow.copy_store(b'\x90\x11\x03')
        changed = bytearray(self.data)
        offset, _, _ = flow.span(self.data, self.secs, 0x5944f87, 4)
        changed[offset + 3] ^= 1
        with self.assertRaisesRegex(ValueError, '80-byte'):
            flow.globals_and_stores(changed, self.secs, self.relocs)

    def test_import_symbols_and_corrupted_symbol_index(self):
        imports = flow.imported_relocations(self.data, self.secs, [row[2] for row in flow.IMPORT_SITES])
        expected = {0x64ec8c8:'open64', 0x64e2310:'read', 0x64eafe8:'fstat64',
                    0x64dfe78:'close', 0x64dffc8:'__errno_location',
                    0x64ec6c8:'getenv', 0x64ebff0:'sysconf',
                    0x64ec918:'getuid', 0x64ec920:'getpwuid_r'}
        self.assertEqual({slot:value[0] for slot,value in imports.items()}, expected)
        changed = bytearray(self.data)
        relocation_offset = imports[0x64e2310][2]
        changed[relocation_offset+12:relocation_offset+16] = b'\xff'*4
        with self.assertRaisesRegex(ValueError, 'symbol index'):
            flow.imported_relocations(changed, self.secs, [0x64e2310])
        with self.assertRaisesRegex(ValueError, 'missing'):
            flow.imported_relocations(self.data, self.secs, [0x64f06c0 + 8])

    def test_failure_diagnostics_and_corrupt_reference(self):
        rows = flow.diagnostic_rows(self.data, self.secs)
        self.assertEqual([r[0] for r in rows], ['duplicate_field','aws_name_key',
                                                'unwrap_error','not_directory','create_error'])
        self.assertEqual(bytes.fromhex(rows[1][5]), b'aws_name')
        changed = bytearray(self.data)
        offset, _, _ = flow.span(self.data, self.secs, 0x1777e95, 7)
        changed[offset+3] ^= 1
        with self.assertRaisesRegex(ValueError, 'reference target'):
            flow.diagnostic_rows(changed, self.secs)

    def test_directory_model_uses_tag_mode_and_creation_result(self):
        constants = flow.directory_constants(self.data, self.secs)
        self.assertEqual(constants, {'error_tag':2,'mask':0xf000,'directory':0x4000})
        cases = [
            ((0,0x41ff,2,0,1),'first'),
            ((2,0x4000,0,0x4000,1),'second'),
            ((2,0x4000,2,0x4000,0),'second_created'),
            ((2,0,2,0,1),'creation_error'),
            ((0,0x8000,0,0x41ed,1),'second'),
            ((3,0x4000,2,0,1),'first'),
        ]
        for args,expected in cases:
            with self.subTest(args=args):
                self.assertEqual(flow.directory_model(constants,*args),expected)
        changed = bytearray(self.data)
        offset, _, _ = flow.span(self.data, self.secs, 0x177813b, 14)
        changed[offset+2] ^= 1
        with self.assertRaisesRegex(ValueError, 'predicate'):
            flow.directory_constants(changed, self.secs)

    def test_reader_models_separate_returned_errors_from_unwraps(self):
        fallback, marker, _ = flow.check_contexts(self.data,self.secs,len(self.names))
        self.assertEqual(flow.static_result_model(fallback,True,0,0),33)
        self.assertEqual(flow.static_result_model(fallback,False,1,0),33)
        self.assertEqual(flow.static_result_model(fallback,False,0,32),32)
        self.assertEqual(flow.static_result_model(fallback,False,0,78),78)
        self.assertEqual(flow.static_result_model(fallback,False,0,marker),79)
        self.assertEqual(flow.missing_name_model(marker,True,0),'read_error_unwrap')
        self.assertEqual(flow.missing_name_model(marker,False,marker),'unknown_name_unwrap')
        self.assertEqual(flow.missing_name_model(marker,False,33),'normal_return')
        with self.assertRaisesRegex(ValueError, 'byte'):
            flow.static_result_model(fallback,False,0,256)
        with self.assertRaisesRegex(ValueError, 'byte'):
            flow.missing_name_model(marker,False,-1)

    def test_generated_evidence_is_reproducible(self):
        packet = flow.ROOT / 'research/work-items/RE-015-static-config-path-115'
        self.assertEqual(self.summary['function_count'], 23)
        self.assertEqual(self.summary['selected_transfer_count'], 52)
        self.assertEqual(self.summary['selected_branch_count'], 52)
        self.assertEqual(self.summary['selected_import_call_count'], 10)
        self.assertEqual(self.summary['comparison_probe_count'], 37)
        self.assertEqual(self.summary['directory_model_case_count'], 9)
        self.assertEqual(self.summary['reader_model_case_count'], 12)
        self.assertEqual(self.summary['value_dispatch_count'],79)
        self.assertEqual(self.summary['selected_table_reference_count'],5)
        self.assertEqual(len(self.files), 18)
        for name,contents in self.files.items():
            with self.subTest(name=name):
                self.assertEqual((packet / name).read_bytes(), contents)


if __name__ == '__main__':
    unittest.main()
