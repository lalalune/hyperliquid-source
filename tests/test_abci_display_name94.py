"""Static corruption and boundary controls for the display-name evidence."""
import csv
import io
import json
import mmap
import struct
import unittest
from contextlib import contextmanager

from tools import abci_display_name94 as subject


class DisplayNameEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.handle = subject.TARGET.open('rb')
        cls.data = mmap.mmap(cls.handle.fileno(), 0, access=mmap.ACCESS_COPY)
        cls.addClassCleanup(cls.handle.close)
        cls.addClassCleanup(cls.data.close)
        cls.outputs = subject.produce(cls.data)
        cls.sec = subject.sections(cls.data)
        cls.summary = json.loads(cls.outputs['summary.json'])
        cls.data_record = json.loads(cls.outputs['data.json'])
        cls.function_rows = cls.rows('functions.tsv')
        # These selected records came from the real shared ELF/FDE parsers in
        # produce(). Reuse them to exercise the selector below the digest gate.
        cls.index = [{'start':int(x['start'],16), 'fde':int(x['fde'],16)}
                     for x in cls.function_rows]
        cls.fdes = [{'start':int(x['start'],16), 'end':int(x['end_exclusive'],16),
                     'fde':int(x['fde'],16), 'cie':int(x['cie'],16),
                     'lsda':int(x['lsda'],16) if x['lsda'] else None}
                    for x in cls.function_rows]

    @classmethod
    def rows(cls, name):
        return list(csv.DictReader(io.StringIO(cls.outputs[name].decode()),delimiter='\t'))

    @contextmanager
    def patch_offset(self, off, new):
        old = self.data[off:off+len(new)]
        try:
            self.data[off:off+len(new)] = new
            yield
        finally:
            self.data[off:off+len(new)] = old

    @contextmanager
    def flip_va(self, va):
        off = subject.file_offset(self.sec, va, 1)
        with self.patch_offset(off, bytes([self.data[off] ^ 1])):
            yield

    def test_authenticated_target(self):
        self.assertEqual(subject.verify_digest(self.data), subject.TARGET_SHA256)
        self.assertEqual(self.summary['target_sha256'],subject.TARGET_SHA256)

    def test_wrong_digest_is_rejected_before_parsing(self):
        with self.assertRaisesRegex(ValueError,'SHA-256'):
            subject.verify_digest(b'not a captured binary')
        with self.flip_va(0x33a8c70):
            with self.assertRaisesRegex(ValueError,'SHA-256'):
                subject.produce(self.data)

    def test_all_eight_evidence_outputs_and_selected_counts(self):
        self.assertEqual(set(self.outputs), {'functions.tsv','edges.tsv','windows.tsv',
                        'branches.tsv','markers.tsv','action-cases.tsv','data.json','summary.json'})
        self.assertEqual(self.summary['function_count'],25)
        self.assertEqual(self.summary['selected_function_bytes'],21697)
        self.assertEqual(self.summary['edge_count'],54)
        self.assertEqual(self.summary['boundary_edge_count'],6)
        self.assertEqual(self.summary['branch_count'],163)
        self.assertEqual(self.summary['window_count'],57)
        self.assertEqual(self.summary['boundary_window_count'],12)
        self.assertEqual(self.summary['synthetic_action_cases'],12)
        self.assertEqual(self.summary['diagnostic_paths'],4)

    def test_selected_fdes_reconcile(self):
        records=subject.select_functions(self.data,self.sec,self.index,self.fdes)
        self.assertEqual(len(records),25)
        self.assertEqual(len({r['start'] for r in records}),25)
        self.assertTrue(all(int(r['end_exclusive'],16)>int(r['start'],16) for r in records))

    def test_corrupt_selected_body_fails_below_digest_gate(self):
        with self.flip_va(0x33a8d52):
            with self.assertRaisesRegex(ValueError,'FDE bytes'):
                subject.select_functions(self.data,self.sec,self.index,self.fdes)

    def test_changed_fde_end_rejected(self):
        altered=[dict(x) for x in self.fdes]
        altered[0]['end']+=1
        with self.assertRaisesRegex(ValueError,'FDE/index'):
            subject.select_functions(self.data,self.sec,self.index,altered)

    def test_changed_or_duplicate_unwind_entry_rejected(self):
        altered=[dict(x) for x in self.index]
        altered[0]['fde']+=1
        with self.assertRaisesRegex(ValueError,'FDE/index'):
            subject.select_functions(self.data,self.sec,altered,self.fdes)
        with self.assertRaisesRegex(ValueError,'duplicate selected unwind'):
            subject.select_functions(self.data,self.sec,self.index+[dict(self.index[0])],self.fdes)
        with self.assertRaisesRegex(ValueError,'duplicate selected FDE'):
            subject.select_functions(self.data,self.sec,self.index,self.fdes+[dict(self.fdes[0])])

    def test_each_selected_branch_opcode_and_displacement_is_bound(self):
        # Each selected function's full hash is an independent constraint even
        # on bytes that a fixed-form conditional decoder would otherwise accept.
        for row in self.rows('branches.tsv'):
            va=int(row['site'],16)
            width=len(bytes.fromhex(row['bytes']))
            for at in (va,va+width-1):
                with self.subTest(site=row['site'],offset=at-va):
                    with self.flip_va(at):
                        with self.assertRaisesRegex(ValueError,'FDE bytes'):
                            subject.select_functions(self.data,self.sec,self.index,self.fdes)

    def test_conditional_decoder_rejects_bad_opcode_and_exposes_changed_target(self):
        va=0x3676432
        original=subject.decode_branch(self.data,self.sec,va)
        self.assertEqual((original['condition'],original['target']),('ne',0x3676556))
        off=subject.file_offset(self.sec,va,6)
        with self.patch_offset(off,b'\x90'):
            with self.assertRaisesRegex(ValueError,'conditional branch'):
                subject.decode_branch(self.data,self.sec,va)
        with self.flip_va(va+5):
            self.assertNotEqual(subject.decode_branch(self.data,self.sec,va)['target'],original['target'])

    def test_each_new_transfer_opcode_and_displacement_is_bound(self):
        for row in self.rows('edges.tsv'):
            if row['scope'] != 'new':
                continue
            va=int(row['site'],16)
            width=len(bytes.fromhex(row['bytes']))
            for at in (va,va+width-1):
                with self.subTest(site=row['site'],offset=at-va):
                    with self.flip_va(at):
                        with self.assertRaisesRegex(ValueError,'FDE bytes'):
                            subject.select_functions(self.data,self.sec,self.index,self.fdes)

    def test_boundary_windows_reject_each_byte_change(self):
        rows=[x for x in subject.WINDOWS if x[1]=='boundary']
        self.assertEqual(len(rows),12)
        for name,scope,lo,hi in rows:
            with self.subTest(name=name):
                with self.flip_va(lo):
                    with self.assertRaisesRegex(ValueError,'boundary bytes'):
                        subject.selected_windows(self.data,self.sec)

    def test_relative_call_encoding_and_target(self):
        raw,target=subject.decode_edge(self.data,self.sec,0x361cf6e,'call')
        self.assertEqual(raw.hex(),'e8fdbcd8ff')
        self.assertEqual(target,0x33a8c70)
        with self.flip_va(0x361cf6f):
            self.assertNotEqual(subject.decode_edge(self.data,self.sec,0x361cf6e,'call')[1],target)
        off=subject.file_offset(self.sec,0x361cf6e,1)
        with self.patch_offset(off,b'\x90'):
            with self.assertRaisesRegex(ValueError,'rel32 opcode'):
                subject.decode_edge(self.data,self.sec,0x361cf6e,'call')
        with self.assertRaises(ValueError):
            subject.decode_edge(self.data,self.sec,0x361cf6e,'unknown')

    def test_all_edges_match_independently_decoded_targets(self):
        for row in self.rows('edges.tsv'):
            with self.subTest(name=row['name']):
                raw,target=subject.decode_edge(self.data,self.sec,int(row['site'],16),row['kind'])
                self.assertEqual(raw.hex(),row['bytes'])
                self.assertEqual(target,int(row['target_or_slot'],16))

    def test_matching_key_copies_old_value_before_replacement(self):
        # This checks the actual copy/store sequence, rather than simulating
        # a container and assuming the desired duplicate semantics.
        expected=('498b4f10488b44240848894810410f10070f1100488b0c24'
                  '0f1001410f1107488b491049894f10')
        subject.expected_bytes(self.data,self.sec,0x33a8d52,expected)
        subject.expected_bytes(self.data,self.sec,0x361cf6e,
                               'e8fdbcd8ff488b34244839ee0f84ddfeffff')
        subject.expected_bytes(self.data,self.sec,0x367641b,
                               'e85028d3ff488b74241048b800000000000000804839c60f851e010000')
        with self.flip_va(0x33a8d66):
            with self.assertRaisesRegex(ValueError,'fixed-byte'):
                subject.expected_bytes(self.data,self.sec,0x33a8d52,expected)

    def test_action_boundaries_and_duplicate_results(self):
        anchors=subject.action_anchors(self.data,self.sec)
        self.assertEqual((anchors['minimum_nonempty'],anchors['maximum'],anchors['outer_limit']), (3,20,101))
        expected={0:('remove',0x186),1:('too_short',0xd4),2:('too_short',0xd4),
                  3:('insert_or_replace',0x186),20:('insert_or_replace',0x186),
                  21:('too_long',0xd3),100:('too_long',0xd3),101:('outer_reject',0x143)}
        for length,result in expected.items():
            with self.subTest(length=length):
                self.assertEqual(subject.action_case(length,False,anchors),result)
        for length in (3,20):
            self.assertEqual(subject.action_case(length,True,anchors),('duplicate_value',0xd5))
        for invalid in (-1,True,1.5):
            with self.assertRaises(ValueError):
                subject.action_case(invalid,False,anchors)
        with self.assertRaises(ValueError):
            subject.action_case(3,1,anchors)
        with self.flip_va(0x4d9b9b8):
            with self.assertRaises(ValueError):
                subject.action_anchors(self.data,self.sec)
        with self.flip_va(0x4d9bc62):
            with self.assertRaises(ValueError):
                subject.action_anchors(self.data,self.sec)

    def test_primary_capture_connects_state_offset_and_row(self):
        row=subject.primary_capture(self.data,self.sec)
        self.assertEqual((row['state_offset'],row['stack_spill_offset'],row['vtable']),
                         ('0x4410','0x1a0','0x57448c8'))
        self.assertEqual(row['closure_array_offset'],'0xf0')
        self.assertEqual((row['thunk'],row['closure_body']),('0x4592a80','0x4ae4ec0'))
        for va in (0x4d7e8fe,0x4d7ef4e,0x4d7f621,0x4592a85):
            with self.subTest(va=va):
                with self.flip_va(va):
                    with self.assertRaises(ValueError):
                        subject.primary_capture(self.data,self.sec)
        off=int(row['call_relocation_file_offset'],16)
        with self.patch_offset(off+16,b'\x00'):
            with self.assertRaisesRegex(ValueError,'relocation changed'):
                subject.primary_capture(self.data,self.sec)

    def test_action_insert_replace_and_remove_count_bytes(self):
        expected=('498b4f10488b44240848894810410f10070f1100488b0c24'
                  '0f1001410f1107488b491049894f10')
        subject.expected_bytes(self.data,self.sec,0x493d232,expected)
        subject.expected_bytes(self.data,self.sec,0x4944c58,'e8132897ff4c8b7c246848ff4d10')
        for va in (0x493d246,0x4944c63):
            with self.subTest(va=va):
                with self.flip_va(va):
                    with self.assertRaisesRegex(ValueError,'FDE bytes'):
                        subject.select_functions(self.data,self.sec,self.index,self.fdes)

    def test_name_comparison_symbol_is_bound(self):
        record=subject.comparison_relocation(self.data,self.sec,0x576e378,b'bcmp')
        self.assertEqual((record['symbol'],record['symbol_index']),('bcmp',11))
        off=int(record['file_offset'],16)
        with self.patch_offset(off+12,b'\x0c\x00\x00\x00'):
            with self.assertRaisesRegex(ValueError,'symbol mismatch'):
                subject.comparison_relocation(self.data,self.sec,0x576e378,b'bcmp')

    def test_all_duplicate_diagnostics_are_derived_from_immediates(self):
        paths={x['path'] for x in self.data_record['diagnostics']}
        self.assertEqual(paths,{'json_object','json_pairs','mp_map','mp_pairs'})
        self.assertTrue(all(x['text']=='duplicate key' for x in self.data_record['diagnostics']))
        self.assertTrue(all(x['first_store']=='488908' and x['second_store']=='48894805'
                            for x in self.data_record['diagnostics']))

    def test_prior_field_guards_and_labels_are_bound_without_claiming_visitors(self):
        found=subject.prior_field_bindings(self.data,self.sec)
        by_mode={x['mode']:x for x in found['duplicate_guards']}
        self.assertEqual(by_mode['json']['duplicate_target'],'0x2ff02d5')
        self.assertEqual(by_mode['messagepack']['duplicate_target'],'0x2abe5aa')
        self.assertEqual(found['json_colon_handoff']['target'],'0x2fe7c09')
        with self.flip_va(0x2ff02d8):
            with self.assertRaises(ValueError):
                subject.prior_field_bindings(self.data,self.sec)
        with self.flip_va(0x578c9a):
            with self.assertRaises(ValueError):
                subject.prior_field_bindings(self.data,self.sec)

    def test_json_selected_dispatch_targets(self):
        values={x['character']:int(x['target'],16) for x in self.data_record['json_dispatch']}
        self.assertEqual(values,{'[':0x361ccf0,'{':0x361cdf6})
        raw=subject.read(self.data,self.sec,0x59035c,4)
        self.assertEqual(0x59035c+struct.unpack('<i',raw)[0],values['['])

    def test_field_label_and_key_width(self):
        subject.expected_bytes(self.data,self.sec,0x27b36d1,'488d35fdbcc3fdba14000000')
        self.assertEqual(subject.read(self.data,self.sec,0x3ef3d5,20),b'user_to_display_name')
        self.assertEqual(subject.read(self.data,self.sec,0x20a020,4),b'User')
        subject.expected_bytes(self.data,self.sec,0x33a8cf0,'ba14000000')
        with self.flip_va(0x27b36d8):
            with self.assertRaisesRegex(ValueError,'fixed-byte'):
                subject.expected_bytes(self.data,self.sec,0x27b36d1,'488d35fdbcc3fdba14000000')

    def test_fixed_container_marker_boundaries(self):
        rows=self.rows('markers.tsv')
        self.assertEqual(len(rows),32)
        for m in range(0x80,0xa0):
            kind,count=subject.marker_case(m,0x80,0x90,0xa0,0x0f)
            self.assertEqual((kind,count),('map' if m<0x90 else 'sequence',m & 15))
            self.assertEqual(rows[m-0x80]['route'],kind)
            self.assertEqual(int(rows[m-0x80]['declared_count']),count)
        for m in (0x7f,0xa0,-1,256,True):
            with self.assertRaises(ValueError):
                subject.marker_case(m,0x80,0x90,0xa0,0x0f)

    def test_selected_pair_marker(self):
        subject.expected_bytes(self.data,self.sec,0x1dd593d,'c6040192')
        subject.expected_bytes(self.data,self.sec,0x43be18d,'c6040192')
        with self.flip_va(0x1dd5940):
            with self.assertRaisesRegex(ValueError,'fixed-byte'):
                subject.expected_bytes(self.data,self.sec,0x1dd593d,'c6040192')

    def test_relocation_resolves_symbol_and_rejects_mutations(self):
        result=subject.memcmp_relocation(self.data,self.sec)
        self.assertEqual((result['type'],result['symbol'],result['symbol_index']), (6,'memcmp',12))
        off=int(result['file_offset'],16)
        with self.patch_offset(off+8,b'\x08'):
            with self.assertRaises(ValueError):
                subject.memcmp_relocation(self.data,self.sec)
        with self.patch_offset(off+12,b'\x00\x00\x00\x00'):
            with self.assertRaises(ValueError):
                subject.memcmp_relocation(self.data,self.sec)
        r=subject.one_section(self.sec,'.rela.dyn')
        duplicate_at=r['offset']
        self.assertNotEqual(duplicate_at,off)
        with self.patch_offset(duplicate_at,self.data[off:off+24]):
            with self.assertRaisesRegex(ValueError,'duplicate'):
                subject.memcmp_relocation(self.data,self.sec)

    def test_nonfile_backed_ambiguous_and_outside_ranges_rejected(self):
        sec=[{'type':8,'address':0x100,'offset':0,'size':32}]
        for start,size in ((0x100,1),(0x101,1),(0x100,0),(-1,1)):
            with self.assertRaises(ValueError):
                subject.file_offset(sec,start,size)
        real={'type':1,'address':0x100,'offset':12,'size':8}
        self.assertEqual(subject.file_offset([real],0x102,2),14)
        for start,size in ((0xff,1),(0x107,2),(0x108,1)):
            with self.assertRaises(ValueError):
                subject.file_offset([real],start,size)
        with self.assertRaises(ValueError):
            subject.file_offset([real,dict(real)],0x100,1)

    def test_unknown_data_or_instruction_address_rejected(self):
        for va in (0,0x7fffffffffff):
            with self.assertRaises(ValueError):
                subject.read(self.data,self.sec,va,1)
        with self.assertRaises(ValueError):
            subject.read(self.data,self.sec,0x3ef3d5,0)

    def test_output_has_no_host_paths(self):
        for name,contents in self.outputs.items():
            with self.subTest(name=name):
                for component in (b'mnt', b'srv', b'home', b'root', b'tmp', b'opt'):
                    forbidden = bytes([47]) + component + bytes([47])
                    self.assertNotIn(forbidden, contents)


if __name__ == '__main__':
    unittest.main()
