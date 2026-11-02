"""Target-bound static controls. No binutils and no captured execution."""
import copy
import csv
import hashlib
import io
import json
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import hlchain_reader94 as h


class ReaderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image=h.Image((ROOT/h.ARTIFACT).read_bytes())
        cls.records=h.collect(cls.image)
        cls.contract=h.contracts(cls.image,cls.records)
        cls.rows={r['va']:r for r in cls.records['instructions']}

    def changed(self,va,new):
        im=copy.copy(self.image)
        im.data=bytearray(self.image.data)
        offset=im.offset(va,len(new))
        im.data[offset:offset+len(new)]=new
        return im

    def model(self,wire,**kw):
        return h.transfer_model(self.contract,wire,**kw)

    def test_target_digest(self):
        self.assertEqual(hashlib.sha256(self.image.data).hexdigest(),h.DIGEST)

    def test_corrupt_digest_rejected_before_elf_parsing(self):
        with self.assertRaisesRegex(ValueError,'digest'):
            h.Image(b'not a captured ELF')

    def test_modified_capture_fails_authentication(self):
        im=self.changed(0x13c4538,b'\x81')
        with self.assertRaisesRegex(ValueError,'digest'):
            h.Image(im.data)

    def test_full_selected_fde_partition(self):
        for f in self.records['functions']:
            rows=[r for r in self.records['instructions'] if f['start']<=r['va']<f['end']]
            self.assertEqual(rows[0]['va'],f['start'])
            self.assertEqual(rows[-1]['va']+rows[-1]['size'],f['end'])
            self.assertEqual(sum(r['size'] for r in rows),f['byte_count'])
            self.assertEqual(bytes.fromhex(''.join(r['bytes'] for r in rows)),
                             self.image.read(f['start'],f['byte_count']))
            for a,b in zip(rows,rows[1:]):self.assertEqual(a['va']+a['size'],b['va'])

    def test_scalar_sse_store_width_is_not_vector_width(self):
        rows=[r for r in self.records['instructions'] if r['bytes'].startswith('f20f11')]
        self.assertEqual(len(rows),2)
        for r in rows:
            self.assertEqual((r['width'],r['memory_width']),(64,64))
            im=self.changed(r['va'],b'\xf3')
            changed=h.instruction(im,r['va'],r['va']+r['size'])
            self.assertEqual((changed['width'],changed['memory_width']),(32,32))

    def test_internal_control_targets_are_instruction_starts(self):
        for row in self.records['instructions']:
            if row['kind'] in ('branch','jump'):self.assertIn(row['target'],self.rows)
        for row in self.records['tables']:self.assertIn(row['target'],self.rows)

    def test_every_byte_contract_corruption_is_rejected(self):
        im=copy.copy(self.image); im.data=bytearray(self.image.data)
        for va,expected in sorted(h.PINS.items()):
            with self.subTest(va=hex(va)):
                pos=im.offset(va);original=im.data[pos];im.data[pos]^=1
                try:
                    with self.assertRaises(ValueError):h.contracts(im,self.records)
                finally:im.data[pos]=original

    def test_table_shifted_into_instruction_rejected(self):
        base=0x216394
        delta=struct.unpack('<i',self.image.read(base,4))[0]
        im=self.changed(base,struct.pack('<i',delta+1))
        with self.assertRaisesRegex(ValueError,'instruction start'):h.collect(im)

    def test_table_out_of_range_rejected(self):
        im=self.changed(0x216394,struct.pack('<i',0x7fffffff))
        with self.assertRaisesRegex(ValueError,'instruction start'):h.collect(im)

    def test_valid_but_wrong_discriminant_arm_rejected(self):
        im=self.changed(0x216394,self.image.read(0x216398,4))
        records=h.collect(im)
        with self.assertRaisesRegex(ValueError,'mapping changed'):h.contracts(im,records)

    def test_branch_into_operand_rejected(self):
        r=self.rows[0x13c458f]
        delta=int.from_bytes(bytes.fromhex(r['bytes'])[-4:],'little',signed=True)
        im=self.changed(r['va']+2,struct.pack('<i',delta+1))
        with self.assertRaisesRegex(ValueError,'instruction start'):h.collect(im)

    def test_branch_direction_corruption_rejected(self):
        im=self.changed(0x13c458f+1,b'\x86')
        with self.assertRaisesRegex(ValueError,'byte contract'):h.contracts(im,h.collect(im))

    def test_unsupported_opcode_fails_closed(self):
        im=self.changed(0x13c44d0,b'\x62')
        with self.assertRaisesRegex(ValueError,'unsupported opcode'):h.collect(im)

    def test_truncated_instruction_fails_closed(self):
        with self.assertRaises(ValueError):h.instruction(self.image,0x13c458f,0x13c4590)

    def test_unmapped_range(self):
        for va,size in ((-1,1),(1<<64,1),(0x13c44d0,0),(0x13c44d0,-1)):
            with self.subTest(va=va,size=size):
                with self.assertRaises(ValueError):self.image.read(va,size)

    def test_section_crossing_range(self):
        s=next(s for s in self.image.sections if s['name']=='.rodata')
        with self.assertRaises(ValueError):self.image.read(s['address']+s['size']-1,2)

    def test_nobits_range(self):
        s=next(s for s in self.image.sections if s['name']=='.bss')
        self.assertEqual(s['type'],8)
        with self.assertRaises(ValueError):self.image.read(s['address'],1)

    def test_ambiguous_section_range(self):
        im=copy.copy(self.image); im.sections=list(im.sections)
        im.sections.append(copy.copy(next(s for s in im.sections if s['name']=='.rodata')))
        with self.assertRaises(ValueError):im.read(0x218227,1)

    def test_redirected_scalar_relocation_rejected(self):
        im=copy.copy(self.image); im.data=bytearray(self.image.data)
        _,pos=im.relocations[0x576e7e0]
        struct.pack_into('<q',im.data,pos+16,0x13c44d1)
        reparsed=h.Image(im.data,authenticate=False)
        with self.assertRaisesRegex(ValueError,'redirected'):h.contracts(reparsed,h.collect(reparsed))

    def test_redirected_name_relocation_rejected(self):
        im=copy.copy(self.image); im.data=bytearray(self.image.data)
        original,pos=im.relocations[0x5668248]
        struct.pack_into('<q',im.data,pos+16,original+1)
        reparsed=h.Image(im.data,authenticate=False)
        with self.assertRaisesRegex(ValueError,'name relocation'):h.contracts(reparsed,h.collect(reparsed))

    def test_changed_name_immediate_rejected(self):
        im=self.changed(0x13f410d,b'X')
        with self.assertRaises(ValueError):h.contracts(im,h.collect(im))

    def test_byte_and_packed_name_comparison_disagreement(self):
        im=self.changed(0x13f3f62,b'X')
        with self.assertRaisesRegex(ValueError,'matchers disagree'):h.contracts(im,h.collect(im))

    def test_two_name_matchers_and_relocated_table_agree(self):
        self.assertEqual([(n['name'],n['tag'],n['discriminant']) for n in self.contract['names']],
                         [('Local',9,0),('Sandbox',9,1),('Testnet',9,2),('Mainnet',9,3)])
        self.assertTrue(all(n['byte_comparison_sites'] for n in self.contract['names']))

    def test_aws_name_seed_is_outside_hlchain_discriminant_domain(self):
        seed=self.contract['seed_boundary']['text'].encode()
        self.assertEqual(self.model(bytes([0xa0|len(seed)])+seed)['outcome'],'unknown_name_call')
        self.assertEqual(self.model(b'\x20')['outcome'],'unsigned_out_of_range')

    def test_unsigned_paths_use_same_output_mapping(self):
        self.assertEqual(len(self.contract['numeric_maps']),5)
        for row in self.contract['numeric_maps']:self.assertEqual(row['outputs'],[0,1,2,3])

    def test_unsigned_success_and_boundaries(self):
        for marker,width in ((0xcc,1),(0xcd,2),(0xce,4),(0xcf,8)):
            for value in (0,1,2,3,4,127,128,(1<<(width*8))-1):
                r=self.model(bytes([marker])+value.to_bytes(width,'big')+b'Z')
                self.assertEqual(r['consumed'],width+1);self.assertEqual(r['remaining'],1)
                self.assertEqual(r['outcome'],'success' if value<4 else 'unsigned_out_of_range')
                self.assertEqual(r['result_tag'],9 if value<4 else 6)

    def test_signed_nonnegative_values_are_type_errors(self):
        for marker,width in ((0xd0,1),(0xd1,2),(0xd2,4),(0xd3,8)):
            for value in range(4):
                r=self.model(bytes([marker])+value.to_bytes(width,'big'))
                self.assertEqual(r['outcome'],'invalid_type_call')
                self.assertEqual(r['result_tag'],self.contract['formatted_error_tag'])

    def test_bool_nil_float_and_negative_fixint_are_type_errors(self):
        for wire in (b'\xc0',b'\xc2',b'\xc3',b'\xe0',b'\xff',b'\xca'+bytes(4),b'\xcb'+bytes(8)):
            self.assertEqual(self.model(wire)['outcome'],'invalid_type_call')

    def test_truncated_scalar_consumes_remaining_input(self):
        for marker,width in ((0xcd,2),(0xcf,8),(0xca,4),(0xd3,8)):
            for n in range(width):
                r=self.model(bytes([marker])+bytes(n))
                self.assertEqual((r['outcome'],r['remaining'],r['consumed']),('payload_eof',0,n+1))

    def test_short_counted_body_retains_available_body(self):
        for wire,consumed in ((b'\xa5Loca',1),(b'\xd9\x05Loca',2),(b'\xda\x00\x05Loca',3),
                              (b'\xdb\x00\x00\x00\x05Loca',5),(b'\xc4\x05Loca',2)):
            r=self.model(wire)
            self.assertEqual((r['outcome'],r['consumed'],r['remaining']),
                             ('declared_length_exceeds_input',consumed,4))

    def test_name_bytes_mode_switch(self):
        for n in self.contract['names']:
            name=n['name'].encode()
            for marker,width in ((0xc4,1),(0xc5,2),(0xc6,4)):
                wire=bytes([marker])+len(name).to_bytes(width,'big')+name+b'Z'
                no=self.model(wire);yes=self.model(wire,bytes_mode=True)
                self.assertEqual(no['callee'],0x1409090)
                self.assertEqual(yes['discriminant'],n['discriminant'])
                self.assertEqual(yes['terminal_site'],n['byte_match_store'])
                self.assertNotEqual(yes['terminal_site'],n['store'])
                self.assertEqual(no['remaining'],yes['remaining']);self.assertEqual(yes['remaining'],1)

    def test_name_case_and_length_are_exact(self):
        for n in self.contract['names']:
            text=n['name'].encode()
            self.assertEqual(self.model(bytes([0xa0|len(text)])+text)['discriminant'],n['discriminant'])
            self.assertEqual(self.model(bytes([0xa0|len(text)])+text)['terminal_site'],n['store'])
            for bad in (text.lower(),text+b' ',text[:-1],text+b'\0'):
                self.assertEqual(self.model(bytes([0xa0|len(bad)])+bad)['outcome'],'unknown_name_call')

    def test_invalid_utf8_is_a_separate_matcher_boundary(self):
        r=self.model(b'\xa1\xff')
        self.assertIn(0x13f3f50,r['trace'])
        self.assertEqual(r['outcome'],'unknown_name_call')
        self.assertIsNone(r['result_tag'])  # shared unknown-name constructor is not re-recovered

    def test_map_sequence_rejection_does_not_restore_depth(self):
        for marker,callee in ((0x80,0x1408e60),(0x90,0x1408fb0)):
            r=self.model(bytes([marker])+b'X',depth=2)
            self.assertEqual((r['depth_after'],r['consumed'],r['remaining'],r['callee']),(1,1,1,callee))

    def test_extension_rejection_restores_depth_and_leaves_payload(self):
        for marker,prefix in ((0xc7,b'\x05'),(0xc8,b'\x00\x05'),(0xc9,b'\x00\x00\x00\x05'),(0xd4,b'')):
            r=self.model(bytes([marker])+prefix+b'payload',depth=2)
            self.assertEqual(r['depth_after'],2);self.assertEqual(r['remaining'],7)
            self.assertEqual(r['callee'],0x14083f0)

    def test_depth_one_retains_zero(self):
        for marker in (0x80,0x90,0xd4):
            r=self.model(bytes([marker]),depth=1)
            self.assertEqual((r['outcome'],r['depth_after'],r['result_tag']),('depth_limit',0,8))

    def test_zero_depth_is_a_panic_boundary_not_wrapping_model(self):
        for marker in (0x80,0x90,0xd4):
            r=self.model(bytes([marker]),depth=0)
            self.assertEqual(r['outcome'],'depth_underflow_panic');self.assertEqual(r['depth_after'],0)

    def test_cached_marker_is_cleared_without_reading_wire_marker(self):
        r=self.model(b'LocalX',cached=(0xa0,5))
        self.assertEqual((r['consumed'],r['remaining'],r['cache_after'],r['discriminant']),(5,1,1,0))
        self.assertEqual(self.model(b'X',cached=(0,3))['consumed'],0)

    def test_invalid_cached_state_outside_model_contract(self):
        for cache in ((4,0),(0,255),(0xe0,0),(0x80,16),(0xa0,32)):
            with self.assertRaises(ValueError):self.model(b'',cached=cache)

    def test_all_wire_markers_have_a_route_and_model_outcome(self):
        routes=h.marker_rows(self.records)
        self.assertEqual([r['wire_marker'] for r in routes],list(range(256)))
        for row in routes:
            self.assertIn(row['fresh_route'],self.rows)
            self.assertIn(row['cached_route'],self.rows)
            if row['scalar_route'] is not None:self.assertIn(row['scalar_route'],self.rows)
            self.assertTrue(self.model(bytes([row['wire_marker']])+bytes(16))['outcome'])

    def test_formatted_rejections_all_use_recovered_tag_six_constructor(self):
        self.assertEqual(self.rows[0x13b53e9]['immediate'],6)
        for r in self.contract['rejection_visitors']:
            self.assertEqual(r['constructor'],0x13b5360)

    def test_valid_but_wrong_marker_dispatch_rejected(self):
        for base,slot,target in ((0x212ad8,0xc0,0x13bb521),
                                 (0x212ea4,0xc,0x13bb521),
                                 (0x2162e0,0xc,0x13c47cf),
                                 (0x212e5c,0,0x13bb230)):
            im=self.changed(base+slot*4,struct.pack('<i',target-base))
            with self.assertRaisesRegex(ValueError,'dispatch classification'):
                h.contracts(im,h.collect(im))

    def test_scalar_width_guard_corruption_rejected(self):
        im=self.changed(0x13c456b+3,b'\x04')
        with self.assertRaisesRegex(ValueError,'width guard'):h.contracts(im,h.collect(im))

    def test_endianness_instruction_corruption_rejected(self):
        im=self.changed(0x13c457c+2,b'\xcb')
        with self.assertRaisesRegex(ValueError,'byte contract'):h.contracts(im,h.collect(im))

    def test_all_cached_routes_preserve_normalized_input_outcomes(self):
        for row in h.marker_rows(self.records):
            wire=bytes(16)
            fresh=self.model(bytes([row['wire_marker']])+wire)
            cached=self.model(wire,cached=(row['normalized_marker'],row['payload']))
            for key in ('outcome','remaining','depth_after','cache_after','discriminant','result_tag','callee'):
                self.assertEqual(fresh[key],cached[key],(row,key))
            self.assertEqual(fresh['consumed'],cached['consumed']+1)

    def test_generation_is_pure_and_stable(self):
        first=h.outputs(self.image); second=h.outputs(self.image)
        self.assertEqual(first,second)
        for name,text in first.items():
            self.assertNotIn(str(ROOT),text)
            self.assertTrue(text.endswith('\n'))
        metrics=json.loads(first['evidence.json'])['metrics']
        rows=list(csv.DictReader(io.StringIO(first['cases.tsv']),delimiter='\t'))
        self.assertEqual(metrics['model_cases'],len(rows))


if __name__=='__main__':
    unittest.main()
