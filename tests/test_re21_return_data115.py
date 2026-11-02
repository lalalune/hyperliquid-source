"""Offline extraction controls for the node-115 return-data evidence."""
import csv
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest

from tools import re21_return_data115 as re21


class ExtractionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = (re21.ROOT / 'artifacts/node/115/hl-node').read_bytes()
        cls.sec = re21.sections(cls.data)
        cls.tmp = tempfile.TemporaryDirectory()
        cls.out = Path(cls.tmp.name) / 'evidence'
        cls.summary = re21.extract(cls.data, cls.out)
        cls.constants = json.loads((cls.out / 'constants.json').read_text())

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def rows(self, name):
        with (self.out / name).open(newline='') as f:
            return list(csv.DictReader(f, delimiter='\t'))

    def test_target_digest(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), re21.TARGET)
        re21.digest(self.data, re21.TARGET)
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            re21.digest(b'corrupt target', re21.TARGET)

    def test_legacy_digest_is_required(self):
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            re21.legacy_check(b'corrupt legacy artifact', self.data)

    def test_file_backed_ranges_exclude_nobits_and_crossing(self):
        sec = [{'name':'text','type':1,'flags':4,'address':0x100,'offset':0,'size':4},
               {'name':'bss','type':8,'flags':4,'address':0x200,'offset':4,'size':4}]
        self.assertEqual(re21.read_va(b'abcd',sec,0x101,2,True),b'bc')
        for start, length in [(0x103,2),(0x200,1),(0x300,1),(0x100,0),(-1,1)]:
            with self.subTest(start=start, length=length), self.assertRaises(ValueError):
                re21.read_va(b'abcd',sec,start,length,True)

    def test_ambiguous_or_nonexecutable_mapping_fails(self):
        a={'name':'a','type':1,'flags':4,'address':0x100,'offset':0,'size':4}
        b=dict(a, name='b')
        with self.assertRaises(ValueError):
            re21.read_va(b'abcd',[a,b],0x101,1,True)
        with self.assertRaises(ValueError):
            re21.read_va(b'abcd',[dict(a,flags=2)],0x101,1,True)

    def test_out_of_file_mapping_fails(self):
        sec=[{'name':'bad','type':1,'flags':4,'address':0x100,'offset':100,'size':4}]
        with self.assertRaises(ValueError):
            re21.read_va(b'xx',sec,0x100,1,True)

    def test_fde_ranges_and_header_selected(self):
        funcs=json.loads((self.out/'functions.json').read_text())
        self.assertEqual(len(funcs),16)
        by={f['label']:f for f in funcs}
        self.assertEqual(by['return_data_copy']['start_va'],'0x2997bd0')
        self.assertEqual(by['return_data_copy']['end_va_exclusive'],'0x2997e58')
        self.assertEqual(by['output_action_builder']['fde_va'],'0x116075c')
        self.assertEqual(sum(f['size'] for f in funcs),3865)

    def test_fde_corruption_fails_closed(self):
        funcs=json.loads((self.out/'functions.json').read_text())
        f=next(x for x in funcs if x['label']=='return_data_size')
        _, off = re21.file_offset(self.sec,int(f['fde_va'],16),16)
        altered=bytearray(self.data)
        altered[off+12] ^= 1
        with self.assertRaises(ValueError):
            re21.selected_fdes(altered,self.sec)

    def test_code_shape_corruption_is_detected(self):
        addr=0x2997bdb
        expected=bytes.fromhex('80bfa901000004')
        self.assertEqual(re21.checked_bytes(self.data,self.sec,addr,expected),expected)
        altered=bytearray(expected)
        altered[-1] ^= 1
        one=[{'name':'text','type':1,'flags':4,'address':addr,'offset':0,'size':len(altered)}]
        with self.assertRaises(ValueError):
            re21.checked_bytes(altered,one,addr,expected)

    def test_relative_branch_corruption_is_detected(self):
        site=0x100
        target=0x108
        sec=[{'name':'text','type':1,'flags':4,'address':site,'offset':0,'size':9}]
        image=bytes.fromhex('0f8202000000909090')
        self.assertEqual(re21.branch(image,sec,site,target)[1],target)
        with self.assertRaises(ValueError):
            re21.branch(image,sec,site,target+1)
        with self.assertRaises(ValueError):
            re21.branch(bytes.fromhex('0f0002000000909090'),sec,site,target)
        with self.assertRaises(ValueError):
            re21.branch(bytes.fromhex('0f8203000000909090'),sec,site,target)

    def test_rip_relative_corruption_is_detected(self):
        site=0x100
        sec=[{'name':'text','type':1,'flags':4,'address':site,'offset':0,'size':6}]
        raw=bytes.fromhex('ff150a000000')
        self.assertEqual(re21.rip_target(raw,sec,site,0x110,b'\xff\x15')[1],0x110)
        with self.assertRaises(ValueError):
            re21.rip_target(raw,sec,site,0x111,b'\xff\x15')
        with self.assertRaises(ValueError):
            re21.rip_target(b'\xff\x25'+raw[2:],sec,site,0x110,b'\xff\x15')

    def test_opcode_relocations_bind_distinct_handlers(self):
        rows={r['opcode']:r for r in self.rows('opcode-table.tsv')}
        self.assertEqual(rows['0x3d']['relocated_target'],'0x2997e60')
        self.assertEqual(rows['0x3e']['relocated_target'],'0x2997bd0')
        self.assertEqual(rows['0xf3']['relocated_target'],'0x2999560')
        self.assertEqual(rows['0xfd']['relocated_target'],'0x29996d0')
        self.assertEqual(len(rows),7)

    def test_relocation_kind_and_target_controls(self):
        self.assertEqual(re21.relative_target({'info':8,'addend':123},123),123)
        for item in ({'info':6,'addend':123},{'info':(1<<32)|8,'addend':123},
                     {'info':8,'addend':-1},{'info':8,'addend':124}):
            with self.subTest(item=item), self.assertRaises(ValueError):
                re21.relative_target(item,123)

    def test_missing_and_duplicate_relocation_controls(self):
        row=struct.pack('<QQq',0x100,8,0x200)
        sec=[{'name':'.rela.dyn','type':4,'flags':0,'address':0,'offset':0,'size':len(row)}]
        self.assertEqual(re21.relocations(row,sec,{0x100})[0x100]['addend'],0x200)
        with self.assertRaises(ValueError):
            re21.relocations(row,sec,{0x101})
        with self.assertRaises(ValueError):
            re21.relocations(row+row,[dict(sec[0],size=2*len(row))],{0x100})
        with self.assertRaises(ValueError):
            re21.relocations(row[:-1],[dict(sec[0],size=len(row)-1)],{0x100})

    def test_address09_anchor_and_all_key_bits(self):
        anchor=json.loads((self.out/'address-anchor.json').read_text())
        key=bytes.fromhex(anchor['key_bytes'])
        self.assertEqual(key,bytes(19)+b'\x09')
        self.assertEqual(anchor['callback_target_va'],'0x5c165b0')
        relocation={'info':8,'addend':0x5c165b0}
        self.assertEqual(re21.check_address09(key,relocation),0x5c165b0)
        for bit in range(160):
            changed=bytearray(key)
            changed[bit//8] ^= 1 << (bit%8)
            with self.subTest(bit=bit), self.assertRaises(ValueError):
                re21.check_address09(bytes(changed),relocation)
        with self.assertRaises(ValueError):
            re21.check_address09(key,{'info':8,'addend':0x5c165b1})

    def test_output_vtable_selection_clone_and_drop(self):
        rows={r['label']:r for r in self.rows('output-vtables.tsv')}
        self.assertEqual(set(rows),{'odd_allocation','even_allocation','promoted_shared'})
        self.assertEqual((rows['odd_allocation']['table_va'],rows['odd_allocation']['clone_target_va'],
                          rows['odd_allocation']['drop_target_va']),
                         ('0x64040c0','0x161c5d0','0x161c3f0'))
        self.assertEqual((rows['even_allocation']['table_va'],rows['even_allocation']['clone_target_va'],
                          rows['even_allocation']['drop_target_va']),
                         ('0x64040e8','0x161c620','0x161c4c0'))
        self.assertEqual((rows['promoted_shared']['clone_target_va'],rows['promoted_shared']['drop_target_va']),
                         ('0x161bcf0','0x161bc50'))
        re21.checked_bytes(self.data,self.sec,0x2999208,bytes.fromhex('4883cb0140f6c501480f45dd'))

    def test_shared_table_xrefs_and_mutation(self):
        rows=self.rows('shared-table-xrefs.tsv')
        self.assertEqual(len(rows),5)
        self.assertTrue(all(row['target_va']=='0x6404008' for row in rows))
        base,end=0x161bd06,0x161c649
        raw=bytearray(re21.read_va(self.data,self.sec,base,end-base,True))
        sec=[{'name':'text','type':1,'flags':4,'address':base,'offset':0,'size':len(raw)}]
        self.assertEqual(len(re21.shared_table_xrefs(raw,sec)),5)
        raw[0x161bf36+3-base]^=1
        with self.assertRaises(ValueError):
            re21.shared_table_xrefs(raw,sec)

    def test_synthetic_allocation_pointer_tag_cases(self):
        rows={r['label']:r for r in self.rows('output-vtables.tsv')}
        for pointer,label in ((1,'odd_allocation'),(2,'even_allocation'),
                              (0x1001,'odd_allocation'),(0x1000,'even_allocation')):
            with self.subTest(pointer=pointer):
                tagged=pointer | 1
                selected=rows['odd_allocation' if pointer & 1 else 'even_allocation']
                self.assertEqual(selected,rows[label])
                base=tagged if pointer & 1 else tagged & ~1
                self.assertEqual(base,pointer)
                self.assertEqual((pointer-base)+64,64)

    def test_ownership_failure_and_race_edges(self):
        rows={r['label']:r for r in self.rows('edges.tsv')}
        expected={'promote_span_overflow':'0x161bfa4',
                  'promote_alloc_null':'0x161bf8a',
                  'promote_compare_exchange_lost':'0x161bf4f',
                  'promote_ref_overflow':'0x161bf9c',
                  'shared_drop_nonfinal':'0x161bc90',
                  'even_drop_size_carry':'0x161c52d',
                  'action_old_value_zero':'0x29992f6',
                  'action_old_type_other':'0x2999382',
                  'action_old_type1_drop':'0x29e15d0'}
        for label,target in expected.items():
            with self.subTest(label=label):
                self.assertEqual(rows[label]['target_va'],target)
        discriminator=bytes.fromhex('83f801')
        self.assertEqual(re21.checked_bytes(self.data,self.sec,0x2999370,discriminator),discriminator)
        one=[{'name':'text','type':1,'flags':4,'address':0x2999370,'offset':0,'size':3}]
        with self.assertRaises(ValueError):
            re21.checked_bytes(bytes.fromhex('83f802'),one,0x2999370,discriminator)

    def test_output_vtable_relocation_corruption(self):
        wanted={0x64df8c0,0x64df8c8,0x64040c0,0x64040e0,0x64040e8,
                0x6404108,0x6404008,0x6404028}
        rel=re21.relocations(self.data,self.sec,wanted)
        self.assertEqual(len(re21.vtable_rows(self.data,self.sec,rel)),3)
        for slot in (0x64df8c0,0x64040e0,0x6404028):
            changed={key:dict(value) for key,value in rel.items()}
            changed[slot]['addend']+=1
            with self.subTest(slot=slot), self.assertRaises(ValueError):
                re21.vtable_rows(self.data,self.sec,changed)
        no_bytes=[dict(section,type=8) if section['address'] <= 0x64040c0 < section['address']+section['size']
                  else section for section in self.sec]
        with self.assertRaises(ValueError):
            re21.vtable_rows(self.data,no_bytes,rel)

    def test_promotion_header_and_atomic_exchange_corruption(self):
        for site,expected in ((0x161bf11,'48c7401002000000'),(0x161bf23,'f0480fb119')):
            raw=bytes.fromhex(expected)
            self.assertEqual(re21.checked_bytes(self.data,self.sec,site,raw),raw)
            bad=bytearray(raw)
            bad[-1]^=1
            sec=[{'name':'text','type':1,'flags':4,'address':site,'offset':0,'size':len(bad)}]
            with self.subTest(site=site), self.assertRaises(ValueError):
                re21.checked_bytes(bad,sec,site,raw)

    def test_promotion_allocation_unwind_landing(self):
        rows=self.rows('exception-sites.tsv')
        selected=[r for r in rows if r['function']=='output_promote_shared'
                  and int(r['start_va'],16)<=0x161bf94<int(r['end_va_exclusive'],16)]
        self.assertEqual(len(selected),1)
        self.assertEqual(selected[0]['landing_va'],'0x161bfcc')

    def test_indirect_symbols_and_expansion_boundary(self):
        rows={r['label']:r for r in self.rows('indirect-transfers.tsv')}
        self.assertEqual(rows['copy_memcpy']['symbol'],'memcpy')
        self.assertEqual(rows['copy_memset']['symbol'],'memset')
        self.assertEqual(rows['copy_expand']['addend'],'0x45244c0')
        self.assertEqual(rows['action_expand']['addend'],'0x45244c0')
        self.assertEqual(rows['drop_last_reference']['addend'],'0x5bde820')
        self.assertEqual(rows['drop_free_tail']['addend'],rows['action_free']['addend'])

    def test_source_paths_are_sanitized(self):
        rows=self.rows('sources.tsv')
        self.assertEqual(len(rows),3)
        self.assertTrue(all(r['sanitized_suffix'].startswith('z_vendor/') for r in rows))
        self.assertEqual(rows[0]['line'],'142')
        self.assertTrue(all(not r['sanitized_suffix'].startswith('/') for r in rows))

    def test_memory_lineage_agrees_across_consumers(self):
        rows=self.rows('field-lineage.tsv')
        groups={}
        for row in rows:
            groups.setdefault(row['group'],set()).add(row['displacement'])
        self.assertEqual(groups,{'memory_object':{'0x10'},'window_base':{'0x18'},
                                 'backing_pointer':{'0x20'},'return_length':{'0x160'},
                                 'return_pointer':{'0x158'}})
        self.assertEqual(len(rows),18)

    def test_memory_lineage_corrupt_displacement_fails(self):
        begin,end=0x2997410,0x29991de
        raw=bytearray(re21.read_va(self.data,self.sec,begin,end-begin,True))
        sec=[{'name':'text','type':1,'flags':4,'address':begin,'offset':0,'size':len(raw)}]
        self.assertEqual(len(re21.field_rows(raw,sec)),18)
        for site in (0x2997d0f,0x299919e):
            altered=raw.copy()
            altered[site-begin]^=1
            with self.subTest(site=site), self.assertRaises(ValueError):
                re21.field_rows(altered,sec)

    def test_word_lane_maps_and_endianness(self):
        rows=self.rows('byte-lanes.tsv')
        self.assertEqual(len(rows),64)
        for op in ('load','store'):
            pairs=sorted((int(r['input_byte_index']),int(r['output_byte_index']))
                         for r in rows if r['operation']==op)
            self.assertEqual(pairs,[(i,31-i) for i in range(32)])
            source=bytes(range(32))
            result=bytearray(32)
            for a,b in pairs:
                result[b]=source[a]
            self.assertEqual(bytes(result),source[::-1])
            for bit in range(256):
                src=(1 << bit).to_bytes(32,'big' if op=='load' else 'little')
                expected=(1 << bit).to_bytes(32,'little' if op=='load' else 'big')
                actual=bytearray(32)
                for a,b in pairs:
                    actual[b]=src[a]
                with self.subTest(op=op,bit=bit):
                    self.assertEqual(bytes(actual),expected)

    def test_word_lane_opcode_and_displacement_corruption(self):
        begin,end=0x2997410,0x2997679
        raw=bytearray(re21.read_va(self.data,self.sec,begin,end-begin,True))
        sec=[{'name':'text','type':1,'flags':4,'address':begin,'offset':0,'size':len(raw)}]
        self.assertEqual(len(re21.lane_rows(raw,sec)),64)
        for site in (0x29974a9,0x29974a8,0x299766e):
            changed=raw.copy()
            changed[site-begin]^=1
            with self.subTest(site=site), self.assertRaises(ValueError):
                re21.lane_rows(changed,sec)

    def test_exception_table_and_cleanup_landing(self):
        rows=self.rows('exception-sites.tsv')
        selected=[r for r in rows if r['function']=='output_action_builder'
                  and int(r['start_va'],16)<=0x29992f3<int(r['end_va_exclusive'],16)]
        self.assertEqual(len(selected),1)
        self.assertEqual(selected[0]['landing_va'],'0x2999436')
        self.assertEqual(self.summary['lsda_headers'],10)
        self.assertEqual(self.summary['lsda_call_sites'],42)

    def test_type1_drop_normal_and_unwind_references(self):
        rows=self.rows('exception-sites.tsv')
        selected=[r for r in rows if r['function']=='old_action_type1_drop'
                  and int(r['start_va'],16)<=0x29e15ec<int(r['end_va_exclusive'],16)]
        self.assertEqual(len(selected),1)
        self.assertEqual(selected[0]['landing_va'],'0x29e161f')

    def test_malformed_exception_tables_fail_closed(self):
        image=bytes.fromhex('ffff010401020500')
        sec=[{'name':'.gcc_except_table','type':1,'flags':2,'address':0x100,'offset':0,'size':len(image)}]
        fde={'lsda':0x100,'start':0x500,'end':0x50a}
        headers=[]
        rows=re21.call_sites(image,sec,fde,'test',headers)
        self.assertEqual(rows[0][3:6],['0x501','0x503','0x505'])
        self.assertEqual(headers[0][-1],'ffff0104')
        self.assertEqual(headers[0][-2],4)
        for raw in (bytes.fromhex('00ff010401020500'),bytes.fromhex('ffff010401020f00'),
                    bytes.fromhex('ffff010901020500'),bytes.fromhex('ffff020401020500')):
            with self.subTest(raw=raw.hex()), self.assertRaises(ValueError):
                re21.call_sites(raw,sec,fde,'test')

    def test_deterministic_evidence_matches_across_direct_generations(self):
        with tempfile.TemporaryDirectory() as d:
            other=Path(d)/'again'
            re21.extract(self.data,other)
            first={p.name:p.read_bytes() for p in self.out.iterdir()}
            second={p.name:p.read_bytes() for p in other.iterdir()}
            self.assertEqual(first,second)

    def test_no_internal_build_paths_in_generated_files(self):
        forbidden=tuple(b'/' + part + b'/' for part in (b'home',b'mnt',b'srv',b'tmp',b'root',b'opt'))
        for p in self.out.iterdir():
            data=p.read_bytes()
            for prefix in forbidden:
                with self.subTest(file=p.name,prefix=prefix):
                    self.assertNotIn(prefix,data)


class GateProjectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        data=(re21.ROOT/'artifacts/node/115/hl-node').read_bytes()
        re21.digest(data,re21.TARGET)
        sec=re21.sections(data)
        for site,hexbytes in re21.CHECKS:
            re21.checked_bytes(data,sec,site,bytes.fromhex(hexbytes))
        cls.k={
            'revision_minimum':re21.read_va(data,sec,0x2997be1,1,True)[0],
            'copy_error_revision':re21.read_va(data,sec,0x2997db6,1,True)[0],
            'copy_error_stack':re21.read_va(data,sec,0x2997bed,1,True)[0],
            'copy_error_wide':re21.read_va(data,sec,0x2997c4e,1,True)[0],
            'copy_error_source_bounds':re21.read_va(data,sec,0x2997c78,1,True)[0],
            'copy_error_insufficient_gas':re21.read_va(data,sec,0x2997dd1,1,True)[0],
            'return_status':struct.unpack('<I',re21.read_va(data,sec,0x2999568,4,True))[0],
            'revert_status':struct.unpack('<I',re21.read_va(data,sec,0x29996e1,4,True))[0]}

    def gate(self, **kw):
        values=dict(revision=4,stack_count=3,destination=0,source=0,size=64,
                    buffer_length=64,gas=6,word_price=3)
        values.update(kw)
        return re21.copy_gate(self.k,**values)

    def test_64_byte_normal_copy_boundary(self):
        self.assertEqual(self.gate(),(0,0,0,'memory-boundary'))

    def test_revision_precedes_stack_and_consumption(self):
        self.assertEqual(self.gate(revision=3,stack_count=0),(0x2b,0,6,'revision'))
        self.assertEqual(self.gate(stack_count=2),(0x2c,2,6,'stack'))

    def test_wide_size_precedes_source_and_charge(self):
        self.assertEqual(self.gate(size=1<<64,source=65,gas=0),(0x24,0,0,'size'))

    def test_source_equality_and_past_end(self):
        self.assertEqual(self.gate(source=63,size=1,gas=3),(0,0,0,'memory-boundary'))
        self.assertEqual(self.gate(source=64,size=1,gas=0),(0x2e,0,0,'source'))

    def test_zero_length_checks_source_before_empty(self):
        self.assertEqual(self.gate(source=64,size=0,destination=1<<200,gas=0),(0,0,0,'empty'))
        self.assertEqual(self.gate(source=65,size=0,gas=0),(0x2e,0,0,'source'))
        self.assertEqual(self.gate(source=1<<64,size=0,gas=0),(0x2e,0,0,'source'))

    def test_insufficient_charge_precedes_wide_destination(self):
        self.assertEqual(self.gate(destination=1<<64,gas=5),(0x20,0,5,'charge'))
        self.assertEqual(self.gate(destination=1<<64,gas=6),(0x24,0,0,'destination'))

    def test_ceiling_word_charge_boundaries(self):
        for size,charge in [(0,0),(1,3),(31,3),(32,3),(33,6),(64,6)]:
            with self.subTest(size=size):
                self.assertEqual(self.gate(size=size,gas=charge)[2],0)
                if charge:
                    self.assertEqual(self.gate(size=size,gas=charge-1)[0],0x20)

    def test_copy_charge_against_independent_division_oracle(self):
        for size in range(8193):
            result=self.gate(size=size,buffer_length=8192,gas=1000,word_price=3)
            expected=3*((size+31)//32)
            with self.subTest(size=size):
                self.assertEqual(result[0],0)
                self.assertEqual(result[2],1000-expected)

    def test_saturated_product_and_equal_gas(self):
        m=re21.U64_MAX
        self.assertEqual(self.gate(size=m,buffer_length=m,gas=m,word_price=m),
                         (0,0,0,'memory-boundary'))
        self.assertEqual(self.gate(size=m,buffer_length=m,gas=m-1,word_price=m),
                         (0x20,0,m-1,'charge'))

    def test_out_of_range_model_inputs_rejected(self):
        for change in ({'size':-1},{'source':1<<256},{'revision':256},
                       {'gas':1<<64},{'stack_count':1025},{'word_price':-1}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.gate(**change)

    def test_return_and_revert_share_action_builder(self):
        for status in (2,16):
            with self.subTest(status=status):
                self.assertEqual(re21.action_gate(self.k,2,0,64,status),
                                 (status,0,'allocation-boundary'))
                self.assertEqual(re21.action_gate(self.k,2,1<<200,0,status),
                                 (status,0,'empty-action'))

    def test_action_failure_order_and_stack_effects(self):
        self.assertEqual(re21.action_gate(self.k,1,1<<200,1<<200,2),(0x2c,1,'stack'))
        self.assertEqual(re21.action_gate(self.k,2,1<<200,1<<64,2),(0x24,0,'size'))
        self.assertEqual(re21.action_gate(self.k,2,1<<64,1,2),(0x24,0,'offset'))
        self.assertEqual(re21.action_gate(self.k,2,0,1,2,growth_status=0x21),
                         (0x21,0,'growth-boundary'))

    def test_action_model_rejects_unknown_status(self):
        for bad in (3, 2.0, True):
            with self.subTest(status=bad), self.assertRaises(ValueError):
                re21.action_gate(self.k,2,0,1,bad)


if __name__ == '__main__':
    unittest.main()
