import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'tools'))
from artifacts import ROOT, check
from compact_string_unwind import (BEGIN, END, SHA256, analyse, decode_lines,
                                    disassemble, generate, gnu_disassemble, join_lock_prefixes, read_va)
from elf_index import sections


class PrefixDisplayControls(unittest.TestCase):
    def test_only_observed_contiguous_lock_forms_join_without_byte_masks(self):
        raw={1:(b'\xf0','lock'),2:(bytes.fromhex('480fb10d01000000'),'cmpxchgq %rcx, 1(%rip)')}
        joined, prefixes=join_lock_prefixes(raw)
        self.assertEqual(prefixes,['0x1'])
        self.assertEqual(joined[1][0],bytes.fromhex('f0480fb10d01000000'))
        self.assertEqual(len(joined),1)
        for bad in [{1:(b'\xf0','lock')},{1:(b'\xf0','lock'),2:(b'\x90','nop')}]:
            with self.assertRaisesRegex(ValueError,'LOCK prefix'):
                join_lock_prefixes(bad)
        with self.assertRaisesRegex(ValueError,'Duplicate native'):
            decode_lines('1: 90 nop\n1: 90 nop\n')

    def test_wrong_input_never_publishes_a_packet(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary, output=Path(tmp)/'not-node94',Path(tmp)/'output'
            binary.write_bytes(b'not a target executable')
            with self.assertRaisesRegex(ValueError,'size/SHA-256'):
                generate(binary,output)
            self.assertFalse(output.exists())


class Node94UnwindEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary=ROOT/'artifacts/node/94/hl-node'
        item=next(x for x in json.loads((ROOT/'provenance/artifacts.json').read_text())['files']
                  if x['path']=='artifacts/node/94/hl-node')
        check(cls.binary,item)
        cls.data=cls.binary.read_bytes()
        cls.code,_=gnu_disassemble(cls.binary,cls.data)
        cls.result=analyse(cls.data,cls.code)

    def test_source_fde_call_intervals_and_external_resume_are_bound(self):
        r=self.result
        self.assertEqual(hashlib.sha256(self.data).hexdigest(),SHA256)
        self.assertEqual((r['fde']['start'],r['fde']['end']),(hex(BEGIN),hex(END)))
        self.assertEqual(r['source_location_binding']['addend'],'0x1ea56a')
        self.assertEqual(r['personality_binding']['slot_va'],'0x577a668')
        self.assertEqual(r['personality_binding']['addend'],'0x4f14ca0')
        self.assertEqual(r['resume_binding']['symbol'],'_Unwind_Resume')
        self.assertEqual(r['resume_binding']['slot_va'],'0x5778db0')
        self.assertEqual(r['denominator'],{'constructor_fdes':1,'call_site_intervals':13,
                         'distinct_landing_pads':4,'decoded_calls':26,'calls_with_table_entry':25})

    def test_optional_llvm_independently_decodes_the_entire_constructor(self):
        if not shutil.which(os.environ.get('LLVM_OBJDUMP','llvm-objdump')):
            self.skipTest('LLVM is optional for repository checks; packet reproduction requires it')
        code,_,prefixes=disassemble(self.binary,self.data)
        self.assertEqual(code,self.code)
        for va in prefixes:
            self.assertEqual(code[int(va,16)][0][0],0xF0)

    def test_return_pc_minus_one_keeps_boundary_call_in_its_cleanup_interval(self):
        r=self.result
        call=next(c for c in r['calls'] if c['site_va']=='0x1449cb2')
        self.assertEqual(call['return_pc_minus_one'],'0x1449cb6')
        self.assertEqual(call['lsda_row'],1)
        row=r['lsda']['rows'][call['lsda_row']]
        self.assertEqual(row['end_va'],'0x1449cb7')
        self.assertEqual(row['landing_pad_va'],'0x1449fa8')
        self.assertEqual(row['action_index'],0)
        # The cleanup-path unlock has a different pad and a negative filter;
        # the final pad's own opaque call is not covered by a table row.
        unlock=next(c for c in r['calls'] if c['site_va']=='0x1449ffb')
        row=r['lsda']['rows'][unlock['lsda_row']]
        self.assertEqual(row['landing_pad_va'],'0x144a003')
        self.assertEqual(row['action_chain'][0]['filter'],-1)
        self.assertIsNone(next(c for c in r['calls'] if c['site_va']=='0x144a003')['lsda_row'])

    def test_actual_lsda_bytes_reject_structural_and_boundary_corruption(self):
        r=self.result['lsda'];start,_=read_va(self.data,int(r['va'],16),1)
        first, second=r['rows'][:2]
        action=int(r['action_table_va'],16)-int(r['va'],16)
        mutations=[('LPStart',0,0),('type encoding',1,0xFF),
                   ('call encoding',3,3),('call table length',4,0x4C),
                   ('overlap',first['field_lsda_offsets'][1],0xF4),
                   ('pad in instruction',second['field_lsda_offsets'][2],0xA9),
                   ('action cycle',action+1,0x7F)]
        for name, offset, byte in mutations:
            with self.subTest(name=name):
                changed=bytearray(self.data);changed[start+offset]=byte
                with self.assertRaises(ValueError):
                    analyse(changed,self.code)

    def test_actual_source_personality_and_resume_retargets_are_detected(self):
        slots={0x566A990:0x1EA56B,0x577A668:0x4F14CA1}
        for slot,addend in slots.items():
            changed=bytearray(self.data);found=False
            for section in sections(changed):
                if section['type']==4:
                    for offset in range(section['offset'],section['offset']+section['size'],24):
                        if struct.unpack_from('<Q',changed,offset)[0]==slot:
                            struct.pack_into('<q',changed,offset+16,addend);found=True
            self.assertTrue(found)
            with self.subTest(slot=hex(slot)),self.assertRaises(ValueError):
                analyse(changed,self.code)
        changed=bytearray(self.data)
        p,_=read_va(changed,int(self.result['resume_binding']['plt_va'],16),6)
        struct.pack_into('<i',changed,p+2,struct.unpack_from('<i',changed,p+2)[0]+8)
        with self.assertRaises(ValueError):
            analyse(changed,self.code)

    def test_valid_action_mutation_changes_the_decoded_signed_filter(self):
        changed=bytearray(self.data)
        offset,_=read_va(changed,int(self.result['lsda']['action_table_va'],16),1)
        self.assertEqual(changed[offset],0x7F)
        changed[offset]=0
        altered=analyse(changed,self.code)
        self.assertEqual(altered['lsda']['rows'][-1]['action_chain'][0]['filter'],0)
        self.assertNotEqual(altered['lsda']['rows'][-1]['action_chain'],self.result['lsda']['rows'][-1]['action_chain'])
        self.assertEqual(altered['denominator'],self.result['denominator'])

    def test_retained_semantic_record_matches_authenticated_input(self):
        path=ROOT/'research/work-items/RE-002-compact-string-unwind-94/observed/records.json'
        stored=json.loads(path.read_text())
        self.assertEqual(stored,self.result)


if __name__=='__main__':
    unittest.main()
