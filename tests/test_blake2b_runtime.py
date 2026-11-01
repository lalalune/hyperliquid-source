"""Static RE-021 runtime path checks; no emulation, external commands or skips."""
import ast
import copy
import csv
import io
import json
from pathlib import Path
import struct
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import blake2b_runtime as m


class Blake2bRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image=m.Image((ROOT/'artifacts/node/94/hl-node').read_bytes())
        cls.output=m.collect(cls.image)
        cls.key=cls.image.read(0x574f0c0,20)

    def test_authentic_corpus(self):
        summary=json.loads(self.output['summary.json'])
        self.assertEqual(summary['function_count'],24)
        self.assertEqual(summary['mode_membership_counts'],[4,8,9,9,10,17])
        self.assertEqual(summary['mode_contains_09'],[False,False,True,True,True,True])
        self.assertFalse(summary['captured_execution'])
        self.assertFalse(summary['gate_requested'])

    def test_regenerated_files_match(self):
        folder=ROOT/'research/work-items'/m.PACKET
        for name,raw in self.output.items():
            with self.subTest(file=name):
                self.assertEqual(raw,(folder/name).read_bytes())

    def test_corrupt_digest_fails_before_elf(self):
        with self.assertRaisesRegex(ValueError,'digest'):
            m.Image(b'not the pinned input')

    def test_corrupt_target_byte_fails(self):
        bad=bytearray(self.image.data)
        bad[self.image.offset(0x4e997a0,1)]^=1
        with self.assertRaisesRegex(ValueError,'digest'):
            m.Image(bad)

    def test_ranges_and_nobits(self):
        bss=next(s for s in self.image.sections if s['name']=='.bss')
        text=self.image.section('.text')
        for va,size in [(bss['address'],1),(-1,1),(0x4e997a0,0),
                        (1<<64,16),(text['address']+text['size']-1,2)]:
            with self.subTest(va=va,size=size),self.assertRaises(ValueError):
                self.image.read(va,size)

    def test_ambiguous_file_mapping(self):
        im=copy.copy(self.image)
        im.sections=self.image.sections+[dict(self.image.section('.text'))]
        with self.assertRaisesRegex(ValueError,'uniquely'):
            im.read(0x4e99650,1)

    def test_missing_or_duplicate_fde(self):
        im=copy.copy(self.image);im.fdes=dict(self.image.fdes)
        with self.assertRaisesRegex(ValueError,'FDE'):
            im.fde(0x4e99651)
        im.fdes[0x4e99650]=im.fdes[0x4e99650]*2
        with self.assertRaisesRegex(ValueError,'FDE'):
            im.fde(0x4e99650)

    def test_predicate_negative_control(self):
        with self.assertRaisesRegex(ValueError,'predicate'):
            self.image.expect(0x4e997a0,'0f1004')

    def test_relocation_type_control(self):
        im=copy.copy(self.image);im.relocations=dict(im.relocations)
        info,dest,off=im.relocations[0x574f0b0]
        self.assertEqual(dest,0x4e9d2a0)
        im.relocations[0x574f0b0]=(6,dest,off)
        with self.assertRaisesRegex(ValueError,'RELATIVE'):
            m.static_records(im)

    def test_record_copy_and_tag(self):
        records=m.static_records(self.image)
        record=next(r for r in records if r['base']==0x574f0a8)
        self.assertEqual(record['tag'],0)
        self.assertEqual(record['callback_slot'],0x574f0b0)
        self.assertEqual(record['key'],'00'*19+'09')
        rows=list(csv.DictReader(io.StringIO(self.output['constructor-copies.tsv'].decode()),delimiter='\t'))
        assembled=b''.join(bytes.fromhex(r['source_bytes']) for r in sorted(rows,key=lambda r:int(r['record_offset'])))
        self.assertEqual(assembled,bytes.fromhex(record['raw']))

    def test_table_targets_and_tamper(self):
        owner=0x4ea2df0
        raw=self.image.read(owner,self.image.fde(owner)['end']-owner)
        bounds={owner+i for i,_ in m.validated_walk(raw)}
        rows=m.jump_table(self.image,0x7c53e0,4,bounds)
        self.assertEqual([r[3] for r in rows],[0x4ea2e0a,0x4ea2e9b,0x4ea2e1b,0x4ea2e40])
        class BadTable:
            def read(self,va,size):return struct.pack('<i',0)*4
        with self.assertRaisesRegex(ValueError,'table target'):
            m.jump_table(BadTable(),0x7c53e0,4,bounds)

    def test_selector_constructor_binding(self):
        start=0x4e9d240
        decoded=m.validated_walk(self.image.read(start,self.image.fde(start)['end']-start))
        rows=m.selector_rows(self.image,decoded)
        self.assertEqual([int(row[4],16) for row in rows],m.MODES)
        self.assertEqual(len({row[2] for row in rows}),6)
        tampered=copy.deepcopy(decoded)
        tail=next(row for off,row in tampered if start+off==0x4e9d273)
        tail['relative']=m.MODES[1]-start
        with self.assertRaisesRegex(ValueError,'mode/constructor'):
            m.selector_rows(self.image,tampered)

    def test_instruction_relative_and_rip(self):
        raw=self.image.read(0x4e997a0,7)
        self.assertEqual(0x4e997a0+m.one(raw,0)['rip'],0x574f0a8)
        raw=self.image.read(0x4e70096,5)
        self.assertEqual(0x4e70096+m.one(raw,0)['relative'],0x4e8cfd0)

    def test_unsupported_and_truncated_shapes(self):
        for raw in [bytes.fromhex('c5'),bytes.fromhex('48b800'),b'\x66'*15+b'\x90',
                    bytes.fromhex('0f'),bytes.fromhex('488b')]:
            with self.subTest(raw=raw.hex()),self.assertRaises(ValueError):m.walk(raw)

    def test_branch_into_instruction_rejected(self):
        with self.assertRaisesRegex(ValueError,'boundary'):
            m.validated_walk(bytes.fromhex('eb014889c0c3'))

    def test_corpus_instruction_partition(self):
        count=0
        for start in m.FUNCTIONS:
            raw=self.image.read(start,self.image.fde(start)['end']-start)
            rows=m.validated_walk(raw)
            self.assertEqual(sum(r['size'] for _,r in rows),len(raw))
            self.assertTrue(all(r['size']<=15 for _,r in rows))
            count+=len(rows)
        self.assertEqual(count,json.loads(self.output['summary.json'])['instruction_count'])

    def test_lookup_model_expected_branches(self):
        cases=json.loads(self.output['lookup-cases.json'])['cases']
        self.assertEqual([c['hit'] is not None for c in cases],
                         [False,True,False,False,True,True,True])
        self.assertEqual([len(c['trace']) for c in cases],[1,1,1,1,2,3,1])
        for c in cases:
            keys=[None]*64
            for i,k in c['keys'].items():keys[int(i)]=bytes.fromhex(k)
            actual=m.probe_lookup(list(bytes.fromhex(c['controls'])),keys,int(c['hash'],16),
                                  bytes.fromhex(c['query']),c['count'])
            self.assertEqual(actual,(c['hit'],c['trace']))

    def test_every_key_byte_matters(self):
        controls=[255]*16;keys=[None]*16
        controls[0]=0;keys[0]=self.key
        self.assertEqual(m.probe_lookup(controls,keys,0,self.key,1)[0],0)
        for byte in range(20):
            for bit in range(8):
                changed=bytearray(self.key);changed[byte]^=1<<bit
                self.assertIsNone(m.probe_lookup(controls,keys,0,bytes(changed),1)[0])

    def test_probe_wrap_and_candidate_order(self):
        c=[255]*16;k=[None]*16
        c[15]=c[0]=0;k[15]=bytes(20);k[0]=self.key
        hit,trace=m.probe_lookup(c,k,15,self.key,2)
        self.assertEqual(hit,0)
        self.assertEqual(trace[0]['candidates'],[15,0])

    def test_probe_malformed_controls_and_table(self):
        for c,k,h,key,n in [([0]*16,[None]*16,0,self.key,0),
                            ([255]*15,[None]*15,0,self.key,0),
                            ([129]+[255]*15,[None]*16,0,self.key,0),
                            ([255]*16,[None]*16,-1,self.key,1),
                            ([255]*16,[None]*16,0,b'short',1)]:
            with self.assertRaises(ValueError):m.probe_lookup(c,k,h,key,n)

    def test_hash_domain_and_seed_dependence(self):
        h=m.address_hash(self.key,1,3,5)
        self.assertNotEqual(h,m.address_hash(self.key,2,3,5))
        for key,seed in [(b'',1),(self.key,-1),(self.key,1<<64)]:
            with self.assertRaises(ValueError):m.address_hash(key,seed,3,5)

    def test_hash_multiply_halves_oracle(self):
        # Independent 32-bit schoolbook product verifies the folded u64 multiply.
        def fold(a,b):
            mask=(1<<32)-1
            limbs=[(a&mask)*(b&mask),(a>>32)*(b&mask)+(a&mask)*(b>>32),(a>>32)*(b>>32)]
            limbs[1]+=limbs[0]>>32;limbs[0]&=mask
            limbs[2]+=limbs[1]>>32;limbs[1]&=mask
            return (limbs[0]|limbs[1]<<32)^limbs[2]
        for t in range(64):
            key=bytes((i*19+t*7)&255 for i in range(20))
            s=t*((1<<64)-1)//63;a=((1<<64)-1)^s;b=(s>>1)^0x123456789abcdef
            word=lambda i:int.from_bytes(key[i:i+8],'little')
            want=fold(fold(word(8)^b,word(12)^a)^fold(word(0)^s,word(4)^a)^20,a)
            self.assertEqual(m.address_hash(key,s,a,b),want)

    def test_result_failure_precedence(self):
        self.assertEqual(m.result_route(12,1,1,1<<63,12),
                         {'status':2,'remaining_word':0,'checkpoint':'decrement_depth'})
        self.assertEqual(m.result_route(11,1,0,0,12)['status'],0x53)
        self.assertEqual(m.result_route(12,0,0,1<<63,0)['status'],0x53)
        self.assertEqual(m.result_route(12,0,0,(1<<63)+1,0)['status'],0x60)
        self.assertEqual(m.result_route(12,0,1,1<<63,0)['checkpoint'],'fatal_return_no_local_action')
        with self.assertRaises(ValueError):m.result_route(-1,0,0,0,0)

    def test_imports_are_offline(self):
        tree=ast.parse((ROOT/'tools/blake2b_runtime.py').read_text())
        imports=set()
        for node in ast.walk(tree):
            if isinstance(node,ast.Import):imports.update(a.name for a in node.names)
            elif isinstance(node,ast.ImportFrom):imports.add(node.module)
        self.assertLessEqual(imports,{'__future__','argparse','csv','hashlib','io','json','pathlib','struct','elf_index','fde_extents'})


if __name__=='__main__':
    unittest.main()
