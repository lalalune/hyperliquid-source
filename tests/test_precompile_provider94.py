"""Target-byte and independent predicate controls; no executable invocation."""
import copy
import csv
import io
import json
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import precompile_provider94 as p


class Provider94Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image=p.Image((ROOT/'artifacts/node/94/hl-node').read_bytes())
        cls.outputs=p.collect(cls.image)
        cls.insns=json.loads(cls.outputs['instructions.json'])
        cls.records=list(csv.DictReader(io.StringIO(cls.outputs['private-records.tsv']),delimiter='\t'))

    def test_target_hash_rejects_corruption(self):
        with self.assertRaisesRegex(ValueError,'digest'):
            p.Image(b'\x7fELFcorrupted')

    def test_expected_byte_negative(self):
        self.image.expect(0x251553c,'ff5128')
        with self.assertRaisesRegex(ValueError,'predicate'):
            self.image.expect(0x251553c,'ff5120')

    def test_range_controls(self):
        for address,size in [(-1,1),(0,1),(0x24448a0,0),(0x24448a0,-1),(1<<64,1)]:
            with self.subTest(address=address,size=size),self.assertRaises(ValueError):
                self.image.read(address,size)

    def test_nobits_is_not_file_data(self):
        bss=next(s for s in self.image.secs if s['name']=='.bss' and s['type']==8)
        with self.assertRaises(ValueError): self.image.read(bss['address'],1)

    def test_section_crossing(self):
        section=self.image.section('.text')
        with self.assertRaises(ValueError):self.image.read(section['address']+section['size']-1,2)

    def test_fde_not_inferred_from_membership(self):
        with self.assertRaises(ValueError):self.image.fde(0x24448a1)

    def test_relocation_negative(self):
        with self.assertRaises(ValueError):self.image.relative(0x56bfac9)
        damaged=copy.copy(self.image);damaged.relas=dict(self.image.relas)
        info,target,offset=damaged.relas[0x56bfac8]
        damaged.relas[0x56bfac8]=(info+1,target,offset)
        with self.assertRaises(ValueError):damaged.relative(0x56bfac8)

    def test_provider_to_runtime_callback_chain(self):
        self.assertEqual(self.image.relative(0x56a6878),0x24448a0)
        self.assertEqual(self.image.relative(0x56bfac8),0x276d390)
        self.assertEqual(self.image.relative(0x56b8060),0x24b6590)
        calls=[r['target'] for r in self.insns if r['function']==0x276d390 and r['kind']=='call']
        self.assertIn(0x2788710,calls)

    def test_private_set_and_builtin_disjointness(self):
        for provider in ['0x24448a0','0x3268ce0']:
            rows=[r for r in self.records if r['provider']==provider]
            self.assertEqual([int(r['address'],16) for r in rows],[0x800,0x813]+list(range(0x801,0x813)))
            self.assertTrue(all(r['tag']=='2' and r['size']=='80' and r['alignment']=='8' for r in rows))
            self.assertNotIn((9).to_bytes(20,'big').hex(),[r['key'] for r in rows])

    def test_corrupt_private_tag_rejected(self):
        rows=copy.deepcopy(self.insns)
        site=int(self.records[0]['tag_store'],16)
        next(r for r in rows if r['va']==site)['immediate']=3
        with self.assertRaisesRegex(ValueError,'tag'):p.private_records(self.image,rows,0x24448a0)

    def test_corrupt_key_suffix_placement_rejected(self):
        rows=copy.deepcopy(self.insns)
        site=int(self.records[0]['suffix_store'],16)
        next(r for r in rows if r['va']==site)['displacement']+=1
        with self.assertRaisesRegex(ValueError,'placement'):p.private_records(self.image,rows,0x24448a0)

    def test_corrupt_vtable_rejected(self):
        damaged=copy.copy(self.image)
        vt=int(self.records[0]['vtable'],16)
        original=self.image.read
        damaged.read=lambda va,n: bytes(n) if va==vt and n==32 else original(va,n)
        with self.assertRaisesRegex(ValueError,'vtable'):p.private_records(damaged,self.insns,0x24448a0)

    def test_qualified_mode_boundaries(self):
        table=self.image.read(0x3e452c,21)
        for raw,expected in [(255,6),(0,0),(5,0),(6,1),(8,1),(9,2),(10,2),(11,3),(16,3),(17,4),(18,5),(19,5)]:
            with self.subTest(raw=raw):self.assertEqual(p.select_mode(raw,table),expected)
        for raw in [-1,20,254,256,True]:
            with self.assertRaises(ValueError):p.select_mode(raw,table)
        with self.assertRaises(ValueError):p.select_mode(0,table[:-1])

    def test_clone_zero_and_one_share_raw_copy_branch(self):
        rows=list(csv.DictReader(io.StringIO(self.outputs['clone-tag-table.tsv']),delimiter='\t'))
        for function,expected in [('0x20482c0','0x2048370'),('0x35775d0','0x3577680')]:
            part=[r for r in rows if r['function']==function]
            self.assertEqual([r['target'] for r in part[:2]],[expected,expected])
            self.assertEqual(len({r['target'] for r in part}),3)

    def test_preservation_and_replacement(self):
        key9=(9).to_bytes(20,'big');key8=(0x800).to_bytes(20,'big')
        opaque=object();base={key9:opaque,key8:'old'}
        out,old=p.overlay(base,[(key8,'new')])
        self.assertIs(out[key9],opaque);self.assertEqual(old,['old'])
        self.assertEqual(base[key8],'old');self.assertEqual(out[key8],'new')
        absent,_=p.overlay({},[(key8,'new')]);self.assertNotIn(key9,absent)
        with self.assertRaises(ValueError):p.overlay({},[(b'\x09','bad')])

    def test_result_success_cost_boundaries(self):
        for gas,cost,remaining in [(0,0,0),(12,12,0),(12,11,1),((1<<64)-1,(1<<64)-1,0)]:
            self.assertEqual(p.result_policy([1,0,0,0,cost],gas),
                             dict(status=2,gas_after=remaining,rollback=False,fatal=False))

    def test_result_failure_and_fatal_are_distinct(self):
        over=p.result_policy([1,0,0,0,13],12)
        self.assertEqual(over,dict(status=0x53,gas_after=12,rollback=True,fatal=False))
        self.assertEqual(p.result_policy([0,0,1<<63,0,0],12),over)
        for code in [0,7,(1<<63)-1,(1<<63)+1,(1<<64)-1]:
            self.assertEqual(p.result_policy([0,0,code,0,0],12)['status'],0x60)
        for flag in [1,3,(1<<64)-1]:
            self.assertEqual(p.result_policy([0,flag,0,0,0],12),
                             dict(status=None,gas_after=None,rollback=None,fatal=True))

    def test_result_range_controls(self):
        for words,gas in [([1,0,0,0],0),([1,0,0,0,-1],0),([1,0,0,0,1<<64],0),([1,0,0,0,0],-1)]:
            with self.assertRaises(ValueError):p.result_policy(words,gas)

    def test_hash_simple_external_expectations(self):
        key=(9).to_bytes(20,'big')
        self.assertEqual(p.key_hash(key,0,0,0),0)
        self.assertEqual(p.key_hash(key,1,0,0),20)
        self.assertEqual(p.key_hash(bytes(20),1,0,1),21)
        for key in [bytes(19),bytes(21),'wrong']:
            with self.assertRaises(ValueError):p.key_hash(key,1,0,0)
        with self.assertRaises(ValueError):p.key_hash(bytes(20),1<<64,0,0)

    def test_lookup_rejects_same_fingerprint_wrong_full_key(self):
        key=(9).to_bytes(20,'big');other=bytes([1])+key[1:]
        controls=[255]*32;controls[20]=controls[21]=0
        buckets={20:(other,'wrong'),21:(key,'right')}
        self.assertEqual(p.lookup_model(key,1,0,0,controls,buckets),('right',21))
        buckets[21]=(key[:-1]+b'\x08','also-wrong')
        self.assertEqual(p.lookup_model(key,1,0,0,controls,buckets),(None,None))

    def test_lookup_next_group_and_wrap(self):
        key=(9).to_bytes(20,'big');controls=[128]*32
        controls[4]=0;controls[5]=255
        self.assertEqual(p.lookup_model(key,1,0,0,controls,{4:(key,'second-group')}),('second-group',4))

    def test_lookup_corruption_controls(self):
        key=(9).to_bytes(20,'big')
        for controls,buckets in [([255]*17,{}),([254]*32,{}),([0]*32,{}),([128]*32,{})]:
            with self.assertRaises(ValueError):p.lookup_model(key,1,0,0,controls,buckets)

    def test_decoder_direct_relative_target(self):
        rows=p.decode(bytes.fromhex('e80100000090c3'),0x1000)
        self.assertEqual(rows[0]['target'],0x1006)
        self.assertEqual([r['size'] for r in rows],[5,1,1])

    def test_decoder_rip_after_immediate(self):
        row=p.decode(bytes.fromhex('48833d0100000000'),0x1000)[0]
        self.assertEqual(row['rip'],0x1009)
        self.assertEqual(row['size'],8)

    def test_decoder_sib_is_not_rip(self):
        row=p.decode(bytes.fromhex('644833042588faffff'),0x1000)[0]
        self.assertNotIn('rip',row);self.assertEqual(row['displacement'],-1400)

    def test_decoder_negative_controls(self):
        for raw in ['e8','0f','62','488b','ebff','90'*0+'66'*16+'90']:
            with self.subTest(raw=raw),self.assertRaises(ValueError):p.decode(bytes.fromhex(raw),0x1000)

    def test_exception_ranges_and_landing_boundaries(self):
        rows=list(csv.DictReader(io.StringIO(self.outputs['exception-call-sites.tsv']),delimiter='\t'))
        boundaries={r['va'] for r in self.insns}
        self.assertTrue(rows)
        for row in rows:
            self.assertIn(int(row['site'],16),boundaries)
            if row['landing']:self.assertIn(int(row['landing'],16),boundaries)
        with self.assertRaises(ValueError):p.call_sites(self.image,0x24448a0,set())
        damaged=copy.copy(self.image)
        wrong=dict(self.image.fde(0x24448a0));wrong['lsda']=0x24448a0
        damaged.fde=lambda function:wrong
        with self.assertRaisesRegex(ValueError,'exception section'):
            p.call_sites(damaged,0x24448a0,boundaries)

    def test_published_evidence_regenerates(self):
        directory=ROOT/'research/work-items/RE-021-precompile-provider-94'
        actual={f.name for f in directory.iterdir() if f.suffix in ('.json','.tsv')}
        self.assertEqual(actual,set(self.outputs))
        for name,expected in self.outputs.items():
            with self.subTest(name=name):self.assertEqual((directory/name).read_bytes(),expected.encode('ascii'))


if __name__=='__main__':unittest.main()
