"""Static target-grounded controls for the private database cache packet."""
import copy
import hashlib
import json
from pathlib import Path
import struct
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import evm_db_cache_path94 as subject


class DatabaseCacheTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image=subject.Image((ROOT/'artifacts/node/94/hl-node').read_bytes())
        cls.generated=subject.outputs(cls.image)

    def mutate(self, va, raw):
        image=copy.copy(self.image)
        offset=image.offset(va,len(raw))
        image.data=image.data[:offset]+raw+image.data[offset+len(raw):]
        return image

    def test_exact_regeneration(self):
        folder=ROOT/'research/work-items/RE-021-db-input-cache-94'
        for name,value in self.generated.items():
            with self.subTest(name=name):
                self.assertEqual((folder/name).read_bytes(),value.encode('ascii'))

    def test_digest_before_parsing(self):
        with mock.patch.object(subject,'sections',side_effect=AssertionError('parsed wrong digest')):
            with self.assertRaisesRegex(ValueError,'digest'):
                subject.Image(b'not the authenticated ELF')

    def test_fde_identity_and_bytes(self):
        expected={0x1f651f0:0x1f657ef,0x1e6af40:0x1e6b2b1,0x1e6b2c0:0x1e6b8cd,
                  0x27c3dd0:0x27c3f56,0x27c4c80:0x27c4e0a,0x27c5000:0x27c5191}
        for start,end in expected.items():
            self.assertEqual(self.image.fde(start)['end'],end)
        for start in subject.FUNCTIONS:
            f=self.image.fde(start)
            rows=subject.decode(self.image.read(start,f['end']-start),start)
            self.assertEqual(sum(r['size'] for r in rows),f['end']-start)
            self.assertEqual(bytes.fromhex(''.join(r['bytes'] for r in rows)),self.image.read(start,f['end']-start))

    def test_invalid_and_nobits_ranges(self):
        bss=next(s for s in self.image.secs if s['name']=='.bss')
        text=self.image.section('.text')
        for va,n in [(-1,4),(0,1),(0x1f651f0,0),(bss['address'],1),
                     (text['address']+text['size']-1,2)]:
            with self.subTest(va=va,n=n),self.assertRaises(ValueError):
                self.image.read(va,n)
        with self.assertRaises(ValueError):
            self.image.fde(0x1f651f1)

    def test_duplicate_fde_and_ambiguous_section(self):
        image=copy.copy(self.image); image.fdes=dict(image.fdes)
        image.fdes[0x1f651f0]=image.fdes[0x1f651f0]*2
        with self.assertRaises(ValueError): image.fde(0x1f651f0)
        image.secs=list(image.secs)+[dict(image.section('.text'))]
        with self.assertRaises(ValueError): image.read(0x1f651f0,1)

    def test_changed_semantic_immediate(self):
        image=self.mutate(0x27c504d,b'\x20')
        with self.assertRaisesRegex(ValueError,'predicate'): subject.check_semantics(image)
        image=self.mutate(0x1e6b544,b'\x02')
        with self.assertRaisesRegex(ValueError,'predicate'): subject.check_semantics(image)

    def test_every_predicate_detects_corruption(self):
        image=copy.copy(self.image)
        original=image.read
        for va,hx in subject.PINS.items():
            raw=bytes.fromhex(hx); changed=bytes([raw[0]^1])+raw[1:]
            def read(at,n,va=va,changed=changed):
                return changed if at==va and n==len(changed) else original(at,n)
            image.read=read
            with self.subTest(va=hex(va)),self.assertRaises(ValueError):
                subject.check_semantics(image)

    def test_table_corruption_to_valid_wrong_arm(self):
        base=0x3bd324
        image=self.mutate(base,self.image.read(base+4,4))
        with self.assertRaisesRegex(ValueError,'branch table'): subject.check_semantics(image)

    def test_table_target_into_instruction(self):
        image=self.mutate(0x3bd324,struct.pack('<i',0x1e6b110-0x3bd324))
        with self.assertRaisesRegex(ValueError,'table target'): subject.collect(image)

    def test_wrong_relocation_kind(self):
        image=copy.copy(self.image); image.relas=dict(image.relas)
        _,addend,off=image.relas[0x574fb98]
        image.relas[0x574fb98]=(6,addend,off)
        with self.assertRaisesRegex(ValueError,'RELATIVE'): subject.collect(image)
        with self.assertRaises(ValueError): image.relative(0x574fb98)

    def test_reviewed_edges_and_branch_records(self):
        csv=__import__('csv')
        edges=list(csv.DictReader(self.generated['call-edges.tsv'].splitlines(),delimiter='\t'))
        by_site={r['site']:r for r in edges}
        self.assertEqual(len(edges),20)
        self.assertEqual(by_site['0x1e6b366']['target'],'0x37d0fb0')
        self.assertEqual(by_site['0x1e6b45d']['target'],'0x37d0fb0')
        self.assertEqual(by_site['0x1e6b4ac']['target'],'0x37d11d0')
        self.assertEqual(by_site['0x1f6572c']['slot'],'0x57732d8')
        self.assertEqual(by_site['0x1f6572c']['target'],'0x4e80200')
        branches=list(csv.DictReader(self.generated['predicate-branches.tsv'].splitlines(),delimiter='\t'))
        by_predicate={r['predicate']:r for r in branches}
        self.assertEqual(len(branches),39)
        self.assertEqual(by_predicate['0x1e6b543']['bytes'],'a801')
        self.assertEqual(by_predicate['0x1e6b543']['taken'],'0x1e6b6d1')
        self.assertEqual(by_predicate['0x1e6b543']['fallthrough'],'0x1e6b54b')
        self.assertEqual(by_predicate['0x1e6b137']['taken'],'0x1e6b2af')

    def test_corrupt_checked_call_and_condition(self):
        # Keep both changed instructions decodable, while changing their meaning.
        old=self.image.read(0x1e6b4ad,1)
        with self.assertRaisesRegex(ValueError,'selected call target'):
            subject.outputs(self.mutate(0x1e6b4ad,bytes([old[0]^1])))
        with self.assertRaisesRegex(ValueError,'selected predicate'):
            subject.outputs(self.mutate(0x1e6b30e,bytes.fromhex('4d85e4')))

    def test_dynamic_symbol_rows_and_controls(self):
        csv=__import__('csv')
        rows=list(csv.DictReader(self.generated['dynamic-symbols.tsv'].splitlines(),delimiter='\t'))
        self.assertEqual([(r['slot'],r['name']) for r in rows],
                         [('0x576dfe0','memcpy'),('0x576e0e0','memmove'),('0x576e1f8','memset')])
        self.assertTrue(all(r['st_shndx']=='0' and r['st_value']=='0x0' for r in rows))
        image=copy.copy(self.image); image.relas=dict(image.relas)
        info,addend,off=image.relas[0x576dfe0]
        image.relas[0x576dfe0]=((info & ~0xffffffff)|8,addend,off)
        with self.assertRaisesRegex(ValueError,'GLOB_DAT'): image.dynamic_symbol(0x576dfe0)
        image.relas[0x576dfe0]=((0xffffffff<<32)|6,0,off)
        with self.assertRaisesRegex(ValueError,'index outside'): image.dynamic_symbol(0x576dfe0)
        image=self.mutate(0x3d0,struct.pack('<I',0xffffffff))
        with self.assertRaisesRegex(ValueError,'name outside'): image.dynamic_symbol(0x576dfe0)
        image=copy.copy(self.image)
        shoff=struct.unpack_from('<Q',image.data,40)[0]
        entsize=struct.unpack_from('<H',image.data,58)[0]
        field=shoff+image.secs.index(image.section('.dynsym'))*entsize+40
        image.data=image.data[:field]+struct.pack('<I',0)+image.data[field+4:]
        with self.assertRaisesRegex(ValueError,'string-table link'): image.dynamic_symbol(0x576dfe0)
        # A different valid name is still rejected as a changed binding.
        image=self.mutate(0x3d0,self.image.read(0x418,4))
        with self.assertRaisesRegex(ValueError,'symbol bindings'): subject.outputs(image)

    def test_clone_tables_and_default_payload(self):
        rows=list(__import__('csv').DictReader(self.generated['branch-tables.tsv'].splitlines(),delimiter='\t'))
        hit=[r['target'] for r in rows if r['table']=='0x3bd324']
        fill=[r['target'] for r in rows if r['table']=='0x3bd314']
        self.assertEqual(hit,fill)
        self.assertEqual(hit,['0x1e6b10f','0x1e6b1ba','0x1e6b133','0x1e6b157'])
        const=json.loads(self.generated['constants.json'])
        self.assertEqual(next(r['raw'] for r in const if r['va']=='0x1e629b'),'00')
        self.assertEqual(next(r['raw'] for r in const if r['va']=='0x20ca80'),
                         'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470')
        self.assertEqual(self.image.relative(0x57732d8),0x4e80200)

    def test_default_map_control_group_and_relocation(self):
        self.assertEqual(self.image.relative(0x574ce10),0x202e90)
        self.assertEqual(self.image.read(0x202e90,16),bytes([255])*16)
        image=self.mutate(0x202e9f,b'\x80')
        with self.assertRaisesRegex(ValueError,'control group'): subject.outputs(image)
        image=copy.copy(self.image); image.relas=dict(image.relas)
        info,_,off=image.relas[0x574ce10]
        image.relas[0x574ce10]=(info,0x202e91,off)
        with self.assertRaisesRegex(ValueError,'empty map pointer'): subject.outputs(image)

    def test_in_place_rehash_control_transform(self):
        # The pinned sequence applies signed byte comparison against zero,
        # followed by OR with the 0x80 lane mask.  These are synthetic inputs.
        self.assertEqual(self.image.read(0x207980,16),bytes([128])*16)
        for byte in range(256):
            signed=byte if byte<128 else byte-256
            compared=255 if 0>signed else 0
            self.assertEqual(compared|128,128 if byte<128 else 255)
        for va in (0x4e5a984,0x4e74dc4,0x4e754c4):
            # Replace signed greater-than with equality, keeping a valid shape.
            image=self.mutate(va+3,b'\x74')
            with self.assertRaises(ValueError): subject.outputs(image)
        image=self.mutate(0x20798f,b'\xff')
        with self.assertRaisesRegex(ValueError,'rehash control mask'): subject.outputs(image)

    def test_growth_publishes_table_fields_before_release(self):
        refs=list(__import__('csv').DictReader(self.generated['control-flow.tsv'].splitlines(),delimiter='\t'))
        by_site={r['site']:r for r in refs}
        for store,call in ((0x4e5ae24,0x4e5ae61),(0x4e750c8,0x4e75101),(0x4e75822,0x4e7585c)):
            self.assertLess(store,call)
            self.assertEqual(by_site[hex(call)]['target'],'0x54c8cb0')
            image=self.mutate(store,b'\x90')
            with self.assertRaises(ValueError): subject.outputs(image)

    def test_decoder_truncation_and_unknown_opcode(self):
        for raw in (b'\xe8',b'\x0f\x01',b'\x48\x8b',b'\xc4',b'\x66'*16):
            with self.subTest(raw=raw),self.assertRaises(ValueError): subject.decode(raw,0x1000)
        with self.assertRaisesRegex(ValueError,'branch into instruction'):
            subject.decode(bytes.fromhex('eb014889c0c3'),0x1000)

    def test_exception_boundaries_and_missing_landing(self):
        f=self.image.fde(0x1f651f0)
        rows=subject.decode(self.image.read(f['start'],f['end']-f['start']),f['start'])
        bounds={r['va'] for r in rows}
        sites,raw=subject.call_sites(self.image,f['start'],bounds)
        self.assertTrue(sites and raw)
        pad=int(next(r['landing'] for r in sites if r['landing']),16)
        with self.assertRaises(ValueError): subject.call_sites(self.image,f['start'],bounds-{pad})
        slot=self.image.fde(0x1e6b2c0)
        rows=subject.decode(self.image.read(slot['start'],slot['end']-slot['start']),slot['start'])
        bounds={r['va'] for r in rows}
        for address,replacement in ((0x9963cc,b'\x00'),(0x9963cd,b'\x00'),
                                    (0x9963ce,b'\x00'),(0x9963cf,b'\x03')):
            with self.subTest(address=hex(address)),self.assertRaises(ValueError):
                subject.call_sites(self.mutate(address,replacement),slot['start'],bounds)

    def test_hash_domains_are_distinct(self):
        key=bytes(range(32)); words=(0x123456789abcdef,0xfedcba9876543210,0x1111222233334444)
        self.assertNotEqual(subject.cache_hash(key,'code',*words),subject.cache_hash(key,'slot',*words))
        self.assertEqual(self.image.read(0x27c4cca,4).hex(),'4883f020')
        self.assertEqual(self.image.read(0x27c504a,4).hex(),'4883f004')
        self.assertEqual(self.image.read(0x27c9b20,4).hex(),'4883f004')

    def test_lookup_and_both_rehash_paths_use_the_same_key_words(self):
        rows=list(__import__('csv').DictReader(self.generated['hash-paths.tsv'].splitlines(),delimiter='\t'))
        self.assertEqual(len(rows),9)
        for kind,width,offsets,domain in [('account','20','0,4,8,12','20'),
                                          ('code','32','0,8,16,24','32'),
                                          ('slot','32','0,8,16,24','4')]:
            selected=[r for r in rows if r['kind']==kind]
            self.assertEqual({r['stage'] for r in selected},{'lookup','in-place','growth'})
            self.assertEqual({(r['key_width'],r['key_offsets'],r['domain_immediate']) for r in selected},
                             {(width,offsets,domain)})
        with self.assertRaises(ValueError):
            subject.outputs(self.mutate(0x4e74e57,b'\xd9'))

    def test_growth_capacity_against_independent_bucket_oracle(self):
        # Oracle asks which power of two first has enough usable buckets;
        # the target-derived model uses its separate small-size and 8/7 rule.
        def oracle(request):
            buckets=4
            while (buckets-1 if buckets<8 else buckets-buckets//8) < request:
                buckets*=2
            return buckets
        for request in range(4097):
            self.assertEqual(subject.growth_buckets(request),oracle(request))
        for request in (1<<20,(1<<30)-1,1<<40,(1<<61)-1):
            self.assertEqual(subject.growth_buckets(request),oracle(request))
        for bad in (-1,1<<61,True):
            with self.assertRaises(ValueError): subject.growth_buckets(bad)

    def test_reciprocal_algebra_against_division_oracle(self):
        # This evaluates the recorded multiply-high algebra on synthetic
        # integers, not instructions or captured function bytes.
        magic=int(json.loads(self.generated['reserve-invariants.json'])['reciprocal_magic'],16)
        values=list(range(4097))
        for center in (1<<20,1<<32,1<<60,(1<<61)-1):
            values.extend(x for x in range(center-8,center+9) if 0<=x<1<<61)
        for request in values:
            x=request*8
            high=(x*magic)>>64
            quotient=(((x-high)>>1)+high)>>2
            self.assertEqual(quotient,x//7)

    def test_reserve_layout_boundaries_and_corrupt_stride(self):
        derived=json.loads(self.generated['reserve-invariants.json'])
        self.assertEqual(derived['small_buckets'],[4,8,16])
        self.assertEqual(derived['candidate_reciprocal_divisor'],7)
        self.assertEqual(derived['strides'],{'account':208,'code':96,'slot':64})
        self.assertEqual(derived['max_allocation_bytes'],'0x7ffffffffffffff0')
        for stride,max_power in ((208,55),(96,56),(64,56)):
            buckets=1<<max_power
            self.assertEqual(subject.allocation_layout(buckets,stride),
                             buckets*stride+buckets+16)
            with self.assertRaises(ValueError): subject.allocation_layout(buckets*2,stride)
        for buckets,stride in ((3,64),(8,48),(-1,96),(True,64)):
            with self.assertRaises(ValueError): subject.allocation_layout(buckets,stride)
        with self.assertRaises(ValueError):
            subject.outputs(self.mutate(0x4e5a724,b'\x60'))
        with self.assertRaises(ValueError):
            subject.outputs(self.mutate(0x4e74b15,b'\x92'))

    def test_hash_independent_limb_product(self):
        def limb_fold(a,b):
            mask=(1<<32)-1; parts=[0]*4
            for i in range(2):
                for j in range(2): parts[i+j]+=((a>>(32*i))&mask)*((b>>(32*j))&mask)
            for i in range(3): parts[i+1]+=parts[i]>>32; parts[i]&=mask
            return (parts[0]|parts[1]<<32)^(parts[2]|parts[3]<<32)
        for a in (0,1,(1<<32)-1,1<<32,(1<<63)+1,subject.MASK):
            for b in (0,1,17,(1<<63)-1,subject.MASK):
                self.assertEqual(subject.folded_product(a,b),limb_fold(a,b))
        for kind in ('account','code','slot'):
            key=bytes(range(20 if kind=='account' else 32)); p0,p1,seed=1,2,3
            w=lambda i:int.from_bytes(key[i:i+8],'little')
            b,d=(4,12) if kind=='account' else (16,24)
            domain={'account':20,'code':32,'slot':4}[kind]
            expected=limb_fold(limb_fold(w(8)^p1,w(d)^p0)^limb_fold(w(0)^seed,w(b)^p0)^domain,p0)
            self.assertEqual(subject.cache_hash(key,kind,p0,p1,seed),expected)

    def test_hash_rejects_malformed_inputs(self):
        for key,kind,p0 in [(b'x'*19,'account',1),(b'x'*20,'code',1),(b'x'*32,'slot',-1),(b'x'*32,'other',1)]:
            with self.assertRaises(ValueError): subject.cache_hash(key,kind,p0,2,3)

    def test_probe_compares_entire_key(self):
        for width in (20,32):
            key=bytes(width); h=(23<<57)|3
            controls=[255]*16; controls[3]=23; keys=[None]*16; keys[3]=key
            self.assertEqual(subject.probe(key,h,controls,keys)['hit'],3)
            for bit in range(width*8):
                changed=bytearray(key); changed[bit//8]^=1<<(bit%8); keys[3]=bytes(changed)
                self.assertIsNone(subject.probe(key,h,controls,keys)['hit'])

    def test_probe_tombstones_triangular_steps_and_wrap(self):
        key=bytes(32); h=(9<<57)|60
        controls=[128]*64; keys=[None]*64
        controls[45]=9; keys[45]=key
        result=subject.probe(key,h,controls,keys)
        self.assertEqual(result,dict(hit=45,groups=[60,12,44]))
        controls[61]=255
        self.assertIsNone(subject.probe(key,h,controls,keys)['hit'])

    def test_probe_checks_hits_before_group_empty(self):
        key=bytes(20); controls=[255]*16; controls[8]=7; keys=[None]*16; keys[8]=key
        self.assertEqual(subject.probe(key,7<<57,controls,keys)['hit'],8)

    def test_probe_invalid_and_nonterminating_tables(self):
        for controls,keys in [([255]*15,[None]*15),([129]*16,[None]*16),([128]*16,[None]*16),
                              ([7]+[255]*15,[None]*16)]:
            with self.assertRaises(ValueError): subject.probe(bytes(32),0,controls,keys)

    def test_publish_empty_deleted_mirror_and_growth(self):
        controls=[255]*32
        self.assertEqual(subject.vacant_publish(controls,0,5<<57,10,3),
                         dict(control=5,index=0,mirror=32,growth_left=9,items=4))
        controls[31]=128
        self.assertEqual(subject.vacant_publish(controls,31,5<<57,0,3)['growth_left'],0)
        controls[31]=5
        with self.assertRaises(ValueError): subject.vacant_publish(controls,31,0,1,3)
        with self.assertRaises(ValueError): subject.vacant_publish(controls,0,0,0,3)

    def test_account_negative_cache_and_result_niche(self):
        missing=subject.account_policy(False,255,False)
        self.assertEqual((missing['state'],missing['result'],missing['insert_account']),(0,'tag-5-absent',True))
        present=subject.account_policy(False,0,True)
        self.assertEqual((present['state'],present['result']),(3,'account-info'))
        for state in range(256):
            hit=subject.account_policy(True,state,False)
            self.assertEqual(hit['backend_account_calls'],0)
            self.assertEqual(hit['result']=='tag-5-absent',state==0)

    def test_code_missing_becomes_cached_default(self):
        for tag in range(5):
            p=subject.code_policy(False,tag)
            self.assertEqual(p['default_empty'],tag==4)
            self.assertEqual(p['clone_tag'],1 if tag==4 else tag)
        self.assertEqual(subject.code_policy(True,4)['backend_code_calls'],0)

    def test_storage_hit_ignores_flag_and_backend(self):
        for state in range(256):
            p=subject.storage_policy(True,True,state,False,False,False)
            self.assertEqual((p['source'],p['account_backend_calls'],p['insert_slot']),('cached-slot',0,False))

    def test_storage_suppression_is_low_bit_not_nonzero(self):
        for state in range(256):
            p=subject.storage_policy(True,False,state,False,True,True)
            self.assertEqual(p['account_backend_calls'],state&1)
            self.assertEqual(p['insert_slot'],bool(state&1))
            self.assertTrue(p['slot_entry_probe'])

    def test_storage_new_account_double_check_and_negative_cache(self):
        p=subject.storage_policy(False,False,0,False,True,True)
        self.assertEqual((p['account_backend_calls'],p['state'],p['insert_account'],p['insert_slot']),(1,0,True,False))
        p=subject.storage_policy(False,False,0,True,False,True)
        self.assertEqual((p['account_backend_calls'],p['slot_backend_calls'],p['state'],p['insert_slot'],p['source']),(2,0,3,True,'zero'))
        p=subject.storage_policy(False,False,0,True,True,False)
        self.assertEqual((p['account_backend_calls'],p['slot_backend_calls'],p['source']),(2,1,'zero'))
        self.assertEqual(subject.storage_policy(False,False,0,True,True,True)['source'],'backend-slot')

    def test_policy_invalid_domains(self):
        for call in [lambda:subject.account_policy(1,0,False),lambda:subject.code_policy(False,5),
                     lambda:subject.storage_policy(True,False,256,True,True,True),
                     lambda:subject.storage_policy(False,True,0,True,True,True)]:
            with self.assertRaises(ValueError): call()


if __name__=='__main__': unittest.main()
