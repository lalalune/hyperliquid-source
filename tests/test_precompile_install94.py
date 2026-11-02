"""Target-byte and negative controls for RE-021 installation. MIT license."""
import copy
import hashlib
import json
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import precompile_install94 as p


class InstallationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.im=p.Image(p.TARGET.read_bytes())
        cls.decoded={a:p.decode(cls.im.body(a)[1],a) for a in p.FUNCTIONS}

    def overlay(self, va, replacement):
        original=self.im.read
        def read(at,size):
            raw=bytearray(original(at,size))
            lo=max(at,va); hi=min(at+size,va+len(replacement))
            if lo<hi: raw[lo-at:hi-at]=replacement[lo-va:hi-va]
            return bytes(raw)
        return patch.object(self.im,'read',side_effect=read)

    def test_full_target_digest(self):
        self.assertEqual(hashlib.sha256(self.im.data).hexdigest(),p.DIGEST)

    def test_wrong_digest_rejected_before_elf_parse(self):
        with self.assertRaisesRegex(ValueError,'digest'):p.Image(b'not the pinned image')

    def test_all_selected_fde_bodies_partition_into_shapes(self):
        for a,rows in self.decoded.items():
            f,blob=self.im.body(a)
            self.assertEqual(b''.join(bytes.fromhex(r['hex']) for r in rows),blob)
            self.assertEqual(rows[-1]['va']+rows[-1]['size'],f['end'])
            self.assertEqual((len(blob),hashlib.sha256(blob).hexdigest()),p.BODY_PINS[a])

    def test_body_mutation_rejected(self):
        for a in p.FUNCTIONS:
            with self.subTest(start=hex(a)),self.overlay(a,b'\x90'):
                with self.assertRaisesRegex(ValueError,'body pin'): self.im.body(a)

    def test_missing_fde_rejected(self):
        a=next(iter(p.FUNCTIONS)); by=dict(self.im.by_start);by.pop(a)
        with patch.object(self.im,'by_start',by):
            with self.assertRaisesRegex(ValueError,'missing'):self.im.body(a)

    def test_changed_fde_end_rejected(self):
        a=next(iter(p.FUNCTIONS));by=copy.deepcopy(self.im.by_start);by[a]['end']-=1
        with patch.object(self.im,'by_start',by):
            with self.assertRaisesRegex(ValueError,'body pin'):self.im.body(a)

    def test_invalid_and_cross_section_ranges(self):
        for va,n in [(-1,1),(0x24448a0,0),(1<<64,1),(True,1)]:
            with self.subTest(va=va,n=n),self.assertRaises(ValueError):self.im.read(va,n)
        s=next(s for s in self.im.secs if s['name']=='.text')
        with self.assertRaises(ValueError):self.im.read(s['address']+s['size']-1,2)

    def test_nobits_is_not_file_backed(self):
        s=next(s for s in self.im.secs if s['name']=='.bss')
        with self.assertRaises(ValueError):self.im.read(s['address'],1)

    def test_ambiguous_file_backing_rejected(self):
        s=next(s for s in self.im.secs if s['name']=='.text')
        with patch.object(self.im,'secs',self.im.secs+[dict(s)]):
            with self.assertRaisesRegex(ValueError,'uniquely'):self.im.read(0x24448a0,1)

    def test_truncated_and_unsupported_shapes(self):
        for b in [b'\x48',b'\xe8\x01',b'\x48\x8b\x84',b'\x0f',b'\x62',b'\x0f\xff']:
            with self.subTest(b=b.hex()),self.assertRaises(ValueError):p.decode(b,0x1000)

    def test_branch_into_immediate_rejected(self):
        with self.assertRaisesRegex(ValueError,'branch into'):p.decode(bytes.fromhex('eb01b801000000c3'),0x1000)

    def test_every_semantic_window_rejects_a_changed_byte(self):
        self.assertEqual(len(p.validate_windows(self.im)),len(p.WINDOWS))
        for a,raw,_ in p.WINDOWS:
            b=bytes.fromhex(raw);at=a+len(b)//2
            with self.subTest(window=hex(a)),self.overlay(at,bytes([b[len(b)//2]^1])):
                with self.assertRaisesRegex(ValueError,'semantic window'):p.validate_windows(self.im)

    def test_private_records_have_no_standard_address_collision(self):
        records=p.private_records(self.im,self.decoded[0x24448a0])
        self.assertEqual([r['key_integer'] for r in records],[0x800,0x813]+list(range(0x801,0x813)))
        self.assertTrue(all(r['key_integer']>9 and r['tag']==2 for r in records))
        self.assertEqual(len({r['callback_va'] for r in records}),20)
        self.assertEqual([r['stack_offset'] for r in records],list(range(0x120,0x4e0,48)))

    def test_changed_private_prefix_rejected_without_body_hash(self):
        r=p.private_records(self.im,self.decoded[0x24448a0])[0]
        with self.overlay(r['prefix_va'],b'\x01'):
            with self.assertRaisesRegex(ValueError,'address range'):p.private_records(self.im,self.decoded[0x24448a0])

    def test_changed_private_suffix_and_tag_rejected(self):
        rows=copy.deepcopy(self.decoded[0x24448a0])
        suffix=next(r for r in rows if r['va']==0x2444a65)
        suffix['imm']=0x09000000
        with self.assertRaisesRegex(ValueError,'address range'):p.private_records(self.im,rows)
        rows=copy.deepcopy(self.decoded[0x24448a0]);next(r for r in rows if r['va']==0x2444c5e)['imm']=0
        with self.assertRaisesRegex(ValueError,'value tag'):p.private_records(self.im,rows)

    def test_private_relocation_type_rejected(self):
        relocs=dict(self.im.relocs);slot=0x56a6898;_,value,off=relocs[slot];relocs[slot]=(6,value,off)
        with patch.object(self.im,'relocs',relocs),self.assertRaisesRegex(ValueError,'RELATIVE'):
            p.private_records(self.im,self.decoded[0x24448a0])

    def test_factory_relocation_target_rejected(self):
        relocs=dict(self.im.relocs);slot=0x56a6870;t,v,o=relocs[slot];relocs[slot]=(t,v+1,o)
        with patch.object(self.im,'relocs',relocs),self.assertRaisesRegex(ValueError,'lineage'):
            p.semantic_outputs(self.im,self.decoded)

    def test_all_revision_routes_and_default(self):
        routes,cases=p.revision_routes(self.im,self.decoded[0x2464bd0])
        self.assertEqual(len(cases),15)
        canon=[0,0,2,2,4,5,6,8,8,9,9,11,12,12,12,15,16,17,18,19]+[255]*236
        mode=[0]*6+[1]*3+[2]*2+[3]*6+[4]+[5]*2+[6]*236
        self.assertEqual([r['canonical_revision'] for r in routes],canon)
        self.assertEqual([r['registry_mode'] for r in routes],mode)
        self.assertEqual(sum(len(c['allocation_failures']) for c in cases),90)

    def test_corrupt_revision_dispatch_target_rejected(self):
        raw=struct.pack('<i',0x2464e3c-0x3e2908)
        with self.overlay(0x3e2908,raw),self.assertRaisesRegex(ValueError,'instruction'):
            p.revision_routes(self.im,self.decoded[0x2464bd0])

    def test_corrupt_mode_table_rejected(self):
        with self.overlay(0x3e452c+10,b'\x01'),self.assertRaisesRegex(ValueError,'mode table'):
            p.revision_routes(self.im,self.decoded[0x2464bd0])

    def test_clone_tag_table_preserves_plain_callback_arm(self):
        rows=p.jump_table(self.im,0x3c3ca0,4,0x204836e,self.decoded[0x20482c0])
        self.assertEqual([int(r[-1],16) for r in rows],[0x2048370,0x2048370,0x2048380,0x20483a0])

    def test_clone_tag_table_corrupt_target_rejected(self):
        with self.overlay(0x3c3ca0,struct.pack('<i',0x2048371-0x3c3ca0)),self.assertRaises(ValueError):
            p.jump_table(self.im,0x3c3ca0,4,0x204836e,self.decoded[0x20482c0])

    def test_exception_sites_bind_factory_install_unwind(self):
        sites,header=p.exception_sites(self.im,0x244fe00,self.decoded[0x244fe00])
        self.assertIn('0x244feac',[r[6] for r in sites])
        self.assertIn('0x244fec6',[r[6] for r in sites])
        self.assertEqual(header['type_encoding'],0x9b)

    def test_exception_encoding_rejected(self):
        f=self.im.by_start[0x244fe00];off=self.im.offset(f['lsda'],1)
        # One temporary mutable image; no binary file is modified.
        data=bytearray(self.im.data);data[off]=0
        with patch.object(self.im,'data',data),self.assertRaisesRegex(ValueError,'landing-pad base'):
            p.exception_sites(self.im,0x244fe00,self.decoded[0x244fe00])

    def test_allocation_boundaries(self):
        expected={0:4,3:4,4:8,7:8,8:16,14:16,15:32,28:32,29:64,56:64,57:128}
        for requested,buckets in expected.items():
            actual=p.allocation_plan(requested)
            self.assertEqual(actual['buckets'],buckets)
            self.assertEqual(actual['allocation_bytes'],49*buckets+16)
            self.assertGreaterEqual(actual['growth_left'],requested)

    def test_allocation_against_independent_minimum_bucket_oracle(self):
        for requested in range(4097):
            buckets=4
            while (buckets-1 if buckets<8 else buckets*7//8)<requested:buckets*=2
            self.assertEqual(p.allocation_plan(requested)['buckets'],buckets)

    def test_allocation_overflow_and_bad_domain(self):
        for value in [1<<61,(1<<64)-1]:self.assertEqual(p.allocation_plan(value)['outcome'],'capacity-overflow')
        self.assertEqual(p.allocation_plan(1<<60)['outcome'],'layout-overflow')
        for value in [-1,1<<64,True,1.0]:
            with self.assertRaises(ValueError):p.allocation_plan(value)

    def test_semantic_windows_start_and_end_at_instruction_boundaries(self):
        starts={r['va'] for rows in self.decoded.values() for r in rows}
        ends={r['va']+r['size'] for rows in self.decoded.values() for r in rows}
        for a,h,_ in p.WINDOWS:
            self.assertIn(a,starts)
            self.assertIn(a+len(bytes.fromhex(h)),ends)

    def test_concrete_hook_to_materializer_to_context_binding(self):
        b=p.entry_binding(self.im,self.decoded)
        self.assertEqual([r['target_va'] for r in b['hook_slots']],[0x244fe00,0x24b6590,0x24b6590])
        self.assertEqual(b['context_factory_data_offset']-b['context_header_bytes'],0x48)
        self.assertEqual(b['context_factory_vtable_offset']-b['context_header_bytes'],0x50)
        self.assertEqual(b['factory_target_va'],0x24448a0)
        self.assertEqual(b['old_map_cleanup_base_offset'],0xe8)
        self.assertEqual(b['required_gate_tag'],5)

    def test_corrupt_borrowed_hook_relocation_rejected(self):
        relocs=dict(self.im.relocs);slot=0x56b8060;t,v,o=relocs[slot];relocs[slot]=(t,0x24448a0,o)
        with patch.object(self.im,'relocs',relocs),self.assertRaisesRegex(ValueError,'hook relocation'):
            p.entry_binding(self.im,self.decoded)

    def test_wrong_factory_field_and_failure_target_rejected(self):
        decoded=copy.deepcopy(self.decoded)
        next(r for r in decoded[0x25154a0] if r['va']==0x251550e)['mem']['disp']+=8
        with self.assertRaisesRegex(ValueError,'offset composition'):p.entry_binding(self.im,decoded)
        decoded=copy.deepcopy(self.decoded)
        next(r for r in decoded[0x25154a0] if r['va']==0x25154fb)['target']=0x2515501
        with self.assertRaisesRegex(ValueError,'failure target'):p.entry_binding(self.im,decoded)

    def test_revision_snapshot_differs_from_raw_requested_byte(self):
        routes,_=p.revision_routes(self.im,self.decoded[0x2464bd0])
        a=p.revision_transition(routes,9,10)
        self.assertEqual((a['replay'],a['captured_revision'],a['handler_revision'],a['registry_mode']),(True,9,10,2))
        b=p.revision_transition(routes,10,9)
        self.assertEqual((b['replay'],b['captured_revision'],b['handler_revision']),(False,9,9))
        for initial in range(256):
            for requested in range(256):
                r=p.revision_transition(routes,initial,requested)
                self.assertEqual(r['captured_revision'],routes[requested]['canonical_revision'])
                self.assertEqual(r['handler_revision'],requested)
                self.assertEqual(r['replay'],routes[initial]['canonical_revision']!=requested)
        for bad in [-1,256,True,1.0]:
            with self.assertRaises(ValueError):p.revision_transition(routes,bad,0)
            with self.assertRaises(ValueError):p.revision_transition(routes,0,bad)

    def test_borrowed_hook_and_consumer_unwind_have_actual_lsda_records(self):
        sites,_=p.exception_sites(self.im,0x24b6590,self.decoded[0x24b6590])
        self.assertIn('0x24b663c',[r[6] for r in sites])
        self.assertIn('0x24b6656',[r[6] for r in sites])
        sites,_=p.exception_sites(self.im,0x25154a0,self.decoded[0x25154a0])
        factory_site=next(r for r in sites if int(r[3],16)<=0x251553c<int(r[5],16))
        self.assertEqual(factory_site[6],'')
        auxiliary_site=next(r for r in sites if int(r[3],16)<=0x251554a<int(r[5],16))
        self.assertEqual(auxiliary_site[6],'0x25173bb')

    def test_capture_slots_match_private_callbacks(self):
        records=p.private_records(self.im,self.decoded[0x24448a0])
        edges=p.capture_edges(self.decoded,records)
        self.assertEqual([r['factory_payload_offset'] for r in edges],list(range(0,160,8)))
        self.assertEqual([r['key_hex'] for r in edges],[r['key_hex'] for r in records])
        self.assertEqual(len({r['record_data_store_va'] for r in edges}),20)
        self.assertTrue(all(len(r['mov_def_use_sites'])>=4 for r in edges))

    def test_capture_source_permutation_rejected(self):
        records=p.private_records(self.im,self.decoded[0x24448a0])
        decoded=copy.deepcopy(self.decoded)
        next(r for r in decoded[0x247d7f0] if r['va']==0x247d807)['mem']['disp']=0
        with self.assertRaisesRegex(ValueError,'capture copy order'):p.capture_edges(decoded,records)
        decoded=copy.deepcopy(self.decoded)
        next(r for r in decoded[0x24448a0] if r['va']==0x2444c8d)['reg']=5
        with self.assertRaisesRegex(ValueError,'record capture order'):p.capture_edges(decoded,records)

    def test_counter_and_rehash_data_constants_and_corruption(self):
        records=p.literal_records(self.im,self.decoded)
        by={r['va']:r for r in records}
        self.assertEqual(by[0x203480]['bytes'],'00'*8+'ff'*8)
        self.assertEqual(by[0x207980]['bytes'],'80'*16)
        for va in (0x203480,0x207980):
            original=self.im.read(va,1)
            with self.overlay(va,bytes([original[0]^1])),self.assertRaisesRegex(ValueError,'vector constant'):
                p.literal_records(self.im,self.decoded)

    def test_generation_matches_retained_evidence(self):
        out=p.collect(self.im)
        packet=ROOT/'research/work-items/RE-021-precompile-install-94'
        for name,data in out.items():
            self.assertEqual(data,(packet/name).read_bytes(),name)
        summary=json.loads(out['summary.json'])
        self.assertEqual(summary['functions'],len(p.FUNCTIONS))
        self.assertEqual(summary['code_bytes'],sum(n for n,_ in p.BODY_PINS.values()))


if __name__=='__main__':unittest.main()
