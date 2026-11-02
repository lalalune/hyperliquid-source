"""Target-grounded and adversarial engine evidence tests (MIT; stdlib only)."""
from contextlib import contextmanager, ExitStack
from collections import Counter
import copy
import hashlib
import importlib.util
import io
import json
import mmap
from pathlib import Path
import re
import shutil
import struct
import tempfile
import unittest
from unittest import mock

from tools import abci_engine_inventory as n

PACKET = n.ROOT/'research/work-items/abci-engine-inventory-94'
spec = importlib.util.spec_from_file_location('abci_engine_verify', PACKET/'verify.py')
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)


@contextmanager
def no_external_effects():
    with ExitStack() as stack:
        for name in ('subprocess.Popen', 'subprocess.run', 'os.system',
                     'socket.socket', 'socket.create_connection', 'urllib.request.urlopen'):
            stack.enter_context(mock.patch(name, side_effect=AssertionError('external effect forbidden')))
        yield


class SmallImage:
    def __init__(self, raw, base=0x1000): self.raw, self.base = raw, base

    def read(self, va, size):
        offset = va-self.base
        n.require(size > 0 and offset >= 0 and offset+size <= len(self.raw), 'synthetic read outside bytes')
        return self.raw[offset:offset+size]

    def evidence(self, va, size):
        return {'va': hex(va), 'file_offset': hex(va-self.base), 'section': 'synthetic',
                'bytes': self.read(va, size).hex()}


def decode_small(raw):
    image = SmallImage(raw)
    return image, n.decode_fde(image, {'start': image.base, 'end': image.base+len(raw)})


class DecoderTests(unittest.TestCase):
    def test_lea_signed_displacements_all_registers(self):
        for reg in range(16):
            for disp in (-2147483648, -7, 0, 2147483647):
                raw = bytes([0x4c if reg >= 8 else 0x48, 0x8d, 5+8*(reg%8)])+struct.pack('<i',disp)
                self.assertEqual(n.decode_lea(raw,0x100000000),(0x100000007+disp,reg))

    def test_lea_wrong_width_modrm_truncation_shift(self):
        for raw in ('488d05000000','408d0500000000','488d0400000000','488d050000000090','8d0500000000'):
            with self.subTest(raw=raw), self.assertRaises(ValueError): n.decode_lea(bytes.fromhex(raw),0)

    def test_rel32_signed_calls_and_jumps(self):
        for opcode in (0xe8,0xe9):
            for disp in (-2147483648,-5,0,2147483647):
                raw=bytes([opcode])+struct.pack('<i',disp)
                self.assertEqual(n.decode_rel32_transfer(raw,0x100000000),0x100000005+disp)
        for raw in ('e800','eb00000000','ff00000000','e80000000090'):
            with self.assertRaises(ValueError):n.decode_rel32_transfer(bytes.fromhex(raw),0)

    def test_engine_added_forms_every_truncation(self):
        for text in ('664521c1','660f76d2'):
            raw=bytes.fromhex(text)
            self.assertEqual(n.decode_instruction(raw)['raw'],raw)
            for end in range(len(raw)):
                with self.subTest(raw=text,end=end),self.assertRaises(ValueError):n.decode_instruction(raw[:end])
        for raw in ('66452101','660f7610','f2660f76d2','66664521c1','f0664521c1'):
            with self.subTest(raw=raw),self.assertRaises(ValueError):n.decode_instruction(bytes.fromhex(raw))

    def test_modrm_sib_immediate_prefix_boundaries(self):
        for text in ('48898c24c8000000','48c744245819000000','49c785100200000e000000',
                     '64488b1c2500000000','6666662e0f1f840000000000','41b812000000',
                     '48b88877665544332211','f0480fb10e','0f8501000000','f390'):
            raw=bytes.fromhex(text)
            self.assertEqual(n.decode_instruction(raw)['raw'],raw)
            for end in range(len(raw)):
                with self.subTest(raw=text,end=end),self.assertRaises(ValueError):n.decode_instruction(raw[:end])

    def test_unknown_reserved_conflicting_and_overlong_encodings(self):
        for text in ('c5f877','62f17c4858c0','ff38','c7c800000000','488dc0',
                     'f0833801','f090','f2f390','666601c0','f0f20100','0f710001','66'*14+'0f1f00'):
            with self.subTest(raw=text),self.assertRaises(ValueError):n.decode_instruction(bytes.fromhex(text))

    def test_embedded_lea_and_call_not_instruction_boundaries(self):
        for operand in ('488d050000000090','e800000000909090'):
            image,insns=decode_small(b'\x48\xb8'+bytes.fromhex(operand)+b'\xc3')
            self.assertEqual([x['site'] for x in insns],[0x1000,0x100a])
            with self.assertRaises(ValueError):n.core.verified_lea(image,insns,0x1002,0x1009)
            edges,_,_=n.edges_and_transfers(image,{0x1000:insns},{0x1000:{'end':0x100b}})
            self.assertEqual(edges,[])

    def test_internal_branch_to_operand_and_truncated_fde_rejected(self):
        for raw in ('eb0148b80000000000000000c3','90488d05'):
            with self.assertRaises(ValueError):decode_small(bytes.fromhex(raw))

    def test_immediate_and_pointer_store_operands(self):
        self.assertEqual(n.decode_mov_immediate(bytes.fromhex('41b9ffffffff')),
                         {'register':9,'value':0xffffffff,'width':32})
        self.assertEqual(n.decode_mov_immediate(bytes.fromhex('48c74424f8ffffffff')),
                         {'memory':{'base_register':4,'displacement':-8},'width':64,'value':-1})
        self.assertEqual(n.decode_pointer_store(bytes.fromhex('4c89b310020000')),
                         ({'base_register':3,'displacement':528},14))
        for text in ('c744245819000000','48c74c245819000000','48c7050000000019000000',
                     '48c744645819000000','48c74424581900000000','48b88877665544332211'):
            with self.subTest(raw=text),self.assertRaises(ValueError):n.decode_mov_immediate(bytes.fromhex(text))

    def test_all_mov_and_store_truncations(self):
        for text,fn in (('49c786280200000b000000',n.decode_mov_immediate),
                        ('41b910000000',n.decode_mov_immediate),('4c89b310020000',n.decode_pointer_store)):
            raw=bytes.fromhex(text)
            for end in range(len(raw)):
                with self.subTest(raw=text,end=end),self.assertRaises(ValueError):fn(raw[:end])

    def test_adjacent_pointer_length_positive_and_corruptions(self):
        raw=bytes.fromhex('488d050e000000488944244048c744244804000000')+b'test'
        image=SmallImage(raw)
        ins=n.decode_fde(image,{'start':0x1000,'end':0x1015})
        self.assertEqual(n.pointer_length_pair(image,ins,0,b'test')['length'],4)
        for offset,value in ((9,0x4c),(15,0x50),(16,5),(17,5),(0,0x4c),(12,0x40)):
            bad=bytearray(raw);bad[offset]=value
            with self.subTest(offset=offset),self.assertRaises(ValueError):
                altered=SmallImage(bytes(bad))
                seq=n.decode_fde(altered,{'start':0x1000,'end':0x1015})
                n.pointer_length_pair(altered,seq,0,b'test')

    def test_local_rdx_ecx_length_and_clobbers(self):
        raw=bytes.fromhex('488d1505000000b904000000')+b'test'
        image=SmallImage(raw);ins=n.decode_fde(image,{'start':0x1000,'end':0x100c})
        self.assertEqual(n.pointer_length_pair(image,ins,0,b'test')['kind'],'local_register_pointer_length')
        for offset,value in ((8,3),(7,0xba),(2,0x0d)):
            bad=bytearray(raw);bad[offset]=value;altered=SmallImage(bad)
            with self.subTest(offset=offset),self.assertRaises(ValueError):
                seq=n.decode_fde(altered,{'start':0x1000,'end':0x100c})
                n.pointer_length_pair(altered,seq,0,b'test')
        gap=copy.deepcopy(ins);gap[1]['site']+=1
        with self.assertRaises(ValueError):n.pointer_length_pair(image,gap,0,b'test')

    def test_counted_chunks_delimiters_length_and_containment(self):
        image=SmallImage(b'\xc0\x03one\xc0\x03two\x00')
        proof=n.counted_fragment(image,0x1000,0x1007,b'two')
        self.assertEqual([c['length'] for c in proof['chunks']],[3,3])
        self.assertEqual(proof['chunks'][-1]['delimiter'],'0x0')
        for raw,occ,needle in ((b'\x03one\x00\x03two\xc0',0x1006,b'two'),
                               (b'\x03one\xc0\x03two\x00',0x1003,b'e\xc0\x03t'),
                               (b'\x04one\xc0',0x1001,b'one'),(b'\x03o\xffe\xc0',0x1001,b'o'),
                               (b'\x03one!',0x1001,b'one'),(b'\x03on',0x1001,b'on'),
                               (b'\x01a\xc0'*4+b'\x01b\x00',0x100d,b'b')):
            with self.subTest(raw=raw),self.assertRaises(ValueError):n.counted_fragment(SmallImage(raw),0x1000,occ,needle)

    def test_boundary_instruction_metadata_cannot_be_forged(self):
        image,ins=decode_small(b'\x90')
        ins[0]['kind']='call_rel32'
        with self.assertRaises(ValueError):n.instruction_evidence(image,ins[0])


class TargetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.handle=(n.ROOT/n.TARGET).open('rb')
        cls.data=mmap.mmap(cls.handle.fileno(),0,access=mmap.ACCESS_READ)
        with no_external_effects():cls.result=n.build(cls.data)
        cls.e=cls.result['inventory.json'];cls.image=n.Image(cls.data)
        cls.relocations=n.relative_relocations(cls.image)
        cls.locs=n.locations(cls.image,cls.relocations)
        cls.scoped={int(f['start'],16):{'start':int(f['start'],16),'end':int(f['end_exclusive'],16)} for f in cls.e['fdes']}
        cls.decoded={s:n.decode_fde(cls.image,f) for s,f in cls.scoped.items()}
        cls.attrs=n.attribution(cls.image,cls.decoded,cls.relocations)

    @classmethod
    def tearDownClass(cls):cls.data.close();cls.handle.close()

    @contextmanager
    def mutated(self, offset, raw):
        with mmap.mmap(self.handle.fileno(),0,access=mmap.ACCESS_COPY) as data:
            data[offset:offset+len(raw)]=raw
            yield n.Image(data)

    def offset(self,va):return self.image.mapping(va)[1]

    def test_exact_regeneration_and_derived_reports(self):
        v.verify_outputs(PACKET,n,self.result)
        v.verify_manifest(PACKET)

    def test_census_every_location_and_lea_redecoded(self):
        self.assertEqual(len(self.locs),20)
        self.assertEqual(len(self.e['location_leas']),28)
        for x in self.e['location_leas']:
            slot,start=int(x['location'],16),int(x['owner'],16)
            site=int(x['instruction']['va'],16)
            _,reg=n.core.verified_lea(self.image,self.decoded[start],site,slot)
            self.assertEqual(reg,x['destination_register'])
            loc=self.locs[slot]
            self.assertEqual(bytes.fromhex(loc['path_bytes']['bytes']),n.PREFIX+n.SCOPE)
            self.assertEqual(loc['path_length'],len(n.PREFIX+n.SCOPE))
            self.assertEqual(n.decode_location(self.image,slot,self.relocations[slot]),loc)

    def test_duplicate_coordinates_not_collapsed(self):
        pairs=Counter((r['line'],r['column']) for r in self.locs.values())
        self.assertEqual(sum(pairs.values()),20);self.assertEqual(len(pairs),12)
        self.assertEqual(pairs[(368,25)],2)
        self.assertEqual([r['va'] for r in self.locs.values() if r['line']==279],['0x571c948'])

    def test_wrong_digest_gate_precedes_parsing(self):
        for data in (b'',b'wrong target'):
            with mock.patch.object(n,'Image',side_effect=AssertionError('parsed unauthenticated input')):
                with self.assertRaisesRegex(ValueError,'SHA-256'):n.build(data)
        with self.mutated(self.offset(0x569dbe8)+16,struct.pack('<I',369)) as image:
            with self.assertRaisesRegex(ValueError,'SHA-256'):n.build(image.data)

    def test_wrong_digest_cli_writes_no_output(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t);(p/'fake').write_bytes(b'not-node94')
            with no_external_effects(),mock.patch('sys.stderr',new=io.StringIO()),self.assertRaises(SystemExit) as exc:
                n.main(['--binary',str(p/'fake'),'--out',str(p/'output')])
            self.assertEqual(exc.exception.code,1);self.assertFalse((p/'output').exists())

    def test_location_corrupt_fields_below_digest(self):
        slot=0x569dbe8;off=self.offset(slot)
        for delta,raw in ((0,struct.pack('<Q',1)),(8,struct.pack('<Q',0)),(8,struct.pack('<Q',46)),
                          (16,struct.pack('<I',0)),(20,struct.pack('<I',0))):
            with self.subTest(delta=delta),self.mutated(off+delta,raw) as image,self.assertRaises(ValueError):
                n.decode_location(image,slot,self.relocations[slot])

    def test_path_and_slot_alignment_corruption(self):
        slot=0x569dbe8;rel=self.relocations[slot]
        with self.mutated(self.offset(rel['target']),b'!') as image,self.assertRaises(ValueError):
            n.decode_location(image,slot,rel)
        with self.assertRaises(ValueError):n.decode_location(self.image,slot+1,rel)
        for field,value in (('target',rel['target']+1),('target',0x2209d40)):
            bad={**rel,field:value}
            with self.assertRaises(ValueError):n.decode_location(self.image,slot,bad)

    def test_relocation_symbol_duplicate_and_addend_rejected(self):
        rel=self.relocations[0x569dbe8];off=rel['entry_file_offset']
        for delta,raw in ((8,struct.pack('<Q',(1<<32)|8)),(16,struct.pack('<q',-1)),
                          (0,struct.pack('<Q',0x569dc00))):
            with self.subTest(delta=delta),self.mutated(off+delta,raw) as image,self.assertRaises(ValueError):
                n.relative_relocations(image)

    def test_legal_location_change_and_missing_record_fail_pinned_census(self):
        for action in ('line','remove'):
            bad=copy.deepcopy(self.e)
            if action=='line':bad['locations'][0]['line']+=1
            else:bad['locations'].pop()
            with self.assertRaisesRegex(ValueError,'Location census'):v.verify_facts(bad)
        slot=0x569dbe8;rel=self.relocations[slot]
        with self.mutated(self.offset(slot)+16,struct.pack('<I',369)) as image:
            changed=n.decode_location(image,slot,rel)
            bad=copy.deepcopy(self.e);bad['locations'][0].update(changed)
            with self.assertRaises(ValueError):v.verify_facts(bad)
        reduced=dict(self.relocations);reduced.pop(slot)
        self.assertEqual(len(n.locations(self.image,reduced)),19)

    def section_header(self,name):
        return struct.unpack_from('<Q',self.data,40)[0]+self.image.sections.index(self.image.by_name[name])*struct.unpack_from('<H',self.data,58)[0]

    def test_missing_every_required_section(self):
        for name in ('.text','.rodata','.data.rel.ro','.rela.dyn','.eh_frame','.eh_frame_hdr'):
            off=self.section_header(name)
            with mmap.mmap(self.handle.fileno(),0,access=mmap.ACCESS_COPY) as data:
                struct.pack_into('<I',data,off,0)
                with self.subTest(section=name),self.assertRaises(ValueError):n.Image(data)

    def test_nonallocated_nobits_nonexecutable_and_wrong_machine(self):
        for off,raw in ((self.section_header('.rodata')+4,struct.pack('<I',8)),
                        (self.section_header('.text')+8,struct.pack('<Q',2)),
                        (self.section_header('.rodata')+8,struct.pack('<Q',0)),(18,struct.pack('<H',3))):
            with mmap.mmap(self.handle.fileno(),0,access=mmap.ACCESS_COPY) as data:
                data[off:off+len(raw)]=raw
                with self.assertRaises(ValueError):n.Image(data)

    def test_missing_fde_encoding_and_changed_extent(self):
        hdr=self.image.by_name['.eh_frame_hdr']['offset']
        with self.mutated(hdr,b'\x02') as image,self.assertRaises(ValueError):n.Fdes(image)
        f=self.e['fdes'][0];fde=int(f['fde_record']['va'],16)
        with self.mutated(self.offset(fde)+12,struct.pack('<I',0)) as image,self.assertRaises(ValueError):n.Fdes(image)

    def test_fde_index_start_disagreement(self):
        row=self.e['fdes'][0]['unwind_index_entry'];off=int(row['file_offset'],16)
        old=struct.unpack_from('<i',self.data,off)[0]
        with self.mutated(off,struct.pack('<i',old+1)) as image,self.assertRaises(ValueError):n.Fdes(image)

    def test_shifted_and_changed_lea_displacement(self):
        row=self.e['location_leas'][0];site=int(row['instruction']['va'],16);start=int(row['owner'],16);slot=int(row['location'],16)
        with self.assertRaises(ValueError):n.core.verified_lea(self.image,self.decoded[start],site+1,slot)
        off=self.offset(site)+3;disp=struct.unpack_from('<i',self.data,off)[0]
        with self.mutated(off,struct.pack('<i',disp+1)) as image:
            seq=n.decode_fde(image,self.scoped[start])
            with self.assertRaises(ValueError):n.core.verified_lea(image,seq,site,slot)

    def test_complete_transcripts_match_actual_bytes(self):
        for f,t in zip(self.e['fdes'],self.result['instructions.json']['fdes']):
            raw=b''.join(bytes.fromhex(row[1]) for row in t['instructions'])
            self.assertEqual(len(raw),f['size']);self.assertEqual(n.sha(raw),f['code_sha256'])
            self.assertEqual(raw,self.image.read(int(f['start'],16),f['size']))
            cursor=0
            for offset,hexbytes,kind in t['instructions']:
                self.assertEqual(int(offset,16),cursor)
                x=n.decode_instruction(bytes.fromhex(hexbytes),base=int(f['start'],16)+cursor)
                self.assertEqual(x['kind'],kind);cursor+=len(x['raw'])

    def test_every_literal_binding_redecodes(self):
        probes={x['id']:x['needle'] for x in n.probes()}
        for d in self.e['diagnostics']:
            for a in d['anchors']:
                start=int(a['owner'],16);seq=self.decoded[start];site=int(a['lea']['va'],16)
                index=next(i for i,x in enumerate(seq) if x['site']==site)
                needle=probes[d['id']]
                if a['kind']=='counted_ascii_chunks':
                    proof=n.counted_fragment(self.image,int(a['anchor'],16),int(a['occurrence'],16),needle)
                else:proof=n.pointer_length_pair(self.image,seq,index,needle)
                for k,value in proof.items():self.assertEqual(a[k],value)
                self.assertTrue(all(r['location']['path']==n.SCOPE.decode() for r in a['local_context']['locations']))

    def test_all_pointer_length_anchors_reject_corrupted_lengths(self):
        probes={x['id']:x['needle'] for x in n.probes()}
        for d in self.e['diagnostics']:
            for a in d['anchors']:
                if a['kind']=='counted_ascii_chunks':continue
                start=int(a['owner'],16);seq=self.decoded[start];site=int(a['lea']['va'],16)
                i=next(i for i,x in enumerate(seq) if x['site']==site)
                length_insn=next(x for x in a['setup'][1:] if x['kind']=='mov_imm' and n.decode_mov_immediate(bytes.fromhex(x['bytes']))['value']==a['length'])
                off=int(length_insn['file_offset'],16)+len(bytes.fromhex(length_insn['bytes']))-4
                with self.subTest(site=hex(site)),self.mutated(off,struct.pack('<I',a['length']+1)) as image:
                    changed=n.decode_fde(image,self.scoped[start])
                    with self.assertRaises(ValueError):n.pointer_length_pair(image,changed,i,probes[d['id']])

    def test_all_counted_anchors_reject_changed_length_and_delimiter(self):
        probes={x['id']:x['needle'] for x in n.probes()}
        for d in self.e['diagnostics']:
            for a in d['anchors']:
                if a['kind']!='counted_ascii_chunks':continue
                for chunk in a['chunks']:
                    offset=int(chunk['record']['file_offset'],16)
                    for off in (offset,offset+chunk['length']+1):
                        with self.subTest(site=a['lea']['va'],off=off),self.mutated(off,b'\xff') as image,self.assertRaises(ValueError):
                            n.counted_fragment(image,int(a['anchor'],16),int(a['occurrence'],16),probes[d['id']])

    def test_foreign_location_blocks_fde_only_false_binding(self):
        d=next(x for x in self.e['diagnostics'] if x['id']=='binary-2')
        self.assertEqual(d['status'],'present-but-unbound');self.assertEqual(d['anchors'],[])
        foreign=[r for r in d['rejected_candidates'] if 'foreign' in r['reason']]
        self.assertEqual(len(foreign),6)
        self.assertTrue(all(any(x['location']['path']=='l1/src/exchange/exchange.rs' for x in r['local_context']['locations']) for r in foreign))
        self.assertEqual(sum(not a['only_exact_file_locations_observed'] for a in self.attrs.values()),6)

    def test_short_tokens_not_padded_with_substring_anchors(self):
        for identifier,count in (('reference-line-35',3),('binary-12',1),('binary-13',1),('binary-14',1)):
            d=next(x for x in self.e['diagnostics'] if x['id']==identifier)
            self.assertEqual(len(d['anchors']),count)
            self.assertTrue(all(a['kind']!='counted_ascii_chunks' for a in d['anchors']))
        tag=next(x for x in self.e['diagnostics'] if x['id']=='binary-15')
        self.assertEqual(tag['status'],'present-but-unbound')

    def test_absent_reference_hints_never_copied(self):
        packed=b''.join((PACKET/f).read_bytes() for f in n.OUTPUTS)
        by_id={p['id']:p for p in n.probes()}
        absent=[x for x in self.e['diagnostics'] if x['status']=='absent']
        self.assertEqual(len(absent),7)
        for d in absent:
            probe=by_id[d['id']]['needle']
            self.assertEqual(self.data.find(probe),-1)
            self.assertNotIn(probe,packed)
            self.assertEqual(n.sha(probe),d['probe_sha256']);self.assertEqual(len(probe),d['probe_length'])

    def test_constant_numeric_matches_do_not_promote_roles(self):
        self.assertEqual(len(self.e['constants']),5)
        for c in self.e['constants']:
            self.assertEqual(c['status'],'unresolved');self.assertEqual(c['anchors'],[])
            for occurrence in c['decoded_mov_occurrences_not_bindings']:
                raw=bytes.fromhex(occurrence['instruction']['bytes'])
                self.assertEqual(n.decode_mov_immediate(raw),occurrence['operand'])
        bad=copy.deepcopy(self.e);bad['constants'][0]['status']='bound'
        with self.assertRaises(ValueError):v.verify_facts(bad)

    def test_direct_edges_exact_entry_and_bytes(self):
        self.assertEqual(len(self.e['call_edges']),4)
        for e in self.e['call_edges']:
            site=int(e['instruction']['va'],16);raw=self.image.read(site,5)
            self.assertEqual(raw.hex(),e['instruction']['bytes'])
            self.assertEqual(n.decode_rel32_transfer(raw,site),int(e['callee'],16))
            self.assertEqual(site+5+e['signed_displacement'],int(e['callee'],16))
            self.assertIn(int(e['caller'],16),self.scoped)
            self.assertIn(int(e['callee'],16),set(self.scoped)|set(n.NAMED))

    def test_actual_rel32_target_shift_loses_qualified_edge(self):
        for edge in self.e['call_edges']:
            site=int(edge['instruction']['va'],16);start=int(edge['caller'],16);disp=edge['signed_displacement']
            with self.mutated(self.offset(site)+1,struct.pack('<i',disp+1)) as image:
                changed={start:n.decode_fde(image,self.scoped[start])}
                edges,transfers,_=n.edges_and_transfers(image,changed,self.scoped)
                self.assertNotIn(hex(site),[e['instruction']['va'] for e in edges])
                row=next(t for t in transfers if t['instruction']['va']==hex(site))
                self.assertEqual(row['disposition'],'external_unresolved')

    def test_transfer_accounting_and_counts_recomputed(self):
        edges,transfers,counts=n.edges_and_transfers(self.image,self.decoded,self.scoped)
        self.assertEqual((edges,transfers,counts),(self.e['call_edges'],self.e['rel32_transfers'],self.e['transfer_counts']))
        self.assertEqual(sum(counts.values()),sum(x['kind'] in ('call_rel32','jmp_rel32','call_indirect','jmp_indirect') for s in self.decoded.values() for x in s))
        metrics=self.e['metrics'];ds=self.e['diagnostics']
        derived={'locations':len(self.e['locations']),'location_leas':len(self.e['location_leas']),
                 'scoped_fdes':len(self.e['fdes']),'scoped_fde_bytes':sum(f['size'] for f in self.e['fdes']),
                 'decoded_instructions':sum(map(len,self.decoded.values())),
                 'diagnostics_bound':sum(d['status']=='bound' for d in ds),
                 'diagnostics_unresolved':sum(d['status']=='present-but-unbound' for d in ds),
                 'diagnostics_absent':sum(d['status']=='absent' for d in ds),
                 'pointer_length_anchors':sum(a['kind']!='counted_ascii_chunks' for d in ds for a in d['anchors']),
                 'counted_fragment_anchors':sum(a['kind']=='counted_ascii_chunks' for d in ds for a in d['anchors']),
                 'anchors_with_local_engine_location':sum(bool(a['local_context']['locations']) for d in ds for a in d['anchors'])}
        for k,value in derived.items():self.assertEqual(metrics[k],value)

    def test_prior_owners_revalidate_without_reclaiming(self):
        self.assertEqual(sum(o['in_scope'] for p in self.e['prior_work'] for o in p['owners']),5)
        for p in self.e['prior_work']:
            self.assertEqual(n.sha((n.ROOT/p['path']).read_bytes()),p['sha256'])
            for o in p['owners']:
                start,end=int(o['start'],16),int(o['end_exclusive'],16)
                self.assertEqual(n.sha(self.image.read(start,end-start)),o['sha256'])
                self.assertTrue(o['revalidated'])
        self.assertEqual([f['start'] for f in self.e['named_callees']],['0x3bade80'])

    def test_seed_reference_and_producer_identities(self):
        self.assertEqual(n.sha(n.reference_bytes()),n.REFERENCE_SHA256)
        self.assertTrue(all(x['exact_fde_start'] and x['references_engine_location'] for x in self.e['seed_checks']))
        for p,digest in self.e['producer_sources_sha256'].items():self.assertEqual(n.sha((n.ROOT/p).read_bytes()),digest)
        with mock.patch.object(n,'REFERENCE_SHA256','0'*64),self.assertRaises(ValueError):n.probes()

    def test_cli_byte_identical_without_external_tools(self):
        with tempfile.TemporaryDirectory() as tmp,no_external_effects(),mock.patch('sys.stdout',new=io.StringIO()):
            n.main(['--out',tmp])
            for name in n.OUTPUTS:self.assertEqual((Path(tmp)/name).read_bytes(),(PACKET/name).read_bytes())

    def test_verifier_runs_without_tools_network_or_target_execution(self):
        with no_external_effects(),mock.patch('sys.stdout',new=io.StringIO()) as stream:v.main()
        self.assertIn('PASS:',stream.getvalue())

    def test_report_metrics_and_location_table_drift_rejected(self):
        for name,old,new in (('README.md','| locations | 20 |','| locations | 21 |'),
                             ('RESULT.md','| call_edges | 4 |','| call_edges | 5 |'),
                             ('README.md','368:25','368:26')):
            with tempfile.TemporaryDirectory() as t:
                p=Path(t)
                for f in ('README.md','RESULT.md'):shutil.copyfile(PACKET/f,p/f)
                text=(p/name).read_text();self.assertIn(old,text);(p/name).write_text(text.replace(old,new,1))
                with self.assertRaisesRegex(ValueError,'report facts/counts'):v.verify_docs(p,n,self.e)

    def test_pinned_diagnostic_and_edge_mutations_rejected(self):
        for key in ('diagnostics','call_edges'):
            bad=copy.deepcopy(self.e)
            if key=='diagnostics':bad[key][0]['status']='absent'
            else:bad[key][0]['callee']='0x220bed1'
            with self.assertRaises(ValueError):v.verify_facts(bad)

    def test_manifest_extra_missing_duplicate_traversal_symlink_tampering(self):
        for mutation in ('extra','missing','duplicate','traversal','symlink','tamper','omit','directory'):
            with tempfile.TemporaryDirectory() as t:
                p=Path(t)
                for name in v.MANIFEST|{'MANIFEST.sha256'}:shutil.copyfile(PACKET/name,p/name)
                if mutation=='extra':(p/'unlisted.json').write_text('{}')
                elif mutation=='missing':(p/'RESULT.md').unlink()
                elif mutation=='duplicate':
                    raw=(p/'MANIFEST.sha256').read_text();(p/'MANIFEST.sha256').write_text(raw+raw.splitlines()[0]+'\n')
                elif mutation=='traversal':(p/'MANIFEST.sha256').write_text('0'*64+'  ../README.md\n')
                elif mutation=='symlink':(p/'RESULT.md').unlink();(p/'RESULT.md').symlink_to(PACKET/'RESULT.md')
                elif mutation=='tamper':(p/'RESULT.md').write_text('changed')
                elif mutation=='omit':(p/'MANIFEST.sha256').write_text('\n'.join((p/'MANIFEST.sha256').read_text().splitlines()[1:])+'\n')
                else:(p/'unexpected').mkdir()
                with self.subTest(mutation=mutation),self.assertRaises(ValueError):v.verify_manifest(p)

    def test_packet_links_exist_and_no_runtime_state(self):
        paths=[PACKET/p for p in v.MANIFEST]+[n.ROOT/'tools/abci_engine_inventory.py',Path(__file__)]
        for p in paths:
            raw=p.read_bytes()
            home=str(Path.home()).encode()
            if len(home)>1:self.assertNotIn(home,raw)
            self.assertNotIn(str(n.ROOT).encode(),raw)
            self.assertNotRegex(raw,rb'20\d\d-\d\d-\d\dT\d\d:\d\d:')
            if p.suffix=='.md':
                for target in re.findall(r'\]\(([^)]+)\)',raw.decode()):
                    self.assertFalse(target.startswith('/'));self.assertTrue((p.parent/target.split('#')[0]).exists(),target)


if __name__ == '__main__':unittest.main()
