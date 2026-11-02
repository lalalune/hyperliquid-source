"""Static node #94 tcp_stream evidence and corruption controls (MIT; stdlib)."""
from collections import Counter
from contextlib import contextmanager, ExitStack
import copy
import importlib.util
import io
import mmap
from pathlib import Path
import shutil
import struct
import tempfile
import unittest
from unittest import mock

from tools import tcp_stream_inventory as n

PACKET = n.ROOT/'research/work-items/tcp-stream-inventory-94'
spec = importlib.util.spec_from_file_location('tcp_stream_verify', PACKET/'verify.py')
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
    def __init__(self, raw): self.raw = raw

    def read(self, va, size):
        off = va-0x1000
        n.require(size > 0 and off >= 0 and off+size <= len(self.raw), 'synthetic read out of bounds')
        return self.raw[off:off+size]

    def evidence(self, va, size):
        return {'va': hex(va), 'file_offset': hex(va-0x1000), 'section': 'synthetic',
                'bytes': self.read(va, size).hex()}


def decode_small(raw, end=None):
    image = SmallImage(raw)
    return image, n.decode_fde(image, {'start': 0x1000, 'end': 0x1000+(len(raw) if end is None else end)})


class DecoderTests(unittest.TestCase):
    def test_signed_lea_all_registers_and_rel32(self):
        for disp in (-2147483648, -7, 0, 2147483647):
            for reg in range(16):
                raw = bytes([0x4c if reg >= 8 else 0x48, 0x8d, 5+8*(reg%8)])+struct.pack('<i',disp)
                self.assertEqual(n.decode_lea(raw,0x100000000), (0x100000007+disp,reg))
            for op in (0xe8,0xe9):
                self.assertEqual(n.decode_rel32_transfer(bytes([op])+struct.pack('<i',disp),0x100000000),0x100000005+disp)
            self.assertEqual(n.decode_slot_call(b'\xff\x15'+struct.pack('<i',disp),0x100000000),0x100000006+disp)

    def test_exact_operand_decoders_reject_invalid_forms(self):
        groups = ((n.decode_lea, ('488d05000000','408d0500000000','488d0400000000','488d050000000090')),
                  (n.decode_rel32_transfer, ('e800','eb00000000','ff00000000','e80000000090')),
                  (n.decode_slot_call, ('ff15000000','ff2500000000','ff1400000000','ff150000000090')))
        for fn, cases in groups:
            for raw in cases:
                with self.subTest(fn=fn.__name__,raw=raw),self.assertRaises(ValueError): fn(bytes.fromhex(raw),0)

    def test_instruction_truncations_modrm_sib_and_prefixes(self):
        for text in ('48898c24c8000000','48c744245819000000','49c785100200000e000000',
                     '64488b1c2500000000','6666662e0f1f840000000000','41b812000000',
                     '48b88877665544332211','f0480fb10e','0f8501000000','f390'):
            raw=bytes.fromhex(text)
            self.assertEqual(n.decode_instruction(raw)['raw'],raw)
            for end in range(len(raw)):
                with self.subTest(raw=text,end=end),self.assertRaises(ValueError): n.decode_instruction(raw[:end])

    def test_unknown_reserved_prefix_and_overlong_fail_closed(self):
        for text in ('c5f877','62f17c4858c0','ff38','c7c800000000','488dc0',
                     'f0833801','f090','f2f390','666601c0','f0f20100','0f710001','66'*14+'0f1f00'):
            with self.subTest(raw=text),self.assertRaises(ValueError): n.decode_instruction(bytes.fromhex(text))

    def test_embedded_lea_and_call_are_not_boundaries(self):
        for operand in ('488d050000000090','e800000000909090'):
            image,insns=decode_small(b'\x48\xb8'+bytes.fromhex(operand)+b'\xc3')
            self.assertEqual([x['site'] for x in insns],[0x1000,0x100a])
            with self.assertRaises(ValueError): n.core.verified_lea(image,insns,0x1002,0x1009)
            edges,_,_=n.edges_and_transfers(image,{0x1000:insns},{0x1000:{'end':0x100b}}, {})
            self.assertEqual(edges,[])

    def test_branch_into_operand_and_truncated_body_fail(self):
        for raw in ('eb0148b80000000000000000c3','90488d05'):
            with self.assertRaises(ValueError): decode_small(bytes.fromhex(raw))

    def test_immediate_pointer_store_and_truncations(self):
        self.assertEqual(n.decode_mov_immediate(bytes.fromhex('41b9ffffffff')), {'register':9,'value':0xffffffff,'width':32})
        self.assertEqual(n.decode_mov_immediate(bytes.fromhex('48c74424f8ffffffff')),
                         {'memory':{'base_register':4,'displacement':-8},'width':64,'value':-1})
        self.assertEqual(n.decode_pointer_store(bytes.fromhex('4c89b310020000')), ({'base_register':3,'displacement':528},14))
        for text,fn in (('49c786280200000b000000',n.decode_mov_immediate),('41b910000000',n.decode_mov_immediate),('4c89b310020000',n.decode_pointer_store)):
            raw=bytes.fromhex(text)
            for end in range(len(raw)):
                with self.subTest(raw=text,end=end),self.assertRaises(ValueError): fn(raw[:end])
        for text in ('c744245819000000','48c74c245819000000','48c7050000000019000000',
                     '48c744645819000000','48c74424581900000000','48b88877665544332211'):
            with self.assertRaises(ValueError): n.decode_mov_immediate(bytes.fromhex(text))

    def test_adjacent_pointer_length_positive_and_corruptions(self):
        raw=bytes.fromhex('488d050e000000488944244048c744244804000000')+b'test'
        image,ins=decode_small(raw,21)
        self.assertEqual(n.pointer_length_pair(image,ins,0,b'test')['length'],4)
        for offset,value in ((9,0x4c),(15,0x50),(16,5),(17,5),(0,0x4c),(12,0x40)):
            bad=bytearray(raw);bad[offset]=value
            with self.subTest(offset=offset),self.assertRaises(ValueError):
                altered,seq=decode_small(bytes(bad),21)
                n.pointer_length_pair(altered,seq,0,b'test')

    def test_register_pair_requires_length_no_clobber_and_call(self):
        raw=bytes.fromhex('488d350a000000ba04000000e800000000')+b'test'
        image,ins=decode_small(raw,17)
        self.assertEqual(n.pointer_length_pair(image,ins,0,b'test')['length'],4)
        for offset,value in ((8,5),(7,0xbe),(12,0xe9),(2,0x3d)):
            bad=bytearray(raw);bad[offset]=value
            with self.subTest(offset=offset),self.assertRaises(ValueError):
                altered,seq=decode_small(bytes(bad),17)
                n.pointer_length_pair(altered,seq,0,b'test')
        gap=copy.deepcopy(ins);gap[1]['site']+=1
        with self.assertRaises(ValueError): n.pointer_length_pair(image,gap,0,b'test')

    def test_counted_fragment_does_not_bind_neighboring_text(self):
        image=SmallImage(b'\x03one\xc0\x03two\xc0\0')
        self.assertEqual(n.core.counted_fragment(image,0x1000,0x1006,b'two')['length'],3)
        for raw,occ,needle in ((b'\x03one\0\x03two\xc0',0x1006,b'two'),
                               (b'\x03one\xc0\x03two\0',0x1003,b'e\xc0\x03t'),
                               (b'\x04one\xc0',0x1001,b'one'),(b'\x03o\xffe\xc0',0x1001,b'o'),
                               (b'\x03one!',0x1001,b'one'),(b'\x03on',0x1001,b'on')):
            with self.subTest(raw=raw),self.assertRaises(ValueError): n.core.counted_fragment(SmallImage(raw),0x1000,occ,needle)

    def test_forged_instruction_metadata_rejected(self):
        image,ins=decode_small(b'\x90');ins[0]['kind']='call_rel32'
        with self.assertRaises(ValueError): n.instruction_evidence(image,ins[0])


class TargetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.handle=(n.ROOT/n.TARGET).open('rb')
        cls.data=mmap.mmap(cls.handle.fileno(),0,access=mmap.ACCESS_READ)
        with no_external_effects(): cls.result=n.build(cls.data)
        cls.e=cls.result['inventory.json'];cls.image=n.Image(cls.data)
        cls.relocations=n.relative_relocations(cls.image)
        cls.locs=n.locations(cls.image,cls.relocations)
        cls.fdes=n.Fdes(cls.image)
        cls.scoped={int(f['start'],16):cls.fdes.owner(int(f['start'],16)) for f in cls.e['fdes']}
        cls.decoded={s:n.decode_fde(cls.image,f) for s,f in cls.scoped.items()}
        cls.attrs=n.attribution(cls.image,cls.decoded,cls.relocations)

    @classmethod
    def tearDownClass(cls): cls.data.close();cls.handle.close()

    @contextmanager
    def mutated(self, offset, raw):
        # Copy-on-write pages, never duplicate/write the complete target file.
        with mmap.mmap(self.handle.fileno(),0,access=mmap.ACCESS_COPY) as data:
            data[offset:offset+len(raw)]=raw
            yield n.Image(data)

    def offset(self,va): return self.image.mapping(va)[1]

    def test_exact_regeneration_reports_and_whitelist(self):
        with no_external_effects():
            v.verify_outputs(PACKET,n,self.result)
            v.verify_manifest(PACKET)

    def test_census_exact_path_every_lea_and_adjacent_call(self):
        self.assertEqual(len(self.locs),15);self.assertEqual(len(self.e['location_leas']),34)
        for x in self.e['location_leas']:
            slot,start=int(x['location'],16),int(x['owner'],16)
            site=int(x['instruction']['va'],16);seq=self.decoded[start]
            _,reg=n.core.verified_lea(self.image,seq,site,slot)
            self.assertEqual(reg,7)
            loc=self.locs[slot]
            self.assertEqual(bytes.fromhex(loc['path_bytes']['bytes']),n.PREFIX+n.SCOPE)
            self.assertEqual(n.decode_location(self.image,slot,self.relocations[slot]),loc)
            i=next(i for i,z in enumerate(seq) if z['site']==site)
            self.assertEqual(n.location_call(self.image,seq,i,self.relocations,self.fdes),x['adjacent_call'])

    def test_duplicate_coordinates_not_collapsed(self):
        self.assertEqual(Counter((r['line'],r['column']) for r in self.locs.values()),
                         {(33,60):3,(45,80):5,(50,73):5,(60,82):2})

    def test_wrong_digest_precedes_parse_and_cli_writes_nothing(self):
        for data in (b'',b'not node 94'):
            with mock.patch.object(n,'Image',side_effect=AssertionError('parsed unauthenticated bytes')):
                with self.assertRaisesRegex(ValueError,'SHA-256'): n.build(data)
        with tempfile.TemporaryDirectory() as t:
            p=Path(t);(p/'fake').write_bytes(b'not node 94')
            with no_external_effects(),mock.patch('sys.stderr',new=io.StringIO()),self.assertRaises(SystemExit) as exc:
                n.main(['--binary',str(p/'fake'),'--out',str(p/'output')])
            self.assertEqual(exc.exception.code,1);self.assertFalse((p/'output').exists())
        with self.mutated(self.offset(0x5697298)+16,struct.pack('<I',46)) as image:
            with self.assertRaisesRegex(ValueError,'SHA-256'): n.build(image.data)

    def test_mutated_location_fields_below_digest(self):
        slot=0x5697298;off=self.offset(slot)
        for delta,raw in ((0,struct.pack('<Q',1)),(8,struct.pack('<Q',0)),(8,struct.pack('<Q',55)),
                          (16,struct.pack('<I',0)),(20,struct.pack('<I',0))):
            with self.subTest(delta=delta),self.mutated(off+delta,raw) as image,self.assertRaises(ValueError):
                n.decode_location(image,slot,self.relocations[slot])

    def test_path_slot_and_relocation_metadata_changes(self):
        slot=0x5697298;rel=self.relocations[slot]
        with self.mutated(self.offset(rel['target']),b'!') as image,self.assertRaises(ValueError):
            n.decode_location(image,slot,rel)
        with self.assertRaises(ValueError): n.decode_location(self.image,slot+1,rel)
        for key,value in (('target',rel['target']+1),('raw','00'*24),('entry_va',rel['entry_va']+24)):
            with self.subTest(key=key),self.assertRaises(ValueError): n.decode_location(self.image,slot,{**rel,key:value})

    def test_bad_relocation_symbol_addend_and_duplicate(self):
        off=self.relocations[0x5697298]['entry_file_offset']
        for delta,raw in ((8,struct.pack('<Q',(1<<32)|8)),(16,struct.pack('<q',-1)),(0,struct.pack('<Q',0x56972b0))):
            with self.subTest(delta=delta),self.mutated(off+delta,raw) as image,self.assertRaises(ValueError): n.relative_relocations(image)

    def test_legal_changed_line_and_missing_record_fail_pinned_census(self):
        with self.mutated(self.offset(0x5697298)+16,struct.pack('<I',46)) as image:
            changed=n.decode_location(image,0x5697298,self.relocations[0x5697298])
            bad=copy.deepcopy(self.e);bad['locations'][0].update(changed)
            with self.assertRaisesRegex(ValueError,'Location census'): v.verify_facts(bad)
        bad=copy.deepcopy(self.e);bad['locations'].pop()
        with self.assertRaisesRegex(ValueError,'Location census'): v.verify_facts(bad)

    def section_header(self,name):
        return struct.unpack_from('<Q',self.data,40)[0]+self.image.sections.index(self.image.by_name[name])*struct.unpack_from('<H',self.data,58)[0]

    def test_missing_required_sections(self):
        for name in ('.text','.rodata','.data.rel.ro','.rela.dyn','.eh_frame','.eh_frame_hdr'):
            with mmap.mmap(self.handle.fileno(),0,access=mmap.ACCESS_COPY) as data:
                struct.pack_into('<I',data,self.section_header(name),0)
                with self.subTest(name=name),self.assertRaises(ValueError): n.Image(data)

    def test_section_mapping_machine_and_permissions(self):
        for off,raw in ((self.section_header('.rodata')+4,struct.pack('<I',8)),
                        (self.section_header('.text')+8,struct.pack('<Q',2)),
                        (self.section_header('.rodata')+8,struct.pack('<Q',0)),(18,struct.pack('<H',3))):
            with mmap.mmap(self.handle.fileno(),0,access=mmap.ACCESS_COPY) as data:
                data[off:off+len(raw)]=raw
                with self.assertRaises(ValueError): n.Image(data)

    def test_fde_encoding_extent_and_index_start_corruption(self):
        f=self.e['fdes'][0];entry=f['unwind_index_entry'];off=int(entry['file_offset'],16)
        changes=((self.image.by_name['.eh_frame_hdr']['offset'],b'\x02'),
                 (self.offset(int(f['fde_record']['va'],16))+12,struct.pack('<I',0)),
                 (off,struct.pack('<i',struct.unpack_from('<i',self.data,off)[0]+1)))
        for off,raw in changes:
            with self.mutated(off,raw) as image,self.assertRaises(ValueError): n.Fdes(image)

    def test_shifted_lea_and_retargeted_displacement(self):
        row=self.e['location_leas'][0];site=int(row['instruction']['va'],16);start=int(row['owner'],16);slot=int(row['location'],16)
        with self.assertRaises(ValueError): n.core.verified_lea(self.image,self.decoded[start],site+1,slot)
        off=self.offset(site)+3;disp=struct.unpack_from('<i',self.data,off)[0]
        with self.mutated(off,struct.pack('<i',disp+1)) as image:
            seq=n.decode_fde(image,self.scoped[start])
            with self.assertRaises(ValueError): n.core.verified_lea(image,seq,site,slot)

    def test_adjacent_location_slot_call_corruptions(self):
        row=self.e['location_leas'][0];start=int(row['owner'],16);site=int(row['instruction']['va'],16)
        i=next(i for i,x in enumerate(self.decoded[start]) if x['site']==site)
        for off,raw in ((self.offset(site)+2,b'\x35'),(self.offset(site)+8,b'\x25'),
                        (self.offset(int(row['adjacent_call']['pointer_slot']['va'],16)),struct.pack('<Q',1))):
            with self.subTest(off=off),self.mutated(off,raw) as image,self.assertRaises(ValueError):
                seq=n.decode_fde(image,self.scoped[start])
                n.location_call(image,seq,i,self.relocations,self.fdes)

    def test_complete_transcripts_match_bytes_and_instruction_boundaries(self):
        for f,t in zip(self.e['fdes'],self.result['instructions.json']['fdes']):
            raw=b''.join(bytes.fromhex(row[1]) for row in t['instructions'])
            self.assertEqual(len(raw),f['size']);self.assertEqual(n.sha(raw),f['code_sha256'])
            self.assertEqual(raw,self.image.read(int(f['start'],16),f['size']))
            cursor=0
            for off,hexbytes,kind in t['instructions']:
                self.assertEqual(int(off,16),cursor)
                x=n.decode_instruction(bytes.fromhex(hexbytes),base=int(f['start'],16)+cursor)
                self.assertEqual(x['kind'],kind);cursor+=len(x['raw'])

    def test_every_literal_binding_and_wrong_lengths(self):
        probes={x['id']:x['needle'] for x in n.probes()}
        for d in self.e['diagnostics']:
            for a in d['anchors']:
                start=int(a['owner'],16);seq=self.decoded[start];site=int(a['lea']['va'],16)
                i=next(i for i,x in enumerate(seq) if x['site']==site)
                proof=n.pointer_length_pair(self.image,seq,i,probes[d['id']])
                for k,value in proof.items(): self.assertEqual(a[k],value)
                self.assertTrue(self.attrs[start]['only_exact_file_locations_observed'])
                length_insn=next(x for x in a['setup'][1:] if x['kind']=='mov_imm' and n.decode_mov_immediate(bytes.fromhex(x['bytes']))['value']==a['length'])
                off=int(length_insn['file_offset'],16)+len(bytes.fromhex(length_insn['bytes']))-4
                with self.subTest(site=hex(site)),self.mutated(off,struct.pack('<I',a['length']+1)) as image:
                    changed=n.decode_fde(image,self.scoped[start])
                    with self.assertRaises(ValueError): n.pointer_length_pair(image,changed,i,probes[d['id']])

    def test_shared_ranges_rejected_and_neighbor_tokens_not_bound(self):
        for identifier in ('reference-line-203','reference-line-286','binary-4'):
            d=next(x for x in self.e['diagnostics'] if x['id']==identifier)
            self.assertEqual(d['status'],'present-but-unbound');self.assertEqual(d['anchors'],[])
            self.assertTrue(any('shared FDE' in x['reason'] for x in d['rejected_candidates']))
        ip=next(x for x in self.e['diagnostics'] if x['id']=='binary-3')
        self.assertEqual({a['length'] for a in ip['anchors']},{9})
        # The string immediately following this length-nine literal is not part of it.
        for a in ip['anchors']:
            self.assertEqual(self.image.read(int(a['anchor'],16)+9,9),b'tcp_bytes')

    def test_rejected_retry_chunk_has_byte_proof_and_corruption_controls(self):
        d=next(x for x in self.e['diagnostics'] if x['id']=='reference-line-203')
        row=d['rejected_candidates'][0]
        proof=row['byte_proof_not_attribution']
        self.assertEqual(proof['kind'],'counted_ascii_chunks')
        needle=next(x['needle'] for x in n.probes() if x['id']==d['id'])
        anchor,occ=int(row['anchor'],16),int(row['occurrence'],16)
        self.assertEqual(n.core.counted_fragment(self.image,anchor,occ,needle),proof)
        chunk=proof['chunks'][0];off=int(chunk['record']['file_offset'],16)
        for delta in (0,chunk['length']+1):
            with self.mutated(off+delta,b'\xff') as image,self.assertRaises(ValueError):
                n.core.counted_fragment(image,anchor,occ,needle)

    def test_foreign_location_in_local_setup_overrides_owner_hint(self):
        a=self.e['diagnostics'][-2]['anchors'][0];start=int(a['owner'],16)
        attrs=copy.deepcopy(self.attrs)
        attrs[start]['location_references'].append({'lea':a['lea'],'location':{'path':'net_utils/src/tcp/read.rs','va':'0x0'}})
        with self.assertRaisesRegex(ValueError,'foreign Location'): n.binding_attribution(attrs,start,a['setup'])

    def test_rel32_edges_redecode_and_retarget_control(self):
        self.assertEqual(len(self.e['call_edges']),3)
        for e in self.e['call_edges']:
            site=int(e['instruction']['va'],16);raw=bytes.fromhex(e['instruction']['bytes'])
            self.assertEqual(n.decode_rel32_transfer(raw,site),int(e['callee'],16))
            start=int(e['caller'],16);off=self.offset(site)+1
            with self.mutated(off,struct.pack('<i',e['signed_displacement']+1)) as image:
                dec=dict(self.decoded);dec[start]=n.decode_fde(image,self.scoped[start])
                edges,transfers,_=n.edges_and_transfers(image,dec,self.scoped,self.attrs)
                self.assertEqual(len(edges),2)
                self.assertTrue(any(t['instruction']['va']==hex(site) and t['disposition']=='external_unresolved' for t in transfers))
                bad=copy.deepcopy(self.e);bad['call_edges']=edges
                with self.assertRaises(ValueError): v.verify_facts(bad)

    def test_numeric_roles_not_promoted_by_coincidence(self):
        self.assertEqual([x['numeric_hint'] for x in self.e['constants']],[5,0,1,40,20,60,10,2,4000000,37])
        self.assertTrue(all(x['status']=='unresolved' and not x['anchors'] for x in self.e['constants']))
        self.assertTrue(any(x['decoded_mov_occurrences_not_bindings'] for x in self.e['constants']))

    def test_prior_overlap_revalidated_and_corruption_fails(self):
        result=n.prior_work(self.image,self.fdes,self.scoped,self.decoded,self.e_locations())
        self.assertEqual(result,self.e['prior_work'])
        s=0x2034eb0
        with self.mutated(self.offset(0x2034fd4)+1,struct.pack('<I',38)) as image:
            dec=dict(self.decoded);dec[s]=n.decode_fde(image,self.scoped[s])
            with self.assertRaisesRegex(ValueError,'prior EOF operand'): n.prior_work(image,self.fdes,self.scoped,dec,self.e_locations())

    def e_locations(self): return {int(r['va'],16):r for r in self.e['locations']}

    def test_reference_hash_and_absent_text_not_exported(self):
        with mock.patch.object(n,'REFERENCE_SHA256','0'*64),self.assertRaisesRegex(ValueError,'hint hash'): n.reference_bytes()
        probes={x['id']:x['needle'] for x in n.probes()}
        rendered=n.render(self.e)
        for d in self.e['diagnostics']:
            if d['status']=='absent':
                self.assertNotIn(probes[d['id']],rendered)
                self.assertEqual(d['probe_sha256'],n.sha(probes[d['id']]))

    def test_report_counts_drift_and_transcript_changes_fail(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)
            for name in ('README.md','RESULT.md'): shutil.copyfile(PACKET/name,p/name)
            for name in ('README.md','RESULT.md'):
                original=(p/name).read_text()
                (p/name).write_text(original.replace('| locations | 15 |','| locations | 14 |'))
                with self.assertRaisesRegex(ValueError,'report facts/counts'): v.verify_docs(p,n,self.e)
                (p/name).write_text(original)
        bad=copy.deepcopy(self.result);bad['instructions.json']['fdes'][0]['instructions'][0][1]='90'
        with self.assertRaisesRegex(ValueError,'regeneration'): v.verify_outputs(PACKET,n,bad)


class ManifestTests(unittest.TestCase):
    def test_manifest_mutations_and_symlinks(self):
        cases=('missing','extra','hash','duplicate','traversal','symlink','directory','cache','newline')
        for case in cases:
            with self.subTest(case=case),tempfile.TemporaryDirectory() as t:
                p=Path(t)
                for name in v.MANIFEST | {'MANIFEST.sha256'}: shutil.copyfile(PACKET/name,p/name)
                manifest=p/'MANIFEST.sha256';text=manifest.read_text()
                if case=='missing': (p/'RESULT.md').unlink()
                elif case=='extra': (p/'unexpected.json').write_text('{}')
                elif case=='hash': (p/'README.md').write_text('wrong')
                elif case=='duplicate': manifest.write_text(text+text.splitlines()[0]+'\n')
                elif case=='traversal': manifest.write_text(text.replace('  README.md','  ../README.md'))
                elif case=='symlink': (p/'README.md').unlink();(p/'README.md').symlink_to(PACKET/'README.md')
                elif case=='directory': (p/'unknown').mkdir()
                elif case=='cache': (p/'__pycache__').mkdir();(p/'__pycache__'/'unknown').write_text('x')
                elif case=='newline': manifest.write_text(text.rstrip('\n'))
                with self.assertRaises(ValueError): v.verify_manifest(p)


if __name__ == '__main__': unittest.main()
