"""Native target evidence and actual write-target counterfactuals."""
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import flag_group_write_static as subject
from elf_index import sections


def make_block(records):
    return b''.join(struct.pack('<QQ',value,fn) for value,fn in records)


class FlagGroupWriteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not subject.TARGET.is_file() or subject.TARGET.stat().st_size!=105896032:
            raise unittest.SkipTest('materialized node115 required')
        cls.data=subject.TARGET.read_bytes()
        if hashlib.sha256(cls.data).hexdigest()!=subject.SHA:
            raise ValueError('wrong node115 capture')
        cls.secs=sections(cls.data);cls.report=subject.analyze(cls.data)

    def offset(self,va):
        s=next(s for s in self.secs if s['type']!=8 and s['address']<=va<s['address']+s['size'])
        return s['offset']+va-s['address']

    def mutate(self,va,value=None):
        b=bytearray(self.data);o=self.offset(va);b[o]=b[o]^1 if value is None else value
        return b

    def test_native_regeneration_matches_retained_packet(self):
        self.assertEqual(self.report,json.loads((subject.PACKET/'records.json').read_text()))
        self.assertEqual(sum(x['bytes'] for x in self.report['owners']),448)
        with tempfile.TemporaryDirectory() as directory:
            out=Path(directory);subject.generate(subject.TARGET,out)
            for p in out.iterdir():self.assertEqual(p.read_bytes(),(subject.PACKET/p.name).read_bytes(),p.name)

    def test_census_and_bindings(self):
        census=self.report['call_census']
        self.assertEqual(census['direct'],0)
        self.assertEqual(census['via_slot_ff15'],1143)
        self.assertEqual(len(census['via_slot_ff25']),86)
        self.assertIn('0x168aa1d',census['via_slot_ff25'])
        self.assertEqual(census['via_slot_loads'],
                         ['0x1456774','0x163394e','0x166e9eb','0x16881a1','0x168821e',
                          '0x2967bcc','0x29fcc18','0x43be3f8','0x4738fbb','0x47390b9',
                          '0x4fb1688','0x5bb7820','0x5bb8460','0x5bda621','0x5be3208',
                          '0x5c4f2a3'])
        self.assertEqual(census['distinct_fdes_ff15'],626)
        self.assertEqual(census['chain_call_site'],'0x141e4be')
        self.assertEqual(census['chain_jump_site'],'0x168aa1d')
        self.assertEqual(census['relocation_references'],['0x64df6f0'])
        self.assertEqual(census['address_as_data'],0)
        self.assertEqual(self.report['slot_bindings'],{'0x64df6f0':'0x1680500'})
        self.assertEqual(self.report['table_methods'],
                         {'0x63f3d50':'0x141e8f0','0x64078f8':'0x1686bd0'})
        self.assertFalse(self.report['captured_code_executed'])

    def test_trace_sites_pinned(self):
        trace=self.report['write_target']
        self.assertEqual(trace['tag_test']['test'],'0x168051a')
        self.assertEqual(trace['scan_entry']['writer_load'],'0x1680534')
        self.assertEqual(trace['scan_entry']['index_zero'],'0x168053c')
        self.assertEqual(trace['literal_run']['call'],'0x1680575')
        self.assertEqual(trace['wide_run']['length_load'],'0x16805b5')
        self.assertEqual(trace['default_tag']['spec_store'],'0x16805a8')
        self.assertEqual(trace['generic_tag']['spec']['load'],'0x16805e5')
        self.assertEqual(trace['generic_tag']['explicit_index']['load'],'0x1680624')
        self.assertEqual(trace['first_arguments_reads']['value_load'],'0x168065e')
        self.assertEqual(trace['first_arguments_reads']['dispatch_call'],'0x1680666')
        self.assertEqual(trace['first_arguments_reads']['indirect_a_load'],'0x1680680')
        self.assertEqual(trace['first_arguments_reads']['indirect_b_load'],'0x168063b')
        self.assertEqual(trace['dispatch']['counter_store'],'0x1680671')
        self.assertEqual(trace['inline_path']['writer_load'],'0x168068e')
        self.assertEqual(trace['inline_path']['tail_jump'],'0x16806a9')
        self.assertEqual(trace['exits'],{'success':'0x16806ab','error':'0x16806af','return':'0x16806bf'})
        self.assertEqual(trace['record'],{'bytes':16,'value_offset':0,'formatter_offset':8})
        self.assertEqual(trace['descriptor']['words'],['out','table','spec block'])

    def test_tagged_path_and_inline_model(self):
        self.assertEqual(subject.tagged_path(0),('scan',None))
        self.assertEqual(subject.tagged_path(2),('scan',None))
        self.assertEqual(subject.tagged_path(1),('inline_length',0))
        self.assertEqual(subject.tagged_path(0x101),('inline_length',0x80))
        self.assertEqual(subject.tagged_path(2**64-1),('inline_length',2**63-1))
        seen=[]
        def writer(data):
            seen.append(bytes(data));return False
        self.assertEqual(subject.simulate_inline(b'abcdef',0xb,writer),0)
        self.assertEqual(seen,[b'abcde'])
        self.assertEqual(subject.simulate_inline(b'abcdef',0xb,lambda data: True),1)
        with self.assertRaisesRegex(ValueError,'inline'):
            subject.simulate_inline(b'abcdef',0xa,writer)

    def test_parse_tag_model(self):
        base=subject.parse_tag(0x81,struct.pack('<I',0x11223344))
        self.assertEqual(base,{'spec':0x11223344,'field_a':0,'field_b':0,'explicit_index':None,
                               'indirect_a':False,'indirect_b':False,'payload_len':4})
        full=subject.parse_tag(0x8f,struct.pack('<IHHH',0xdeadbeef,5,7,2))
        self.assertEqual(full,{'spec':0xdeadbeef,'field_a':5,'field_b':7,'explicit_index':2,
                               'indirect_a':False,'indirect_b':False,'payload_len':10})
        bare=subject.parse_tag(0xc1,struct.pack('<I',9))
        self.assertEqual(bare['spec'],9);self.assertEqual(bare['payload_len'],4)
        indirect=subject.parse_tag(0x92,struct.pack('<H',3))
        self.assertEqual(indirect['field_a'],3);self.assertTrue(indirect['indirect_a'])
        self.assertFalse(indirect['indirect_b']);self.assertEqual(indirect['payload_len'],2)
        self.assertEqual(subject.parse_tag(0xff,struct.pack('<IHHH',1,2,3,4))['payload_len'],10)
        # Bit 6 is never tested: 0xc0-shaped generic tags keep the field grammar.
        b6=subject.parse_tag(0xc2,struct.pack('<H',11))
        self.assertEqual(b6['field_a'],11);self.assertEqual(b6['payload_len'],2)

    def test_scan_simulator_literals(self):
        block=make_block([(0x1111,0x2222)])
        events=[]
        def writer(data):
            events.append(('literal',bytes(data)));return False
        def dispatch(value,descriptor):
            events.append(('arg',value,descriptor));return False
        self.assertEqual(subject.simulate_scan(bytes([0]),block,writer,dispatch),0)
        self.assertEqual(events,[])
        self.assertEqual(subject.simulate_scan(bytes([2])+b'ab'+bytes([0]),block,writer,dispatch),0)
        self.assertEqual(events,[('literal',b'ab')])
        events.clear()
        wide=bytes([0x80])+struct.pack('<H',3)+b'xyz'+bytes([0])
        self.assertEqual(subject.simulate_scan(wide,block,writer,dispatch),0)
        self.assertEqual(events,[('literal',b'xyz')])
        events.clear()
        err=subject.simulate_scan(bytes([2])+b'ab'+bytes([0xc0,0]),block,
                                  lambda data: True,dispatch)
        self.assertEqual(err,1);self.assertEqual(events,[])
        with self.assertRaisesRegex(ValueError,'empty template'):
            subject.simulate_scan(b'',block,writer,dispatch)

    def test_scan_simulator_chain_template(self):
        # Chain template 2 from the flag-group-format packet: three default
        # placeholders interleaved with two one-byte '/' literal runs.
        block=make_block([(0xa0,0xb0),(0xa1,0xb1),(0xa2,0xb2)])
        events=[]
        def writer(data):
            events.append(('literal',bytes(data)));return False
        def dispatch(value,descriptor):
            events.append(('arg',value,descriptor));return False
        template=bytes.fromhex('c0012fc0012fc000')
        self.assertEqual(subject.simulate_scan(template,block,writer,dispatch),0)
        default=subject.descriptor_block(subject.DEFAULT_SPEC,0,0)
        self.assertEqual(events,[('arg',0xa0,default),('literal',b'/'),
                                 ('arg',0xa1,default),('literal',b'/'),
                                 ('arg',0xa2,default)])
        # Chain template 1: exactly one default placeholder, then terminator.
        events.clear()
        self.assertEqual(subject.simulate_scan(bytes.fromhex('c000'),block,writer,dispatch),0)
        self.assertEqual(events,[('arg',0xa0,default)])
        # A dispatch error stops the walk with result 1.
        self.assertEqual(subject.simulate_scan(template,block,writer,
                                               lambda value,descriptor: True),1)

    def test_scan_simulator_fields_and_counter(self):
        block=make_block([(0xa0,0xb0),(0xa1,0xb1),(0xa2,0xb2),(0xa3,0xb3)])
        seen=[]
        def dispatch(value,descriptor):
            seen.append((value,descriptor));return False
        # Generic tag with spec + both fields from the stream.
        tag=bytes([0x87])+struct.pack('<IHH',0x11223344,5,7)+bytes([0])
        self.assertEqual(subject.simulate_scan(tag,block,lambda data: False,dispatch),0)
        self.assertEqual(seen,[(0xa0,subject.descriptor_block(0x11223344,5,7))])
        seen.clear()
        # Explicit index: dispatch record 2, then the counter continues at 3.
        tag=bytes([0x88])+struct.pack('<H',2)+bytes([0xc0,0])
        self.assertEqual(subject.simulate_scan(tag,block,lambda data: False,dispatch),0)
        self.assertEqual([v for v,_ in seen],[0xa2,0xa3])
        seen.clear()
        # Indirection: the stream u16 is a record index whose +0x8 low u16
        # becomes the field.
        block2=make_block([(0xa0,0x1000),(0xa1,0x2000000000000077),(0xa2,0x3000)])
        tag=bytes([0x92])+struct.pack('<H',1)+bytes([0])
        self.assertEqual(subject.simulate_scan(tag,block2,lambda data: False,dispatch),0)
        self.assertEqual(seen,[(0xa0,subject.descriptor_block(subject.DEFAULT_SPEC,0x77,0))])
        seen.clear()
        tag=bytes([0xa4])+struct.pack('<H',2)+bytes([0])
        block3=make_block([(0xa0,0x1000),(0xa1,0x2000),(0xa2,0x3000000000000099)])
        self.assertEqual(subject.simulate_scan(tag,block3,lambda data: False,dispatch),0)
        self.assertEqual(seen,[(0xa0,subject.descriptor_block(subject.DEFAULT_SPEC,0,0x99))])

    def test_slot_binding_counterfactuals(self):
        sec=next(s for s in self.secs if s['name']=='.rela.dyn')
        offsets={struct.unpack_from('<Q',self.data,p)[0]:p for p in range(sec['offset'],sec['offset']+sec['size'],24)}
        changed=bytearray(self.data);changed[offsets[subject.SLOT_WRITE]+16]^=1
        with self.assertRaisesRegex(ValueError,'slot binding|relocation reference'):
            subject.analyze(changed)

    def test_table_method_counterfactual(self):
        sec=next(s for s in self.secs if s['name']=='.rela.dyn')
        offsets={struct.unpack_from('<Q',self.data,p)[0]:p for p in range(sec['offset'],sec['offset']+sec['size'],24)}
        va=subject.CONSUMER_TABLE+subject.TABLE_METHOD_OFFSET
        changed=bytearray(self.data)
        if va in offsets:
            changed[offsets[va]+16]^=1
        else:
            changed[self.offset(va)]^=1
        with self.assertRaisesRegex(ValueError,'table method'):
            subject.analyze(changed)

    def test_body_counterfactuals(self):
        for va in (0x168051a,0x168065e,0x1680666):
            with self.subTest(va=hex(va)):
                with self.assertRaisesRegex(ValueError,'body changed'):
                    subject.analyze(self.mutate(va))

    def test_extra_slot_caller_counterfactual(self):
        text=next(s for s in self.secs if s['name']=='.text')
        body=self.data[text['offset']:text['offset']+text['size']];base=text['address']
        a,b,_=subject.OWNERS['write_target']
        changed=bytearray(self.data);made=False
        index=body.find(b'\xff\x15')
        while index!=-1:
            va=base+index
            target=va+6+struct.unpack_from('<i',body,index+2)[0]
            if target!=subject.SLOT_WRITE and not (a<=va<b):
                struct.pack_into('<i',changed,text['offset']+index+2,subject.SLOT_WRITE-(va+6))
                made=True;break
            index=body.find(b'\xff\x15',index+1)
        self.assertTrue(made)
        with self.assertRaisesRegex(ValueError,'census'):
            subject.analyze(changed)

    def test_public_identity_rejection_precedes_output(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'changed';out=Path(directory)/'out'
            p.write_bytes(self.mutate(0x168051a))
            for path in [p,subject.ROOT/'artifacts/visor/captured/hl-visor']:
                with self.assertRaisesRegex(ValueError,'pinned node115'):
                    subject.generate(path,out)
            p.write_bytes(self.data[:4096])
            with self.assertRaisesRegex(ValueError,'pinned node115'):
                subject.generate(p,out)
            self.assertFalse(out.exists())


if __name__=='__main__':
    unittest.main()
