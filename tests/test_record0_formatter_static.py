"""Native target evidence and actual record-0 formatter counterfactuals."""
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import record0_formatter_static as subject
from elf_index import sections


class Record0FormatterTests(unittest.TestCase):
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
        self.assertEqual(sum(x['bytes'] for x in self.report['owners']),58)
        with tempfile.TemporaryDirectory() as directory:
            out=Path(directory);subject.generate(subject.TARGET,out)
            for p in out.iterdir():self.assertEqual(p.read_bytes(),(subject.PACKET/p.name).read_bytes(),p.name)

    def test_census_and_bindings(self):
        census=self.report['reference_census']
        self.assertEqual(census['direct'],0)
        self.assertEqual(census['via_formatter_slot'],0)
        self.assertEqual(census['formatter_slot_refs'],['0x15ae459'])
        self.assertEqual(census['formatter_slot_store'],'0x15ae460')
        self.assertEqual(census['constructor_fde'],['0x15ae430','0x15ae5ae'])
        self.assertEqual(census['relocation_references'],['0x64e1490'])
        self.assertEqual(census['address_as_data'],0)
        self.assertEqual(self.report['slot_bindings'],
                         {'0x64e1490':'0x16035e0','0x64df6f0':'0x1680500'})
        self.assertEqual(self.report['template']['va'],'0x43b857')
        self.assertEqual(self.report['template']['stream_hex'],'c000')
        self.assertEqual(self.report['next_formatter'],
                         {'start':'0x15eadd0','end':'0x15eadff','bytes':47})
        self.assertFalse(self.report['captured_code_executed'])

    def test_trace_sites_pinned(self):
        trace=self.report['formatter']
        self.assertEqual(trace['frame'],{'alloc':'0x16035e0','bytes':24,
                                         'restore':'0x1603615','return':'0x1603619'})
        self.assertEqual(trace['value_store']['site'],'0x16035e4')
        self.assertFalse(trace['value_store']['dereferenced_by_formatter'])
        self.assertEqual(trace['record']['value_store'],'0x16035eb')
        self.assertEqual(trace['record']['formatter_lea'],'0x16035f0')
        self.assertEqual(trace['record']['formatter_store'],'0x16035f7')
        self.assertEqual(trace['record']['formatter'],'0x15eadd0')
        self.assertEqual(trace['descriptor_reads']['out_load'],'0x16035fc')
        self.assertEqual(trace['descriptor_reads']['table_load'],'0x16035ff')
        self.assertIsNone(trace['descriptor_reads']['spec_dword'])
        self.assertIsNone(trace['descriptor_reads']['field_a'])
        self.assertIsNone(trace['descriptor_reads']['field_b'])
        self.assertEqual(trace['nested_call']['call'],'0x160360f')
        self.assertEqual(trace['nested_call']['slot'],'0x64df6f0')
        self.assertEqual(trace['nested_call']['target'],'0x1680500')

    def test_formatter_model_block_layout(self):
        frame=subject.build_stack_frame(0xdeadbeef)
        self.assertEqual(frame['value_slot'],0xdeadbeef)
        self.assertEqual(frame['record']['value'],'value_slot')
        self.assertEqual(frame['record']['formatter'],subject.NEXT_FORMATTER)
        seen=[]
        def write_target(out,table,template,records):
            seen.append((out,table,template,records));return 0
        descriptor=struct.pack('<QQIHH',0x1111,0x2222,0x60000020,5,7)
        self.assertEqual(subject.simulate_formatter(0xdeadbeef,descriptor,write_target),0)
        # The nested call forwards out/table unchanged, reuses the chain's
        # two-byte template, and dispatches ONE record whose value word is
        # the slot handle — not the value itself.
        self.assertEqual(seen,[(0x1111,0x2222,bytes.fromhex('c000'),
                                [('value_slot',subject.NEXT_FORMATTER)])])

    def test_formatter_model_spec_and_fields_ignored(self):
        calls=[]
        def write_target(out,table,template,records):
            calls.append((out,table,template,records));return 0
        base=struct.pack('<QQIHH',0x1111,0x2222,0x60000020,0,0)
        other=struct.pack('<QQIHH',0x1111,0x2222,0xffffffff,0xbeef,0xcafe)
        subject.simulate_formatter(0x42,base,write_target)
        subject.simulate_formatter(0x42,other,write_target)
        self.assertEqual(calls[0],calls[1])

    def test_formatter_model_return_passthrough(self):
        descriptor=struct.pack('<QQIHH',0x1111,0x2222,0,0,0)
        self.assertEqual(subject.simulate_formatter(1,descriptor,lambda *a: 0),0)
        self.assertEqual(subject.simulate_formatter(1,descriptor,lambda *a: 1),1)

    def test_slot_binding_counterfactuals(self):
        sec=next(s for s in self.secs if s['name']=='.rela.dyn')
        offsets={struct.unpack_from('<Q',self.data,p)[0]:p for p in range(sec['offset'],sec['offset']+sec['size'],24)}
        for slot in (subject.FORMATTER_SLOT,subject.WRITE_SLOT):
            with self.subTest(slot=hex(slot)):
                changed=bytearray(self.data);changed[offsets[slot]+16]^=1
                with self.assertRaisesRegex(ValueError,'slot binding'):
                    subject.analyze(changed)

    def test_template_counterfactual(self):
        with self.assertRaisesRegex(ValueError,'template'):
            subject.analyze(self.mutate(subject.TEMPLATE))

    def test_body_counterfactuals(self):
        for va in (0x16035e4,0x16035fc,0x160360f,0x16035f3):
            with self.subTest(va=hex(va)):
                with self.assertRaisesRegex(ValueError,'body changed'):
                    subject.analyze(self.mutate(va))

    def test_extra_slot_reference_counterfactual(self):
        text=next(s for s in self.secs if s['name']=='.text')
        body=self.data[text['offset']:text['offset']+text['size']];base=text['address']
        changed=bytearray(self.data);made=False
        index=body.find(b'\xff\x15')
        while index!=-1:
            va=base+index
            target=va+6+struct.unpack_from('<i',body,index+2)[0]
            if target!=subject.FORMATTER_SLOT and va!=0x160360f:
                struct.pack_into('<i',changed,text['offset']+index+2,subject.FORMATTER_SLOT-(va+6))
                made=True;break
            index=body.find(b'\xff\x15',index+1)
        self.assertTrue(made)
        with self.assertRaisesRegex(ValueError,'census'):
            subject.analyze(changed)

    def test_public_identity_rejection_precedes_output(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'changed';out=Path(directory)/'out'
            p.write_bytes(self.mutate(0x16035e4))
            for path in [p,subject.ROOT/'artifacts/visor/captured/hl-visor']:
                with self.assertRaisesRegex(ValueError,'pinned node115'):
                    subject.generate(path,out)
            p.write_bytes(self.data[:4096])
            with self.assertRaisesRegex(ValueError,'pinned node115'):
                subject.generate(p,out)
            self.assertFalse(out.exists())


if __name__=='__main__':
    unittest.main()
