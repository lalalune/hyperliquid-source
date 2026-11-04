"""Native target evidence and actual format-consumer counterfactuals."""
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import flag_group_format_static as subject
from elf_index import sections


class FlagGroupFormatTests(unittest.TestCase):
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
        self.assertEqual(sum(x['bytes'] for x in self.report['owners']),408)
        with tempfile.TemporaryDirectory() as directory:
            out=Path(directory);subject.generate(subject.TARGET,out)
            for p in out.iterdir():self.assertEqual(p.read_bytes(),(subject.PACKET/p.name).read_bytes(),p.name)

    def test_census_and_bindings(self):
        census=self.report['call_census']
        self.assertEqual(census['direct'],0)
        self.assertEqual(census['via_slot_ff15'],840)
        self.assertEqual(census['via_slot_ff25'],['0x294a37c','0x2a5dc4c','0x2b7b7bc'])
        self.assertEqual(census['distinct_fdes_ff15'],586)
        self.assertEqual(census['chain_sites'],['0x15ae476','0x15ae4f5'])
        self.assertEqual(census['chain_fde'],'0x15ae430..0x15ae5ae')
        self.assertEqual(census['relocation_references'],['0x64df6e8'])
        self.assertEqual(census['address_as_data'],0)
        self.assertEqual(self.report['slot_bindings'],
                         {'0x64df6e8':'0x141e3a0','0x64df6f0':'0x1680500',
                          '0x64df480':'0x6355830','0x64df498':'0x141e264',
                          '0x64df6a0':'0x1680c30','0x64df4a0':'0x635de30'})
        self.assertEqual(self.report['vtable'],
                         {'va':'0x63f3d50','words':['0x141c960','0x18','0x8',
                                                    '0x141e8f0','0x141e7e0','0x141ed80']})
        self.assertFalse(self.report['captured_code_executed'])

    def test_consumer_sites_pinned(self):
        consumer=self.report['consumer']
        self.assertEqual(consumer['tag_test']['test'],'0x141e3b8')
        self.assertEqual(consumer['tag_test']['odd_shift'],'0x141e456')
        self.assertEqual(consumer['scan']['finish'],'0x141e45b')
        self.assertEqual(consumer['capacity']['double'],'0x141e46b')
        self.assertEqual(consumer['allocation']['slot'],'0x64df480')
        self.assertEqual(consumer['allocation']['empty_pointer'],'0x141e495')
        self.assertEqual(consumer['write_call']['slot'],'0x64df6f0')
        self.assertEqual(consumer['write_call']['vtable'],'0x63f3d50')
        self.assertEqual(consumer['write_call']['arguments_mov'],'0x141e4bb')
        self.assertEqual(consumer['panic']['message'],'0x456d84')
        self.assertEqual(consumer['panic']['message_len'],86)
        self.assertEqual(consumer['cleanup_pad']['resume_target'],'0x63f0a50')
        self.assertEqual(consumer['triple']['words'],['capacity','pointer','0'])

    def test_scan_and_capacity_models(self):
        scan=subject.scan_template
        self.assertEqual(scan(b''),(0,False,1))
        self.assertEqual(scan(bytes([0])),(0,False,1))
        self.assertEqual(scan(bytes([3])+b'abc'+bytes([0])),(3,False,5))
        wide=bytes([0x80])+struct.pack('<H',300)+bytes(300)+bytes([0])
        self.assertEqual(scan(wide),(300,False,304))
        for b in range(0x81,0x100):
            skip=(((b&1)<<2)|(b&2))+(2 if b&4 else 0)+(2 if b&8 else 0)
            with self.subTest(tag=hex(b)):
                self.assertEqual(scan(bytes([b])+bytes(skip)+bytes([0])),(0,True,skip+2))
        mixed=bytes([5])+b'hello'+bytes([0xc0])+bytes([0])
        self.assertEqual(scan(mixed),(5,False,8))
        capacity=subject.scan_capacity
        self.assertEqual(capacity(0,True),0)
        self.assertEqual(capacity(15,True),0)
        self.assertEqual(capacity(16,True),32)
        self.assertEqual(capacity(44,False),88)
        self.assertEqual(capacity(0,False),0)
        self.assertIsNone(capacity(2**63,False))
        self.assertIsNone(capacity(2**63,True))
        self.assertEqual(subject.rdx_path(0),('scan',None))
        self.assertEqual(subject.rdx_path(2),('scan',None))
        self.assertEqual(subject.rdx_path(1),('inline_length',0))
        self.assertEqual(subject.rdx_path(0x101),('inline_length',0x80))
        self.assertEqual(subject.rdx_path(2**64-1),('inline_length',2**63-1))

    def test_templates_decoded(self):
        got={t['va']:(t['bytes'],t['literal_len'],t['placeholder_at_zero'],t['initial_capacity'])
             for t in self.report['templates']}
        self.assertEqual(got,{'0x43b857':(2,0,True,0),'0x440e47':(8,2,True,0),
                              '0x43b859':(49,44,False,88)})
        streams={t['va']:t['stream_hex'] for t in self.report['templates']}
        self.assertEqual(streams['0x43b857'],'c000')
        self.assertEqual(streams['0x440e47'],'c0012fc0012fc000')

    def test_slot_binding_counterfactuals(self):
        sec=next(s for s in self.secs if s['name']=='.rela.dyn')
        offsets={struct.unpack_from('<Q',self.data,p)[0]:p for p in range(sec['offset'],sec['offset']+sec['size'],24)}
        for slot in (0x64df6f0,0x64df480,0x64df6a0):
            with self.subTest(slot=hex(slot)):
                changed=bytearray(self.data);changed[offsets[slot]+16]^=1
                with self.assertRaisesRegex(ValueError,'slot binding'):
                    subject.analyze(changed)
        changed=bytearray(self.data);changed[offsets[0x64df6e8]+16]^=1
        with self.assertRaisesRegex(ValueError,'relocation reference|slot binding'):
            subject.analyze(changed)

    def test_vtable_and_message_counterfactuals(self):
        with self.assertRaisesRegex(ValueError,'vtable'):
            subject.analyze(self.mutate(subject.VTABLE+8))
        with self.assertRaisesRegex(ValueError,'panic message'):
            subject.analyze(self.mutate(subject.PANIC_MSG))

    def test_template_counterfactuals(self):
        # A longer literal run in chain template 2 changes its decode.
        with self.assertRaisesRegex(ValueError,'template decode'):
            subject.analyze(self.mutate(0x440e47+1))
        # Removing chain template 1's terminator extends its walk.
        with self.assertRaisesRegex(ValueError,'template decode'):
            subject.analyze(self.mutate(0x43b857+1))

    def test_body_counterfactuals(self):
        for va in (0x141e3b8,0x141e45b,0x141e4bb):
            with self.subTest(va=hex(va)):
                with self.assertRaisesRegex(ValueError,'body changed'):
                    subject.analyze(self.mutate(va))

    def test_extra_slot_caller_counterfactual(self):
        text=next(s for s in self.secs if s['name']=='.text')
        body=self.data[text['offset']:text['offset']+text['size']];base=text['address']
        a,b,_=subject.OWNERS['format_consumer']
        changed=bytearray(self.data);made=False
        index=body.find(b'\xff\x15')
        while index!=-1:
            va=base+index
            target=va+6+struct.unpack_from('<i',body,index+2)[0]
            if target!=subject.SLOT_SELF and not (a<=va<b):
                struct.pack_into('<i',changed,text['offset']+index+2,subject.SLOT_SELF-(va+6))
                made=True;break
            index=body.find(b'\xff\x15',index+1)
        self.assertTrue(made)
        with self.assertRaisesRegex(ValueError,'census'):
            subject.analyze(changed)

    def test_public_identity_rejection_precedes_output(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'changed';out=Path(directory)/'out'
            p.write_bytes(self.mutate(0x141e3b8))
            for path in [p,subject.ROOT/'artifacts/visor/captured/hl-visor']:
                with self.assertRaisesRegex(ValueError,'pinned node115'):
                    subject.generate(path,out)
            p.write_bytes(self.data[:4096])
            with self.assertRaisesRegex(ValueError,'pinned node115'):
                subject.generate(p,out)
            self.assertFalse(out.exists())


if __name__=='__main__':
    unittest.main()
