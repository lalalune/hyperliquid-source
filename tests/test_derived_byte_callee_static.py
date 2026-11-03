"""Native target evidence and actual callee/guard counterfactuals."""
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import derived_byte_callee_static as subject
from elf_index import sections


class DerivedByteCalleeTests(unittest.TestCase):
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
        self.assertEqual(sum(x['bytes'] for x in self.report['owners']),10999)
        with tempfile.TemporaryDirectory() as directory:
            out=Path(directory);subject.generate(subject.TARGET,out)
            for p in out.iterdir():self.assertEqual(p.read_bytes(),(subject.PACKET/p.name).read_bytes(),p.name)

    def test_census_and_slot_bindings(self):
        callers=self.report['direct_callers']
        self.assertEqual(callers['count'],4)
        self.assertEqual(callers['sites'],['0x15a3f5f','0x15a401e','0x15a4263','0x15a431c'])
        self.assertEqual(callers['containing_fde'],'consumer_large')
        self.assertEqual(callers['relocation_references'],0)
        self.assertEqual(callers['address_as_data'],0)
        self.assertEqual(self.report['slot_bindings'],
                         {'0x64df6e8':'0x141e3a0','0x64df650':'0x141cc40',
                          '0x64df4a0':'0x635de30','0x64e1490':'0x16035e0',
                          '0x64e0b68':'0x150ce90'})
        self.assertFalse(self.report['captured_code_executed'])

    def test_guard_and_variant_models(self):
        fires=subject.drop_guard_fires
        self.assertFalse(fires(0))
        self.assertFalse(fires(subject.SENTINEL))
        for value in (1,2,subject.SENTINEL-1,subject.SENTINEL+1,2**64-1):
            self.assertTrue(fires(value),hex(value))
        for byte in range(256):
            self.assertEqual(subject.record_variant(byte),
                             'sentinel' if byte & 1 else 'register')
        guard=self.report['callee']['record_drop_guard']
        self.assertEqual(guard['load'],'0x15ae524')
        self.assertEqual(guard['call'],'0x15ae537')
        self.assertEqual(guard['slot'],'0x64df4a0')

    def test_rsi_provenance_and_tests_pinned(self):
        consumer=self.report['consumer_derived']
        self.assertEqual(consumer['rsi_provenance']['stack_offset'],'0x1a8')
        self.assertEqual([t['site'] for t in consumer['derived_tests']],
                         ['0x15a3f1f','0x15a4220'])
        self.assertEqual([t['register_variant'] for t in consumer['derived_tests']],
                         ['0x15a3fd2','0x15a42c8'])
        self.assertEqual(consumer['sentinel_record_stores'],['0x15a3f2a','0x15a422b'])
        self.assertEqual(consumer['group']['derived_offset'],'0x15')

    def test_slot_binding_counterfactuals(self):
        sec=next(s for s in self.secs if s['name']=='.rela.dyn')
        offsets={struct.unpack_from('<Q',self.data,p)[0]:p for p in range(sec['offset'],sec['offset']+sec['size'],24)}
        for slot in (0x64df6e8,0x64df4a0,0x64e1490):
            with self.subTest(slot=hex(slot)):
                changed=bytearray(self.data);changed[offsets[slot]+16]^=1
                with self.assertRaisesRegex(ValueError,'slot binding'):
                    subject.analyze(changed)

    def test_callee_relocation_appearance_counterfactual(self):
        sec=next(s for s in self.secs if s['name']=='.rela.dyn')
        offsets={struct.unpack_from('<Q',self.data,p)[0]:p for p in range(sec['offset'],sec['offset']+sec['size'],24)}
        changed=bytearray(self.data)
        struct.pack_into('<q',changed,offsets[0x64e1490]+16,subject.CALLEE)
        with self.assertRaisesRegex(ValueError,'relocation reference'):
            subject.analyze(changed)

    def test_body_counterfactuals(self):
        # Guard neg inside the callee body and the derived-byte test inside
        # the consumer body are both stopped by their body hashes.
        for va in (0x15ae52a,0x15a3f1f):
            with self.subTest(va=hex(va)):
                with self.assertRaisesRegex(ValueError,'body changed'):
                    subject.analyze(self.mutate(va))

    def test_fifth_caller_counterfactual(self):
        text=next(s for s in self.secs if s['name']=='.text')
        body=self.data[text['offset']:text['offset']+text['size']];base=text['address']
        owners=[(a,b) for a,b,_ in subject.OWNERS.values()]
        changed=bytearray(self.data);made=False
        index=body.find(b'\xe8')
        while index!=-1:
            va=base+index
            target=va+5+struct.unpack_from('<i',body,index+1)[0]
            if target!=subject.CALLEE and not any(a<=va<b for a,b in owners):
                struct.pack_into('<i',changed,text['offset']+index+1,subject.CALLEE-(va+5))
                made=True;break
            index=body.find(b'\xe8',index+1)
        self.assertTrue(made)
        with self.assertRaisesRegex(ValueError,'census'):
            subject.analyze(changed)

    def test_public_identity_rejection_precedes_output(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'changed';out=Path(directory)/'out'
            p.write_bytes(self.mutate(0x15ae52a))
            for path in [p,subject.ROOT/'artifacts/visor/captured/hl-visor']:
                with self.assertRaisesRegex(ValueError,'pinned node115'):
                    subject.generate(path,out)
            p.write_bytes(self.data[:4096])
            with self.assertRaisesRegex(ValueError,'pinned node115'):
                subject.generate(p,out)
            self.assertFalse(out.exists())


if __name__=='__main__':
    unittest.main()
