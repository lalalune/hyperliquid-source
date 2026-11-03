"""Native target evidence and actual pointer formatter counterfactuals."""
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import pointer_formatter_static as subject
from elf_index import sections


class PointerFormatterTests(unittest.TestCase):
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
        self.assertEqual(sum(x['bytes'] for x in self.report['owners']),47)
        with tempfile.TemporaryDirectory() as directory:
            out=Path(directory);subject.generate(subject.TARGET,out)
            for p in out.iterdir():self.assertEqual(p.read_bytes(),(subject.PACKET/p.name).read_bytes(),p.name)

    def test_census_and_bindings(self):
        census=self.report['reference_census']
        self.assertEqual(census['direct'],0)
        self.assertEqual(census['via_formatter_slot'],0)
        self.assertEqual(census['relocation_references'],[])
        self.assertEqual(census['rip_relative_refs'],['0x16035f0'])
        self.assertEqual(census['lea_site'],'0x16035f0')
        self.assertEqual(census['lea_fde'],['0x16035e0','0x160361a'])
        self.assertEqual(census['address_as_data'],0)
        self.assertEqual(self.report['chain_method_binding'],
                         {'table':'0x63f3d50','slot':'0x63f3d68','method':'0x141e8f0'})
        self.assertFalse(self.report['captured_code_executed'])

    def test_trace_sites_pinned(self):
        trace=self.report['formatter']
        self.assertEqual(trace['value_load']['site'],'0x15eadd0')
        self.assertEqual(trace['first_byte_load']['site'],'0x15eadd3')
        self.assertEqual(trace['first_byte_load']['offset'],0)
        self.assertTrue(trace['first_byte_load']['first_dereference_in_chain'])
        self.assertEqual(trace['length_table']['base'],'0x457fc0')
        self.assertEqual(trace['pointer_table']['base'],'0x46a838')
        self.assertEqual(trace['descriptor_reads']['out_load'],'0x15eadef')
        self.assertEqual(trace['descriptor_reads']['table_load'],'0x15eadf2')
        self.assertEqual(trace['descriptor_reads']['method_load'],'0x15eadf6')
        self.assertIsNone(trace['descriptor_reads']['spec_dword'])
        self.assertIsNone(trace['descriptor_reads']['field_a'])
        self.assertIsNone(trace['descriptor_reads']['field_b'])
        self.assertEqual(trace['tail_call']['site'],'0x15eadfd')
        self.assertFalse(trace['builds_records'])
        self.assertFalse(trace['dispatches_formatter'])

    def test_selection_table_values(self):
        selections=self.report['formatter']['selections']
        self.assertEqual([(s['index'],s['text'],s['length']) for s in selections],
                         [(0,'Error',5),(1,'Warn',4),(2,'Info',4),(3,'Debug',5)])
        self.assertEqual([s['pointer'] for s in selections],
                         ['0x46a5c4','0x459e50','0x45a19c','0x46a5c9'])
        for index,(pointer,length,text) in subject.SELECTIONS.items():
            self.assertEqual(subject.selection(index),(pointer,length,text))

    def test_formatter_model_selection_and_arguments(self):
        seen=[]
        def write_method(out,pointer,length):
            seen.append((out,pointer,length));return 0
        descriptor=struct.pack('<QQIHH',0x1111,0x2222,0x60000020,5,7)
        for index,(pointer,length,_) in subject.SELECTIONS.items():
            seen.clear()
            self.assertEqual(subject.simulate_formatter(index,descriptor,write_method),0)
            # The tail call forwards the descriptor out word unchanged and
            # passes exactly the selected (pointer, length) pair.
            self.assertEqual(seen,[(0x1111,pointer,length)])

    def test_formatter_model_spec_and_fields_ignored(self):
        calls=[]
        def write_method(out,pointer,length):
            calls.append((out,pointer,length));return 0
        base=struct.pack('<QQIHH',0x1111,0x2222,0x60000020,0,0)
        other=struct.pack('<QQIHH',0x1111,0x2222,0xffffffff,0xbeef,0xcafe)
        subject.simulate_formatter(2,base,write_method)
        subject.simulate_formatter(2,other,write_method)
        self.assertEqual(calls[0],calls[1])

    def test_formatter_model_return_passthrough(self):
        descriptor=struct.pack('<QQIHH',0x1111,0x2222,0,0,0)
        self.assertEqual(subject.simulate_formatter(1,descriptor,lambda *a: 0),0)
        self.assertEqual(subject.simulate_formatter(1,descriptor,lambda *a: 1),1)

    def test_formatter_model_unpinned_index_rejected(self):
        descriptor=struct.pack('<QQIHH',0x1111,0x2222,0,0,0)
        with self.assertRaisesRegex(ValueError,'not pinned'):
            subject.simulate_formatter(4,descriptor,lambda *a: 0)

    def test_chain_method_binding_counterfactual(self):
        sec=next(s for s in self.secs if s['name']=='.rela.dyn')
        offsets={struct.unpack_from('<Q',self.data,p)[0]:p for p in range(sec['offset'],sec['offset']+sec['size'],24)}
        changed=bytearray(self.data);changed[offsets[subject.CHAIN_METHOD_SLOT]+16]^=1
        with self.assertRaisesRegex(ValueError,'chain method binding'):
            subject.analyze(changed)

    def test_selection_counterfactuals(self):
        # A length entry, a relative-pointer entry and a selected string
        # byte are each rejected by the selection derivation.
        for va in (subject.LENGTH_TABLE,subject.POINTER_TABLE,0x46a5c4):
            with self.subTest(va=hex(va)):
                with self.assertRaisesRegex(ValueError,'selection'):
                    subject.analyze(self.mutate(va))

    def test_body_counterfactuals(self):
        for va in (0x15eadd0,0x15eadd3,0x15eaddd,0x15eadfd):
            with self.subTest(va=hex(va)):
                with self.assertRaisesRegex(ValueError,'body changed'):
                    subject.analyze(self.mutate(va))

    def test_lea_target_counterfactual(self):
        # One byte inside the predecessor's lea displacement breaks the
        # sole rip-relative reference to the formatter.
        with self.assertRaisesRegex(ValueError,'census'):
            subject.analyze(self.mutate(0x16035f3))

    def test_public_identity_rejection_precedes_output(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'changed';out=Path(directory)/'out'
            p.write_bytes(self.mutate(0x15eadd0))
            for path in [p,subject.ROOT/'artifacts/visor/captured/hl-visor']:
                with self.assertRaisesRegex(ValueError,'pinned node115'):
                    subject.generate(path,out)
            p.write_bytes(self.data[:4096])
            with self.assertRaisesRegex(ValueError,'pinned node115'):
                subject.generate(p,out)
            self.assertFalse(out.exists())


if __name__=='__main__':
    unittest.main()
