"""Native target evidence and actual out-buffer owner counterfactuals."""
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import out_buffer_owner_static as subject
from elf_index import sections


class OutBufferOwnerTests(unittest.TestCase):
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

    def rela_field_offset(self,slot,field):
        sec=next(s for s in self.secs if s['name']=='.rela.dyn')
        for p in range(sec['offset'],sec['offset']+sec['size'],24):
            if struct.unpack_from('<Q',self.data,p)[0]==slot:
                return p+field
        raise AssertionError('relocation slot not found')

    def test_native_regeneration_matches_retained_packet(self):
        self.assertEqual(self.report,json.loads((subject.PACKET/'records.json').read_text()))
        self.assertEqual(sum(x['bytes'] for x in self.report['owners']),10617)
        with tempfile.TemporaryDirectory() as directory:
            out=Path(directory);subject.generate(subject.TARGET,out)
            for p in out.iterdir():self.assertEqual(p.read_bytes(),(subject.PACKET/p.name).read_bytes(),p.name)

    def test_census_and_bindings(self):
        census=self.report['out_owner']['access_census']
        self.assertEqual(census['lea_out'],['0x15a3f3a','0x15a3ff2','0x15a423e','0x15a42f0'])
        self.assertEqual(census['store_capacity'],['0x15a402a','0x15a4328'])
        self.assertEqual(census['store_pointer'],['0x15a4032','0x15a4330'])
        self.assertEqual(census['store_length'],['0x15a403a','0x15a4338'])
        self.assertEqual(census['load_length'],['0x15a4117','0x15a41b0','0x15a440d','0x15a448a'])
        self.assertEqual(census['load_head'],['0x15a4123','0x15a41c0','0x15a4419','0x15a449a'])
        self.assertEqual(census['callee_direct_calls'],['0x15a3f5f','0x15a401e','0x15a4263','0x15a431c'])
        self.assertEqual(census['insert_direct_calls'],['0x15a41eb','0x15a44c8'])
        total=sum(len(census[k]) for k in ('lea_out','store_capacity','store_pointer','store_length','load_length','load_head'))
        self.assertEqual(total,18)
        bindings=self.report['slot_bindings']
        self.assertEqual(bindings['consumer']['addend'],'0x141e3a0')
        self.assertEqual(bindings['alloc']['addend'],'0x6355830')
        self.assertEqual(bindings['dealloc']['addend'],'0x635de30')
        self.assertEqual(bindings['write_target']['addend'],'0x1680500')
        self.assertEqual(bindings['memcpy']['symbol'],'memcpy')
        self.assertFalse(self.report['captured_code_executed'])

    def test_trace_facts(self):
        trace=self.report['out_owner']
        self.assertEqual(trace['out_slot']['stack_offset'],'0x158')
        self.assertEqual(trace['out_slot']['layout'],{'capacity':'+0x0','buffer_pointer':'+0x8','length':'+0x10'})
        self.assertEqual([s['call'] for s in trace['callee_call_setups']],['0x15a3f5f','0x15a401e','0x15a4263','0x15a431c'])
        self.assertEqual([p['alloc_slot'] for p in trace['inline_prefill']],['0x64df480','0x64df480'])
        self.assertEqual([p['triple'] for p in trace['inline_prefill']],
                         ['{capacity=size, pointer=allocation, length=size}']*2)
        self.assertEqual(trace['map_walk']['node_layout']['count_word'],'+0x112')
        self.assertEqual([h['length_store'] for h in trace['map_hit']['hits']],['0x15a411f','0x15a4415'])
        self.assertEqual(trace['map_hit']['segment_a_free']['call'],'0x15a4145')
        self.assertEqual(trace['map_hit']['segment_b_free']['call'],'0x15a3f05')
        self.assertEqual([m['insert_call'] for m in trace['map_miss']['misses']],['0x15a41eb','0x15a44c8'])
        self.assertEqual(trace['map_miss']['insert_target'],'0x156d840')
        boundaries={b['role']:(b['start'],b['bytes']) for b in self.report['boundaries']}
        self.assertEqual(boundaries['format_consumer'],('0x141e3a0',408))
        self.assertEqual(boundaries['derived_byte_callee'],('0x15ae430',382))
        self.assertEqual(boundaries['map_insert'],('0x156d840',364))
        citations=self.report['boundary_citations']
        self.assertEqual(citations['format_consumer_construction']['alloc']['slot'],'0x64df480')
        self.assertEqual(citations['format_consumer_construction']['triple_stores']['values'],'{capacity, allocation pointer, 0}')
        self.assertEqual(citations['callee_delivery']['consumer_slot'],'0x64df6e8')
        self.assertEqual([c['out_slot'] for c in citations['callee_delivery']['consumer_calls']],
                         ['callee stack [rsp+0x28]','callee stack [rsp+0x10]'])

    def test_free_guard_model(self):
        self.assertFalse(subject.should_free(0))
        self.assertFalse(subject.should_free(0x8000000000000000))
        self.assertFalse(subject.should_free(0x8000000000000001))
        self.assertTrue(subject.should_free(1))
        self.assertTrue(subject.should_free(0x20))
        self.assertTrue(subject.should_free(0x8000000000000002))

    def test_inline_prefill_model(self):
        events=[]
        self.assertEqual(subject.inline_prefill(0x1a,events),(0x1a,0x1a))
        self.assertEqual(events,[('alloc',0x1a),('copy',0x1a)])

    def test_store_into_entry_model(self):
        # A real replaced capacity frees the replaced buffer.
        stored,freed=subject.store_into_entry((0x20,0x5000,0x1c),(0x40,0x9000,0x05))
        self.assertEqual(stored,(0x40,0x9000,0x05))
        self.assertEqual(freed,(0x5000,0x20))
        # Sentinel and empty replaced capacities are not freed.
        for cap in (0,0x8000000000000000,0x8000000000000001):
            stored,freed=subject.store_into_entry((cap,0x1,0x0),(0x40,0x9000,0x05))
            self.assertEqual(stored,(0x40,0x9000,0x05))
            self.assertIsNone(freed)

    def test_slot_binding_counterfactual(self):
        # Flipping one byte of the consumer slot's relocation
        # addend breaks the binding derivation.
        changed=bytearray(self.data);changed[self.rela_field_offset(subject.CONSUMER_SLOT,16)]^=1
        with self.assertRaisesRegex(ValueError,'slot binding'):
            subject.analyze(changed)

    def test_memcpy_binding_counterfactual(self):
        changed=bytearray(self.data);changed[self.rela_field_offset(subject.MEMCPY_SLOT,8)+7]^=1
        with self.assertRaisesRegex(ValueError,'memcpy binding'):
            subject.analyze(changed)

    def test_owner_body_counterfactuals(self):
        # Each mutation is rejected with its specific error: the
        # body hash for the entry byte, the named pin for the
        # traced store sites.
        for va in (0x15a3b90,0x15a411f,0x15a402a):
            with self.subTest(va=hex(va)):
                with self.assertRaisesRegex(ValueError,'changed'):
                    subject.analyze(self.mutate(va))

    def test_census_counterfactual(self):
        # One byte inside an out-slot lea encoding removes that
        # access from the census pattern set (the setup pin over
        # the same bytes rejects it first, with its own error).
        with self.assertRaisesRegex(ValueError,'changed'):
            subject.analyze(self.mutate(0x15a3f3a+3))

    def test_callee_call_counterfactual(self):
        # Flipping the first callee call's opcode byte breaks the
        # pinned call and the direct-call census.
        with self.assertRaisesRegex(ValueError,'changed'):
            subject.analyze(self.mutate(0x15a3f5f))

    def test_boundary_counterfactuals(self):
        for va in (0x141e3a0,0x15ae430,0x156d840):
            with self.subTest(va=hex(va)):
                with self.assertRaisesRegex(ValueError,'body changed'):
                    subject.analyze(self.mutate(va))

    def test_boundary_citation_counterfactuals(self):
        # The re-pinned construction and delivery sites are
        # checked, not just the boundary body hashes.
        with self.assertRaisesRegex(ValueError,'consumer capacity store changed|consumer alloc call changed|changed'):
            subject.analyze(self.mutate(0x141e49d))
        with self.assertRaisesRegex(ValueError,'changed'):
            subject.analyze(self.mutate(0x15ae500))

    def test_public_identity_rejection_precedes_output(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'changed';out=Path(directory)/'out'
            p.write_bytes(self.mutate(0x15a3b90))
            for path in [p,subject.ROOT/'artifacts/visor/captured/hl-visor']:
                with self.assertRaisesRegex(ValueError,'pinned node115'):
                    subject.generate(path,out)
            p.write_bytes(self.data[:4096])
            with self.assertRaisesRegex(ValueError,'pinned node115'):
                subject.generate(p,out)
            self.assertFalse(out.exists())


if __name__=='__main__':
    unittest.main()
