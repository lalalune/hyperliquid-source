"""Native target evidence and actual map-owner counterfactuals."""
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import map_owner_static as subject
from elf_index import sections


class MapOwnerTests(unittest.TestCase):
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
        self.assertEqual(sum(x['bytes'] for x in self.report['owners']),15451)
        with tempfile.TemporaryDirectory() as directory:
            out=Path(directory);subject.generate(subject.TARGET,out)
            for p in out.iterdir():self.assertEqual(p.read_bytes(),(subject.PACKET/p.name).read_bytes(),p.name)

    def test_census_and_bindings(self):
        census=self.report['map_owner']['consumer']['handle']['access_census']
        self.assertEqual(census['root_store_imm'],['0x15a3d24'])
        self.assertEqual(census['size_store_imm'],['0x15a3d30'])
        self.assertEqual(census['root_load_rax'],['0x15a4055','0x15a4353','0x15a453c'])
        self.assertEqual(census['root_load_rcx'],['0x15a5506','0x15a63d1'])
        self.assertEqual(census['root_lea_rcx'],['0x15a417c','0x15a4456'])
        self.assertEqual(census['height_load_rcx'],['0x15a4066','0x15a4364','0x15a4560'])
        self.assertEqual(census['height_load_rdx'],['0x15a5513','0x15a63e4'])
        self.assertEqual(census['size_load_rax'],['0x15a551b','0x15a63ec'])
        self.assertEqual(census['height_stores'],[])
        self.assertEqual(census['total_accesses'],16)
        calls=self.report['map_owner']['direct_calls']
        self.assertEqual(calls['large_consumer']['sites'],['0x15a6556'])
        self.assertEqual(calls['large_consumer']['containing_fdes'],['0x15a6510'])
        self.assertEqual(calls['map_insert']['sites'],['0x15a41eb','0x15a44c8'])
        self.assertEqual(calls['insert_delegate']['sites'],['0x156d88b'])
        self.assertEqual([s for s in calls['collect_helper']['sites'] if s in ('0x15a5580','0x15a6459','0x15a64b5')],
                         ['0x15a5580','0x15a6459','0x15a64b5'])
        delegate=self.report['map_owner']['delegate']
        self.assertEqual(delegate['dealloc_sites'],
                         ['0x1495ed2','0x1495f3f','0x1495f4f','0x1495f9d','0x1495fd3','0x1495fee'])
        collect=self.report['map_owner']['collect']['layout_census']
        self.assertEqual(collect['count_load'],['0x153bb67'])
        self.assertEqual(collect['count_compare'],['0x153bc8e'])
        self.assertIn('0x153baf0',collect['child_accesses'])
        bindings=self.report['slot_bindings']
        self.assertEqual(bindings['alloc']['addend'],'0x6355830')
        self.assertEqual(bindings['dealloc']['addend'],'0x635de30')
        self.assertEqual(bindings['assert_format']['addend'],'0x1680e60')
        self.assertEqual(bindings['memmove']['symbol'],'memmove')
        self.assertFalse(self.report['captured_code_executed'])

    def test_trace_facts(self):
        trace=self.report['map_owner']
        self.assertEqual(trace['consumer']['handle']['frame_offsets'],
                         {'root':'0x178','height':'0x180','size':'0x188'})
        self.assertEqual(trace['node_layout']['count_word'],'+0x112')
        self.assertEqual(trace['node_layout']['key_bytes'],'+0x114')
        self.assertEqual(trace['node_layout']['max_entries'],11)
        self.assertEqual(trace['insert']['creation_path']['root_store'],'0x156d8cb')
        self.assertEqual(trace['insert']['creation_path']['height_zero'],'0x156d8cf')
        self.assertEqual(trace['insert']['common_exit']['size_increment'],'0x156d91b')
        self.assertEqual(trace['delegate']['root_split']['root_store'],'0x1495cf3')
        self.assertEqual(trace['delegate']['root_split']['height_store'],'0x1495cf7')
        self.assertEqual(trace['consumer']['phase2_probe']['capacity_compare'],'0x15a45e0')
        self.assertEqual(trace['consumer']['drain']['collect_call'],'0x15a5580')
        self.assertEqual(trace['consumer']['drain']['free_call'],'0x15a55ca')
        self.assertEqual(trace['sole_caller']['call'],'0x15a6556')
        boundaries={b['role']:(b['start'],b['bytes']) for b in self.report['boundaries']}
        self.assertEqual(boundaries['caller_wrapper'],('0x15a6510',356))
        self.assertEqual(boundaries['second_structure_helper'],('0x1542870',322))
        owners={o['role']:(o['start'],o['bytes']) for o in self.report['owners']}
        self.assertEqual(owners['insert_delegate'],('0x1495230',3532))
        self.assertEqual(owners['collect_helper'],('0x153ba90',938))

    def test_handle_models(self):
        # The loop head zeroes root and size but preserves the
        # height the insert family last wrote.
        self.assertEqual(subject.initialise_handle(3),
                         {'root':0,'height':3,'size':0})
        # Creation writes the root, zeroes the height, and the
        # common exit increments the size.
        self.assertEqual(subject.insert_into_empty({'root':0,'height':0,'size':0},0x5000),
                         {'root':0x5000,'height':0,'size':1})
        # A non-split delegate insert changes only the size.
        self.assertEqual(subject.insert_existing({'root':0x5000,'height':2,'size':7}),
                         {'root':0x5000,'height':2,'size':8})
        # A root split replaces the root and increments both
        # the height and the size.
        self.assertEqual(subject.root_split({'root':0x5000,'height':2,'size':7},0x9000),
                         {'root':0x9000,'height':3,'size':8})

    def test_probe_and_drain_models(self):
        self.assertFalse(subject.phase2_probe_present(0x8000000000000000))
        self.assertTrue(subject.phase2_probe_present(0))
        self.assertTrue(subject.phase2_probe_present(0x20))
        self.assertFalse(subject.drain_should_free(0))
        self.assertFalse(subject.drain_should_free(0x8000000000000000))
        self.assertTrue(subject.drain_should_free(0x5000))

    def test_slot_binding_counterfactual(self):
        changed=bytearray(self.data);changed[self.rela_field_offset(subject.ALLOC_SLOT,16)]^=1
        with self.assertRaisesRegex(ValueError,'slot binding'):
            subject.analyze(changed)

    def test_memmove_binding_counterfactual(self):
        changed=bytearray(self.data);changed[self.rela_field_offset(subject.MEMMOVE_SLOT,8)+7]^=1
        with self.assertRaisesRegex(ValueError,'memmove binding'):
            subject.analyze(changed)

    def test_owner_body_counterfactuals(self):
        for va in (0x15a3b90,0x156d840,0x1495230,0x153ba90):
            with self.subTest(va=hex(va)):
                with self.assertRaisesRegex(ValueError,'body changed'):
                    subject.analyze(self.mutate(va))

    def test_pin_counterfactuals(self):
        # Each traced site is pinned, not just hash-covered:
        # the handle initialisation store, the insert's root
        # store, the delegate's split root store, the phase-2
        # capacity compare, the drain sentinel compare, and
        # the collect helper's count load.
        for va in (0x15a3d24,0x156d8cb,0x1495cf3,0x15a45e0,0x15a55b2,0x153bb67):
            with self.subTest(va=hex(va)):
                with self.assertRaisesRegex(ValueError,'changed'):
                    subject.analyze(self.mutate(va))

    def test_delegate_dealloc_census_counterfactual(self):
        # Bending one landing pad's slot displacement removes
        # it from the dealloc census.
        with self.assertRaisesRegex(ValueError,'delegate dealloc site census changed'):
            subject.analyze(self.mutate(0x1495fee+2))

    def test_handle_census_counterfactual(self):
        # One byte inside a height load's displacement moves
        # the access out of the census pattern set.
        with self.assertRaisesRegex(ValueError,'changed'):
            subject.analyze(self.mutate(0x15a4066+4))

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
