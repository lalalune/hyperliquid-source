"""Native target evidence and actual table method counterfactuals."""
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import table_method_static as subject
from elf_index import sections


class TableMethodTests(unittest.TestCase):
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
        self.assertEqual(sum(x['bytes'] for x in self.report['owners']),97)
        with tempfile.TemporaryDirectory() as directory:
            out=Path(directory);subject.generate(subject.TARGET,out)
            for p in out.iterdir():self.assertEqual(p.read_bytes(),(subject.PACKET/p.name).read_bytes(),p.name)

    def test_census_and_bindings(self):
        census=self.report['reference_census']
        self.assertEqual(census['method_direct'],0)
        self.assertEqual(census['method_rip_relative_refs'],[])
        self.assertEqual(census['method_address_as_data'],0)
        self.assertEqual(census['table_rip_relative_refs'],['0x141e4ad','0x141ed86'])
        self.assertEqual(census['method_slot_rip_relative_refs'],[])
        binding=self.report['table_binding']
        self.assertEqual(binding['table'],'0x63f3d50')
        self.assertEqual(binding['section'],'.data.rel.ro')
        self.assertEqual(binding['method_slot'],'0x63f3d68')
        self.assertEqual(binding['method_addend_slots'],['0x63f3d68'])
        self.assertEqual([w['file_value'] for w in binding['words']],[0,0x18,8,0])
        self.assertEqual([w['relocation'] and w['relocation']['addend'] for w in binding['words']],
                         ['0x141c960',None,None,'0x141e8f0'])
        memcpy=self.report['memcpy_binding']
        self.assertEqual(memcpy['slot'],'0x64df508')
        self.assertEqual(memcpy['symbol'],'memcpy')
        self.assertEqual(memcpy['relocation_type_name'],'R_X86_64_GLOB_DAT')
        self.assertFalse(self.report['captured_code_executed'])

    def test_trace_sites_pinned(self):
        trace=self.report['method']
        self.assertEqual(trace['arguments'],{'out':'rdi','string':'rsi','length':'rdx'})
        self.assertEqual(trace['out_layout'],{'capacity':'+0x0','buffer_pointer':'+0x8','length':'+0x10'})
        self.assertEqual(trace['capacity_load']['site'],'0x141e901')
        self.assertEqual(trace['length_load']['site'],'0x141e904')
        self.assertEqual(trace['remaining']['branch_target'],'0x141e937')
        self.assertEqual(trace['zero_length']['skips_to'],'0x141e925')
        self.assertEqual(trace['copy']['call'],'0x141e91f')
        self.assertEqual(trace['copy']['slot'],'0x64df508')
        self.assertEqual(trace['length_store']['site'],'0x141e928')
        self.assertTrue(trace['length_store']['only_store_to_out'])
        self.assertEqual(trace['return']['value'],0)
        slow=trace['slow_path']
        self.assertEqual(slow['grow_target'],'0x141c980')
        self.assertEqual(slow['grow_arguments'],{'rdi':'out','rsi':'current length','rdx':'requested length'})
        self.assertEqual(slow['rejoin_target'],'0x141e915')
        self.assertFalse(slow['capacity_rechecked'])
        boundaries={b['role']:(b['start'],b['bytes']) for b in self.report['boundaries']}
        self.assertEqual(boundaries['grow'],('0x141c980',114))
        self.assertEqual(boundaries['table_word0_function'],('0x141c960',21))

    def test_method_model_fast_path(self):
        events=[]
        # Fits: copied at the current length, length advances, no grow.
        self.assertEqual(subject.simulate_write(64,10,5,events),(0,15,5))
        self.assertEqual(events,[('copy',10,5)])

    def test_method_model_exact_fit_takes_fast_path(self):
        events=[]
        # Requested length equal to the remaining space does not grow:
        # the branch is taken only when the request exceeds it.
        self.assertEqual(subject.simulate_write(64,10,54,events),(0,64,54))
        self.assertEqual(events,[('copy',10,54)])

    def test_method_model_grow_then_copy_without_recheck(self):
        events=[]
        self.assertEqual(subject.simulate_write(64,10,55,events),(0,65,55))
        self.assertEqual(events,[('grow',10,55),('copy',10,55)])

    def test_method_model_zero_length_skips_copy(self):
        events=[]
        self.assertEqual(subject.simulate_write(64,10,0,events),(0,10,0))
        self.assertEqual(events,[])

    def test_table_binding_counterfactual(self):
        # Flipping one byte of the method slot's relocation addend
        # breaks the binding derivation.
        changed=bytearray(self.data);changed[self.rela_field_offset(subject.METHOD_SLOT,16)]^=1
        with self.assertRaisesRegex(ValueError,'table binding'):
            subject.analyze(changed)

    def test_table_word_counterfactual(self):
        # The literal +0x8 table word (0x18) is pinned from the file.
        with self.assertRaisesRegex(ValueError,'table word'):
            subject.analyze(self.mutate(subject.TABLE+8))

    def test_memcpy_binding_counterfactual(self):
        # Flipping a byte of the memcpy slot's relocation info
        # (symbol index) breaks the binding derivation.
        changed=bytearray(self.data);changed[self.rela_field_offset(subject.MEMCPY_SLOT,8)+7]^=1
        with self.assertRaisesRegex(ValueError,'memcpy binding'):
            subject.analyze(changed)

    def test_body_counterfactuals(self):
        for va in (0x141e901,0x141e928,0x141e943):
            with self.subTest(va=hex(va)):
                with self.assertRaisesRegex(ValueError,'body changed'):
                    subject.analyze(self.mutate(va))

    def test_boundary_counterfactual(self):
        with self.assertRaisesRegex(ValueError,'body changed'):
            subject.analyze(self.mutate(0x141c980))

    def test_lea_target_counterfactual(self):
        # One byte inside a table lea displacement removes that
        # reference from the census.
        with self.assertRaisesRegex(ValueError,'census'):
            subject.analyze(self.mutate(0x141e4ad+3))

    def test_public_identity_rejection_precedes_output(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'changed';out=Path(directory)/'out'
            p.write_bytes(self.mutate(0x141e8f0))
            for path in [p,subject.ROOT/'artifacts/visor/captured/hl-visor']:
                with self.assertRaisesRegex(ValueError,'pinned node115'):
                    subject.generate(path,out)
            p.write_bytes(self.data[:4096])
            with self.assertRaisesRegex(ValueError,'pinned node115'):
                subject.generate(p,out)
            self.assertFalse(out.exists())


if __name__=='__main__':
    unittest.main()
