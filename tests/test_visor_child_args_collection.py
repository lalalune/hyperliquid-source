"""Actual-byte premise controls; symbolic examples are model support only."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import visor_child_args_collection as collect
from elf_index import sections
PACKET = ROOT/'research/work-items/RE-013-visor-child-args-collection'


class VisorCollectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = collect.TARGET.read_bytes()
        cls.sections = sections(cls.data)
        cls.record = json.loads((PACKET/'record.json').read_text())
        cls.terms = cls.record['actual_terms']

    def offset(self,va):
        section = next(s for s in self.sections if s['type']!=8 and s['address']<=va<s['address']+s['size'])
        return section['offset']+va-section['address']

    def change(self,va,raw):
        value = bytearray(self.data);offset = self.offset(va)
        value[offset:offset+len(raw)] = raw
        return bytes(value)

    def test_complete_actual_body_record_and_conditional_projection(self):
        record,exports = collect.collect(self.data)
        self.assertEqual(record,self.record)
        for name,raw in exports.items():self.assertEqual(raw,(PACKET/name).read_bytes())
        graph = record['graph']
        self.assertEqual((graph['instructions'],len(graph['blocks']),len(graph['branches']),len(graph['calls'])),(220,61,33,16))
        self.assertEqual(graph['normal_projection_reachable_instructions'],176)
        self.assertEqual(graph['open_normal_boundaries'],['0x61dd6c'])
        self.assertEqual(record['conditional_projection']['reachable_instruction_nodes'],144)
        self.assertFalse(record['conditional_projection']['growth_call_reached'])
        self.assertFalse(record['proof_method']['automatic_general_machine_equivalence_verifier'])
        self.assertEqual(record['actual_copy_symbol']['name'],'memcpy')

    def test_full_target_identity_refused_before_native_provider(self):
        with mock.patch.object(collect.subprocess,'run',side_effect=AssertionError('native provider must not run')):
            for bad in (self.data[:64],self.change(0x61dc72,b'\x10')):
                with self.assertRaisesRegex(ValueError,'visor identity differs'):collect.collect(bad)

    def test_actual_capacity_stride_and_guard_mutations_rejected(self):
        cases=[(0x61dac8,b'\x04'),(0x61dacb,b'\xaa'),(0x61dadd,b'\x02'),
               (0x61dada,b'\x05'),(0x61dae9,b'\x10'),(0x61dc72,b'\x10'),
               (0x61daf3,b'\xf0'),(0x61da43,b'\x10')]
        for va,raw in cases:
            with self.subTest(va=hex(va)),self.assertRaisesRegex(ValueError,'block binding differs|block domain differs'):
                collect._derive(self.change(va,raw))

    def test_stop_zero_length_row_and_final_store_mutations_rejected(self):
        cases=[(0x61da39,b'\xd2'),(0x61db98,b'\xd2'), # test length instead of returned pointer
               (0x61dab8,b'\x00'),(0x61dbf3,b'\x00'), # empty payload is raw pointer1
               (0x61da5f,b'\x00'),                    # raw empty output8 becomes0
               (0x61dc8c,b'\x08'),                    # count overwrites output pointer word
               (0x61dc52,b'\x69'),                    # row pointer store no longer its copy pointer
               (0x61da1d,b'\x40')]                    # caller local frame no longer72B
        for va,raw in cases:
            with self.subTest(va=hex(va)),self.assertRaisesRegex(ValueError,'block binding differs|block domain differs'):
                collect._derive(self.change(va,raw))

    def test_real_loop_branch_bypass_rejected(self):
        # Skip the next callback on a backedge, landing at an actual instruction.
        displacement = struct.pack('<i',0x61db90-(0x61dc7e+6))
        with self.assertRaisesRegex(ValueError,'block binding differs|block domain differs'):
            collect._derive(self.change(0x61dc80,displacement))

    def test_fde_relocations_symbol_and_actual_prerequisites_rejected(self):
        allocator = next(r for r in self.record['used_bindings'] if r['slot']=='0x7e4b60')
        bad = bytearray(self.data);struct.pack_into('<q',bad,allocator['file_offset']+16,0x70bf31)
        with self.assertRaisesRegex(ValueError,'binding differs'):collect._derive(bytes(bad))
        symbol = self.record['actual_copy_symbol']
        bad = bytearray(self.data);bad[symbol['name_file_offset']+3] = ord('x')
        with self.assertRaisesRegex(ValueError,'copy import name differs'):collect._derive(bytes(bad))
        bad = bytearray(self.data);struct.pack_into('<Q',bad,symbol['symbol_section_header_file_offset']+56,16)
        with self.assertRaisesRegex(ValueError,'dynsym index/stride'):collect._derive(bytes(bad))
        fde = int(self.record['range']['fde_va'],16)
        with self.assertRaisesRegex(ValueError,'FDE extent differs'):collect._derive(self.change(fde+12,b'\x5b'))
        with self.assertRaisesRegex(ValueError,'descriptor/call differs'):collect._derive(self.change(0x5b9227,b'\x74'))
        with self.assertRaisesRegex(ValueError,'UTF8 adapter body differs'):collect._derive(self.change(0x48dc18,b'\x00'))

    def test_capacity_arithmetic_boundary_support_only(self):
        for n in list(range(1,257))+[1<<32,collect.ISIZE_MAX//24]:
            facts = collect.capacity_facts(n,self.terms)
            self.assertEqual(facts['capacity_on_allocation_branch'],max(4,n))
            self.assertEqual(facts['record_allocation_request'],24*max(4,n))
            self.assertTrue(facts['strict_preappend_bound'])
            self.assertEqual(facts['all_preappend_completed_counts'],[0,n-1])
        self.assertTrue(collect.capacity_facts(4,self.terms)['final_completed_count_may_equal_capacity'])
        self.assertEqual(collect.capacity_facts(collect.ISIZE_MAX//24,self.terms)['remaining_descriptor_bytes'],0x7fffffffffffffe0)
        for bad in (0,-1,collect.ISIZE_MAX//24+1,True):
            with self.assertRaises(ValueError):collect.capacity_facts(bad,self.terms)
        wrong=dict(self.terms,inverse_three=self.terms['inverse_three']-1)
        with self.assertRaisesRegex(ValueError,'algebra differs'):collect.capacity_facts(8,wrong)

    def test_symbolic_prefix_zero_stop_and_order_model_support_only(self):
        with mock.patch.object(collect,'capacity_facts',side_effect=AssertionError('no allocation capacity on empty routes')):
            self.assertEqual(collect.prefix_model(0,[],self.terms)['output_words'],[0,8,0])
            immediate=collect.prefix_model(3,[(0,-1)],self.terms)
            self.assertEqual(immediate['output_words'],[0,8,0])
            self.assertEqual(immediate['callback_indices'],[0])
        for n in range(1,9):
            for stop in range(n+1):
                callbacks=[(0x1000+24*i,0 if i%2==0 else i+1) for i in range(n)]
                if stop<n:callbacks[stop]=(0,collect.U64_END-1)
                model=collect.prefix_model(n,callbacks,self.terms)
                self.assertEqual(len(model['records']),stop)
                self.assertEqual(model['callback_indices'],list(range(min(stop+1,n))))
                if stop:self.assertEqual(model['output_words'],[max(4,n),'fresh-record-buffer',stop])
                self.assertEqual(model['growth_calls'],0)
        model=collect.prefix_model(3,[(99,0),(88,2),(77,0)],self.terms)
        self.assertEqual(model['records'],[[0,1,0],[2,'fresh-payload-1',2],[0,1,0]])
        self.assertEqual(model['positive_copy_requests'][0]['source'],88)
        self.assertEqual(model['positive_copy_requests'][0]['bytes'],2)
        # No original instructions or callback implementation are executed here.

    def test_interval_frame_return_and_alias_domain_counterexamples(self):
        a,start,q,s=0x100000,0x200000,0x300000,0x400008
        protected=[(0x61da10,0x61dd6c)]
        good=collect.memory_domain(a,start,start+48,q,s,[(0x500000,0x500010)],protected)
        self.assertEqual(good['descriptor_count'],2)
        self.assertTrue(good['readability_immutability_freshness_callee_frames_and_hardware_return_not_checked'])
        for x,z in ((start,start+1),(start+24,start),(0,collect.U64_END),(0,collect.ISIZE_MAX+1)):
            with self.assertRaises(ValueError):collect.descriptor_domain(x,z)
        cases=[(a,start,start+48,s,s,[]),(s-48,start,start+48,q,s,[]),
               (a,s-48,s,q,s,[]),(a,start,start+48,q,s,[(s,s+1)]),
               (a,start,start+48,0x61da10,s,[]),(a,start,start+48,q,s+8,[])]
        for args in cases:
            with self.assertRaises(ValueError):collect.memory_domain(*args,protected)

    def test_restored_wrong_private_native_view_rejected(self):
        real=subprocess.run;seen=[]
        def invoke(argv,*args,**kwargs):
            if argv[-1]!='collection.bin':return real(argv,*args,**kwargs)
            p=Path(kwargs['cwd'])/'collection.bin';original=p.read_bytes()
            self.assertEqual(len(original),860);self.assertEqual(p.stat().st_mode&0o777,0o400)
            self.assertNotIn(str(collect.TARGET),argv);seen.append(p)
            changed=bytearray(original);changed[0x61dc72-collect.START]=0x10
            p.chmod(0o600);p.write_bytes(changed);r=real(argv,*args,**kwargs)
            p.write_bytes(original);p.chmod(0o400);return r
        before=collect.sha(collect.TARGET.read_bytes())
        with mock.patch.object(collect.subprocess,'run',side_effect=invoke):
            with self.assertRaisesRegex(ValueError,'native row bytes differ'):collect.collect(self.data)
        self.assertEqual(len(seen),1);self.assertFalse(seen[0].exists())
        self.assertEqual(collect.sha(collect.TARGET.read_bytes()),before)

    def test_real_cli_preserves_prior_report_and_rejected_input(self):
        def run(binary,output):return subprocess.run([sys.executable,'-B',str(ROOT/'tools/visor_child_args_collection.py'),
              '--binary',str(binary),'--output',str(output)],capture_output=True,text=True,timeout=30,
              env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1'))
        with tempfile.TemporaryDirectory(prefix='collection spaces ') as temporary:
            p=Path(temporary);output=p/'record with spaces.json'
            first=run(collect.TARGET,output);self.assertEqual(first.returncode,0,first.stderr)
            self.assertEqual(json.loads(output.read_text()),self.record);prior=output.read_bytes()
            self.assertNotEqual(run(collect.TARGET,output).returncode,0);self.assertEqual(output.read_bytes(),prior)
            wrong=p/'wrong';wrong.write_bytes(self.data[:64])
            absent=p/'absent';self.assertNotEqual(run(wrong,absent).returncode,0);self.assertFalse(absent.exists())
            self.assertNotEqual(run(wrong,output).returncode,0);self.assertEqual(output.read_bytes(),prior)

    def test_packet_reproduction_and_changed_record_or_native_rejected(self):
        spec=importlib.util.spec_from_file_location('collection_packet',PACKET/'check_packet.py')
        checker=importlib.util.module_from_spec(spec);spec.loader.exec_module(checker)
        self.assertEqual(checker.verify(PACKET,self.data)['conditional_projection_nodes'],144)
        with tempfile.TemporaryDirectory() as temporary:
            packet=Path(temporary)/'packet';shutil.copytree(PACKET,packet)
            p=packet/'record.json';r=json.loads(p.read_text());r['actual_terms']['zero_length_pointer_word']=0
            p.write_text(json.dumps(r))
            with self.assertRaisesRegex(ValueError,'record differs'):checker.verify(packet,self.data)
            p.write_text(json.dumps(self.record));native=packet/'collection.objdump.txt'
            native.write_bytes(native.read_bytes().replace(b'0x18',b'0x10',1))
            with self.assertRaisesRegex(ValueError,'native export differs'):checker.verify(packet,self.data)
