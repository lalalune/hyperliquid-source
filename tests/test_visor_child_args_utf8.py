"""Real target proof-premise controls; codec checks are high-level model support."""
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
import visor_child_args_utf8 as utf8
from elf_index import sections
PACKET = ROOT/'research/work-items/RE-013-visor-child-args-utf8'


class VisorChildArgsUtf8Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = utf8.TARGET.read_bytes()
        cls.sections = sections(cls.data)
        cls.record = json.loads((PACKET/'record.json').read_text())

    def offset(self,va):
        s = next(s for s in self.sections if s['type']!=8 and s['address']<=va<s['address']+s['size'])
        return s['offset']+va-s['address']

    def replace(self,va,raw):
        result = bytearray(self.data)
        offset = self.offset(va)
        result[offset:offset+len(raw)] = raw
        return bytes(result)

    def test_actual_full_bodies_graph_table_protocol_and_witnesses(self):
        record,exports = utf8.collect(self.data)
        self.assertEqual(record,self.record)
        for name,raw in exports.items():
            self.assertEqual(raw,(PACKET/name).read_bytes())
        v,a = record['graphs']['validator'],record['graphs']['adapter']
        self.assertEqual((v['decoded_instructions'],v['reachable_instruction_nodes'],len(v['blocks'])),(143,140,57))
        self.assertEqual(len(v['branches']),48)
        self.assertEqual(v['calls'],[])
        self.assertEqual(v['returns'],['0x49b756'])
        self.assertEqual((a['decoded_instructions'],len(a['blocks'])),(15,4))
        self.assertEqual(a['open_normal_boundaries'],['0x48dc43'])
        self.assertEqual(len(record['lead_table']['entries']),256)
        self.assertEqual(record['defined_result_protocol']['incomplete']['byte17'],'unqualified')
        self.assertEqual(record['caller_witness']['revisited_witness_bytes'],92)
        self.assertFalse(record['proof_method']['automatic_general_machine_semantic_verifier'])
        self.assertFalse(record['finite_predicate_support']['wholePredicateEstablishedByTheseSetsAlone'])

    def test_whole_identity_rejected_before_any_native_provider(self):
        with mock.patch.object(utf8.subprocess,'run',side_effect=AssertionError('no native provider')):
            for data in (self.data[:64],self.replace(0x49b5d3,b'\x11')):
                with self.subTest(size=len(data)),self.assertRaisesRegex(ValueError,'visor identity differs'):
                    utf8.collect(data)

    def test_used_width_mutations_rejected_but_unused_ascii_entry_is_not_semantics(self):
        for lead,width in ((0xc0,2),(0xe0,4),(0xf5,4)):
            with self.subTest(lead=hex(lead)),self.assertRaisesRegex(ValueError,'nonASCII lead widths differ'):
                utf8._derive(self.replace(0x8047e+lead,bytes([width])))
        counterfactual,_ = utf8._derive(self.replace(0x8047e+0x41,b'\x00'))
        self.assertNotEqual(counterfactual['lead_table']['sha256'],self.record['lead_table']['sha256'])
        self.assertEqual(counterfactual['finite_predicate_support'],self.record['finite_predicate_support'])
        self.assertEqual(utf8.contract_model(b'A',counterfactual['lead_table']['entries'],
                                           counterfactual['finite_predicate_support']['sets']),
                         {'tag':0,'input_length':1,'same_input_span':True})

    def test_complete_block_binding_rejects_cursor_bounds_and_continuation_changes(self):
        cases = [(0x49b589,b'\xb1\x01'), # lose full cursor initialization
                 (0x49b5d3,b'\x11'),     # skip unchecked byte after an ASCII chunk
                 (0x49b570,b'\x0e'),     # unsafe n-14 instead of n-15 wide-read guard
                 (0x49b5d7,b'\x77'),     # unsigned > instead of >= at the bulk bound
                 (0x49b631,b'\x00'),     # second-byte offset loses +1
                 (0x49b5a2,b'\xce'),     # DEC R14 instead of INC at valid join
                 (0x49b6b0,b'\x80'),     # permit E0 overlong second bytes
                 (0x49b6a1,b'\x9f'),     # permit out-of-range F4 second bytes
                 (0x49b71c,b'\x00')]     # wrong last continuation threshold
        for va,raw in cases:
            with self.subTest(va=hex(va)),self.assertRaisesRegex(ValueError,'block binding differs|block domain differs'):
                utf8._derive(self.replace(va,raw))

    def test_defined_protocol_and_adapter_route_are_bound(self):
        cases = [(0x49b74a,b'\x00'),      # error tag becomes success
                 (0x49b740,b'\x50'),      # prefix overwritten by length register
                 (0x49b735,b'\xd2'),      # incomplete flag no longer cleared in R9
                 (0x49b73d,b'\x03'),      # invalid-third width changes2->3
                 (0x49b724,b'\x02'),      # invalid-fourth width changes3->2
                 (0x49b729,b'\x78'),      # success span pointer no longer original RSI
                 (0x48dc18,b'\x00'),      # success/error tag test reversed
                 (0x48dc1f,b'\x10')]      # adapter returns length as pointer
        for va,raw in cases:
            with self.subTest(va=hex(va)),self.assertRaisesRegex(ValueError,'block binding differs|block domain differs'):
                utf8._derive(self.replace(va,raw))

    def test_actual_branch_bypass_does_not_survive_complete_ledger(self):
        # Redirect an incomplete-width2 edge onto the valid second-byte load.
        changed = self.replace(0x49b637,struct.pack('<i',0x49b63b-(0x49b635+6)))
        with self.assertRaisesRegex(ValueError,'block binding differs|block domain differs'):
            utf8._derive(changed)

    def test_fde_relocation_and_actual_caller_provenance_rejected(self):
        row = next(r for r in self.record['used_bindings'] if r['slot']=='0x7e4d28')
        data = bytearray(self.data)
        struct.pack_into('<q',data,row['file_offset']+16,0x49b561)
        with self.assertRaisesRegex(ValueError,'binding differs'):
            utf8._derive(bytes(data))
        fde = int(self.record['ranges']['validator']['fde_va'],16)
        with self.assertRaisesRegex(ValueError,'FDE extent differs'):
            utf8._derive(self.replace(fde+12,b'\xf6'))
        with self.assertRaisesRegex(ValueError,'descriptor/collection call differs'):
            utf8._derive(self.replace(0x5b9227,b'\x74'))

    def test_domain_counterexamples_include_return_slots_image_and_input_saves(self):
        protected = [(int(a,16),int(z,16)) for a,z in self.record['domain']['protected_image_intervals']]
        p,q,s = 0x10000000,0x20000000,0x30000008
        result = utf8.domain_arithmetic(p,16,q,s,protected)
        self.assertFalse(result['permissions_immutability_and_valid_call_return_state_checked'])
        bad = [(p,16,s,s),          # q=S overwrites RET, initial proof-domain counterexample
               (s-24,1,q,s),      # pushes would overwrite input
               (s,1,q,s),         # explicit return-region separation
               (q,1,q,s),         # result/input alias
               (p,16,0x49b560,s), # result aliases immutable captured code
               (p,16,utf8.U64_END-8,s),
               (p,utf8.ISIZE_MAX+1,q,s)]
        for args in bad:
            with self.subTest(args=args),self.assertRaises(ValueError):
                utf8.domain_arithmetic(*args,protected)
        composed = utf8.adapter_domain_arithmetic(p,16,s,protected)
        self.assertEqual(composed['combined_adapter_stack_and_return'],[s-56,s+8])
        with self.assertRaises(ValueError):
            utf8.adapter_domain_arithmetic(s,1,s,protected)
        self.assertTrue(utf8.domain_arithmetic(0,0,q,s,protected)['arithmetic_nonalias_checks'])

    def test_high_level_model_only_matches_strict_codec_boundary_protocol(self):
        table = self.record['lead_table']['entries']
        predicates = self.record['finite_predicate_support']['sets']
        vectors = [bytes([i]) for i in range(256)]
        vectors += [chr(i).encode() for i in (0,0x7f,0x80,0x7ff,0x800,0xd7ff,0xe000,0xffff,0x10000,0x10ffff)]
        edges = [b'\xc2',b'\xc2A',b'\xc0\x80',b'\xe0\x80',b'\xe0\xa0',b'\xe0\xa0A',
                 b'\xed\xa0\x80',b'\xed\x9f\xbf',b'\xf0\x80',b'\xf0\x90',b'\xf0\x90\x80',
                 b'\xf0\x90\x80A',b'\xf4\x8f\xbf\xbf',b'\xf4\x90\x80\x80',b'\xf5\x80\x80\x80']
        for n in (0,1,7,8,14,15,16,17,31,32,33):
            vectors.append(b'A'*n)
            vectors += [b'A'*n+value for value in edges]
        for payload in vectors:
            with self.subTest(hex=payload.hex()):
                model = utf8.contract_model(payload,table,predicates)
                try:
                    payload.decode('utf-8','strict')
                except UnicodeDecodeError as error:
                    incomplete = error.reason=='unexpected end of data'
                    self.assertEqual(model,{'tag':1,'valid_prefix':error.start,
                                            'width_present':0 if incomplete else 1,
                                            'error_width':None if incomplete else error.end-error.start})
                else:
                    self.assertEqual(model,{'tag':0,'input_length':len(payload),'same_input_span':True})
        # This method runs no original instructions; the complete static proof
        # and its exact target bindings, not codec examples, justify the target claim.

    def test_restored_wrong_private_gnu_view_rejected_without_target_mutation(self):
        real = subprocess.run
        paths = []
        def invoke(argv,*args,**kwargs):
            if argv[-1] != 'validator.bin':
                return real(argv,*args,**kwargs)
            directory = Path(kwargs['cwd'])
            path = directory/'validator.bin'
            original = path.read_bytes()
            self.assertEqual(len(original),503)
            self.assertEqual(directory.stat().st_mode&0o777,0o700)
            self.assertEqual(path.stat().st_mode&0o777,0o400)
            self.assertNotIn(str(utf8.TARGET),argv)
            paths.append(path)
            changed = bytearray(original)
            changed[0x49b5d3-0x49b560] = 0x11
            path.chmod(0o600)
            path.write_bytes(changed)
            result = real(argv,*args,**kwargs)
            path.write_bytes(original)
            path.chmod(0o400)
            return result
        before = utf8.sha(utf8.TARGET.read_bytes())
        with mock.patch.object(utf8.subprocess,'run',side_effect=invoke):
            with self.assertRaisesRegex(ValueError,'native row bytes differ'):
                utf8.collect(self.data)
        self.assertEqual(len(paths),1)
        self.assertFalse(paths[0].exists())
        self.assertEqual(utf8.sha(utf8.TARGET.read_bytes()),before)

    def invoke(self,binary,output):
        return subprocess.run([sys.executable,'-B',str(ROOT/'tools/visor_child_args_utf8.py'),
                               '--binary',str(binary),'--output',str(output)],capture_output=True,
                              text=True,timeout=30,env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1'))

    def test_real_cli_preserves_existing_and_rejected_input_boundaries(self):
        with tempfile.TemporaryDirectory(prefix='vutf8 spaces ') as tmp:
            root = Path(tmp)
            output = root/'record with spaces.json'
            first = self.invoke(utf8.TARGET,output)
            self.assertEqual(first.returncode,0,first.stderr)
            self.assertEqual(json.loads(output.read_text()),self.record)
            before = output.read_bytes()
            self.assertNotEqual(self.invoke(utf8.TARGET,output).returncode,0)
            self.assertEqual(output.read_bytes(),before)
            wrong = root/'wrong-visor'
            wrong.write_bytes(self.data[:64])
            for prior in (False,True):
                result_path = root/('prior.json' if prior else 'absent.json')
                if prior:result_path.write_bytes(b'preserve earlier evidence\n')
                result = self.invoke(wrong,result_path)
                self.assertNotEqual(result.returncode,0)
                self.assertIn('visor identity differs',result.stderr)
                if prior:self.assertEqual(result_path.read_bytes(),b'preserve earlier evidence\n')
                else:self.assertFalse(result_path.exists())

    def test_packet_checker_rejects_changed_record_or_native(self):
        spec = importlib.util.spec_from_file_location('vutf8_packet',PACKET/'check_packet.py')
        checker = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(checker)
        self.assertEqual(checker.verify(PACKET,self.data)['validator_blocks'],57)
        with tempfile.TemporaryDirectory() as tmp:
            packet = Path(tmp)/'packet'
            shutil.copytree(PACKET,packet)
            record_path = packet/'record.json'
            record = json.loads(record_path.read_text())
            record['defined_result_protocol']['incomplete']['byte17'] = 0
            record_path.write_text(json.dumps(record))
            with self.assertRaisesRegex(ValueError,'record differs'):
                checker.verify(packet,self.data)
            record_path.write_text(json.dumps(self.record))
            native = packet/'validator.objdump.txt'
            native.write_bytes(native.read_bytes().replace(b'0x10',b'0x11',1))
            with self.assertRaisesRegex(ValueError,'native export differs'):
                checker.verify(packet,self.data)


if __name__=='__main__':
    unittest.main()
