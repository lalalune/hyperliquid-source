"""Real visor-byte cutset counterfactuals and isolated native-input controls."""
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
import visor_lookup_result as lookup
from elf_index import sections

PACKET = ROOT/'research/work-items/RE-013-visor-lookup-result'


class VisorLookupResultTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = lookup.TARGET.read_bytes()
        cls.sections = sections(cls.data)
        cls.record = json.loads((PACKET/'record.json').read_text())

    def offset(self,va):
        sec = next(s for s in self.sections if s['type']!=8 and s['address']<=va<s['address']+s['size'])
        return sec['offset']+va-sec['address']

    def replace(self,va,raw):
        changed = bytearray(self.data)
        offset = self.offset(va)
        changed[offset:offset+len(raw)] = raw
        return bytes(changed)

    def test_actual_target_regenerates_record_native_and_cutset(self):
        record,native = lookup.collect(self.data)
        self.assertEqual(record,self.record)
        self.assertEqual(native,(PACKET/'lookup.objdump.txt').read_bytes())
        self.assertEqual(record['normal_CFG']['decoded_instructions'],94)
        self.assertEqual(record['normal_CFG']['returns'],['0x5d335c'])
        self.assertEqual(record['return_cutset']['normal_return_low32_upper_bound'],[0,1])
        self.assertEqual([r['EAX'] for r in record['return_cutset']['cases']],[0,1,1])
        self.assertFalse(record['return_cutset']['whole_RAX_high32_proved'])
        self.assertFalse(record['return_cutset']['outcome_feasibility_or_termination_proved'])
        self.assertEqual(record['comparison_binding']['name'],'bcmp')

    def test_wrong_whole_identity_fails_before_native_provider(self):
        with mock.patch.object(lookup,'decode_slice',side_effect=AssertionError('provider must not run')):
            for data in (self.data[:64],self.replace(0x5d335e,b'\x02')):
                with self.subTest(size=len(data)),self.assertRaisesRegex(ValueError,'visor identity differs'):
                    lookup.collect(data)

    def test_noncanonical_partial_register_return_values_rejected(self):
        for va in (0x5d335e,0x5d3300):
            with self.subTest(va=hex(va)),self.assertRaisesRegex(ValueError,'domain is not canonical'):
                lookup._derive(self.replace(va,b'\x02'))

    def test_zero_predicate_width_capture_and_return_preservation_matter(self):
        cases = [(0x5d3256,b'\x84','test is not 32-bit EAX'),
                 (0x5d3301,b'\x84','test is not 32-bit ECX'),
                 (0x5d32fe,b'\xd1','does not capture EAX'),
                 (0x5d334c,b'\x09','not full EAX zeroing'),
                 (0x5d3352,b'\x58','epilogue differs')]
        for va,raw,message in cases:
            with self.subTest(va=hex(va)),self.assertRaisesRegex(ValueError,message):
                lookup._derive(self.replace(va,raw))

    def test_actual_branches_cannot_bypass_test_or_enter_epilogue(self):
        # Both counterfactual destinations are valid decoded instruction starts.
        cases = [(0x5d3265,struct.pack('<i',0x5d3352-(0x5d3263+6)),'epilogue interior'),
                 (0x5d32be,struct.pack('<b',0x5d3258-(0x5d32bd+2)),'zero-predicate chain differs')]
        for va,raw,message in cases:
            with self.subTest(va=hex(va)),self.assertRaisesRegex(ValueError,message):
                lookup._derive(self.replace(va,raw))

    def test_import_arguments_dependency_and_fde_bindings_reject_changes(self):
        row = self.record['comparison_binding']
        changed = bytearray(self.data)
        struct.pack_into('<Q',changed,row['relocation_file_offset']+8,6|(8<<32))
        with self.assertRaisesRegex(ValueError,'GLOB_DAT binding differs'):
            lookup._derive(bytes(changed))
        cases = [(0x5d324f,b'\xdb','comparison arguments differ'),
                 (0x5d3274,b'\xe9','probe dependency target differs'),
                 (0x6267b1,b'\x4a','subcall target differs')]
        for va,raw,message in cases:
            with self.subTest(va=hex(va)),self.assertRaisesRegex(ValueError,message):
                lookup._derive(self.replace(va,raw))
        fde = int(self.record['lookup_fde']['fde_va'],16)
        with self.assertRaisesRegex(ValueError,'FDE extent differs'):
            lookup._derive(self.replace(fde+12,b'\x40'))

    def test_restored_wrong_native_view_rejected_from_private_raw_input(self):
        real = subprocess.run
        private_calls = []
        def invoke(argv,*args,**kwargs):
            if argv[-1] != 'lookup.bin':
                return real(argv,*args,**kwargs)
            directory = Path(kwargs['cwd'])
            path = directory/'lookup.bin'
            original = path.read_bytes()
            self.assertEqual(len(original),321)
            self.assertEqual(directory.stat().st_mode&0o777,0o700)
            self.assertEqual(path.stat().st_mode&0o777,0o400)
            self.assertNotIn(str(lookup.TARGET),argv)
            private_calls.append(path)
            # GNU observes one changed raw opcode; restore it before the post-hash
            # to require full native-row byte binding, not only before/after hashes.
            changed = bytearray(original)
            changed[0x5d334c-lookup.START] = 0x09
            path.chmod(0o600)
            path.write_bytes(changed)
            result = real(argv,*args,**kwargs)
            path.write_bytes(original)
            path.chmod(0o400)
            return result
        before = lookup.sha(lookup.TARGET.read_bytes())
        with mock.patch.object(lookup.subprocess,'run',side_effect=invoke):
            with self.assertRaisesRegex(ValueError,'native instruction bytes differ'):
                lookup.collect(self.data)
        self.assertEqual(len(private_calls),1)
        self.assertFalse(private_calls[0].exists())
        self.assertEqual(lookup.sha(lookup.TARGET.read_bytes()),before)

    def invoke(self,binary,output):
        return subprocess.run([sys.executable,'-B',str(ROOT/'tools/visor_lookup_result.py'),
                               '--binary',str(binary),'--output',str(output)],
                              capture_output=True,text=True,timeout=30,
                              env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1'))

    def test_real_cli_spaces_and_existing_output_preserved(self):
        with tempfile.TemporaryDirectory(prefix='visor lookup ') as tmp:
            output = Path(tmp)/'record with spaces.json'
            result = self.invoke(lookup.TARGET,output)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(json.loads(output.read_text()),self.record)
            before = output.read_bytes()
            result = self.invoke(lookup.TARGET,output)
            self.assertNotEqual(result.returncode,0)
            self.assertEqual(output.read_bytes(),before)

    def test_rejected_cli_input_publishes_nothing_and_preserves_prior(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root/'wrong-visor'
            binary.write_bytes(self.data[:64])
            for prior in (False,True):
                output = root/('prior.json' if prior else 'absent.json')
                if prior:output.write_bytes(b'preserve earlier evidence\n')
                result = self.invoke(binary,output)
                self.assertNotEqual(result.returncode,0)
                self.assertIn('visor identity differs',result.stderr)
                if prior:self.assertEqual(output.read_bytes(),b'preserve earlier evidence\n')
                else:self.assertFalse(output.exists())

    def test_packet_checker_rejects_false_record_and_native_export(self):
        spec = importlib.util.spec_from_file_location('visor_lookup_packet_check',PACKET/'check_packet.py')
        checker = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(checker)
        self.assertEqual(checker.verify(PACKET,self.data)['normal_return_low32_upper_bound'],[0,1])
        with tempfile.TemporaryDirectory() as tmp:
            packet = Path(tmp)/'packet'
            shutil.copytree(PACKET,packet)
            path = packet/'record.json'
            record = json.loads(path.read_text())
            record['return_cutset']['normal_return_low32_upper_bound'] = [0,2]
            path.write_text(json.dumps(record))
            with self.assertRaisesRegex(ValueError,'record differs'):
                checker.verify(packet,self.data)
            path.write_text(json.dumps(self.record))
            native = packet/'lookup.objdump.txt'
            native.write_bytes(native.read_bytes().replace(b'mov    al,0x1',b'mov    al,0x2',1))
            with self.assertRaisesRegex(ValueError,'native export differs'):
                checker.verify(packet,self.data)


if __name__ == '__main__':
    unittest.main()
