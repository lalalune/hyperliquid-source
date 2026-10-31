"""Pinned visor startup bytes and independently corruptible static evidence."""
import json
import importlib.util
import hashlib
import os
from pathlib import Path
import subprocess
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import visor_startup as startup
from elf_index import sections

PACKET = ROOT/'research/work-items/RE-013-visor-startup-handoff/record.json'


class VisorStartupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = startup.TARGET.read_bytes()
        cls.secs = sections(cls.data)
        cls.record = json.loads(PACKET.read_text(encoding='utf-8'))

    def offset(self,va):
        s = next(s for s in self.secs if s['type'] != 8 and s['address'] <= va < s['address']+s['size'])
        return s['offset']+va-s['address']

    def mutated(self,offset):
        data = bytearray(self.data)
        data[offset] ^= 1
        return bytes(data)

    def test_actual_target_regenerates_packet(self):
        self.assertEqual(startup.build(self.data),self.record)
        self.assertEqual(self.record['coverage'],{'fde_ranges':5,'instruction_control_windows':15,
                         'selected_call_sites':17,'selected_branch_sites':6,'complete_cfg_or_call_census':False})
        self.assertEqual(self.record['startup_location']['line'],66)
        self.assertEqual(bytes.fromhex(self.record['startup_location']['path']['hex']),b'node/src/utils.rs')

    def test_public_entry_rejects_changed_or_truncated_artifact(self):
        for data in (self.data[:-1], self.mutated(self.offset(0x4e4f9e))):
            with self.subTest(size=len(data)),self.assertRaisesRegex(ValueError,'size/SHA256 differs'):
                startup.build(data)

    def test_initial_state_and_poll_call_corruptions_rejected(self):
        for va in (0x4e4f9e,0x5e3b03,0x5e4107):
            with self.subTest(va=hex(va)),self.assertRaisesRegex(ValueError,'instruction control differs'):
                startup._derive(self.mutated(self.offset(va)))

    def test_relative_call_relocation_corruption_rejected(self):
        row = next(r for r in self.record['relocations'] if r['slot']=='0x7e6ec0')
        with self.assertRaisesRegex(ValueError,'startup relocation differs'):
            startup._derive(self.mutated(row['relocation_file_offset']+16))

    def test_location_and_literal_corruptions_rejected(self):
        for va,message in ((0x7d6fe0,'Location fields differ'),(0x629f6,'Location path differs'),
                           (0xb8342,'unwrap literal differs')):
            with self.subTest(va=hex(va)),self.assertRaisesRegex(ValueError,message):
                startup._derive(self.mutated(self.offset(va)))

    def test_unwind_extent_corruption_rejected(self):
        row = next(r for r in self.record['fde_ranges'] if r['va']=='0x5e34c0')
        # The range field follows length, CIE pointer and PC-relative start.
        offset = self.offset(int(row['fde_va'],16))+12
        with self.assertRaisesRegex(ValueError,'FDE extent differs'):
            startup._derive(self.mutated(offset))

    def test_retained_linear_disassembly_checks_target_bytes_and_counts(self):
        path = PACKET.parent/'check_disassembly.py'
        spec = importlib.util.spec_from_file_location('visor_startup_boundaries',path)
        checker = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(checker)
        self.assertEqual(checker.verify(PACKET.parent,self.data),{
            'decodedRows':803,'comparedRawBytes':4209,'controlWindows':15,
            'fullCFG':False,'capturedBinaryExecuted':False})

    def test_listing_comparator_rejects_repinned_corruption_and_false_count(self):
        spec = importlib.util.spec_from_file_location('visor_startup_negative_boundaries',PACKET.parent/'check_disassembly.py')
        checker = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(checker)
        with tempfile.TemporaryDirectory() as tmp:
            packet = Path(tmp)/'packet'
            shutil.copytree(PACKET.parent,packet)
            audit_path = packet/'BOUNDARY-AUDIT.json'
            original = audit_path.read_bytes()
            audit = json.loads(original)
            listing = packet/'disassembly'/Path(audit['ranges'][0]['file']).name
            raw = listing.read_bytes()
            # Re-pin a deliberately wrong instruction byte so the target-byte
            # comparator, rather than only the listing hash, must reject it.
            changed = raw.replace(b'f3 0f 1e fa',b'f2 0f 1e fa',1)
            self.assertNotEqual(raw,changed)
            listing.write_bytes(changed)
            audit['ranges'][0]['sha256'] = hashlib.sha256(changed).hexdigest()
            audit_path.write_text(json.dumps(audit))
            with self.assertRaisesRegex(ValueError,'instruction bytes differ'):
                checker.verify(packet,self.data)
            listing.write_bytes(raw)
            audit = json.loads(original)
            audit['totalDecodedRows'] -= 1
            audit_path.write_text(json.dumps(audit))
            with self.assertRaisesRegex(ValueError,'total counts differ'):
                checker.verify(packet,self.data)

    def invoke(self,binary,output):
        return subprocess.run([sys.executable,'-B',str(ROOT/'tools/visor_startup.py'),
                               '--binary',str(binary),'--output',str(output)],
                              env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1'),
                              capture_output=True,text=True,timeout=30)

    def test_cli_paths_with_spaces_and_existing_output(self):
        with tempfile.TemporaryDirectory(prefix='visor startup ') as tmp:
            output = Path(tmp)/'record with spaces.json'
            result = self.invoke(startup.TARGET,output)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(json.loads(output.read_text()),self.record)
            before = output.read_bytes()
            result = self.invoke(startup.TARGET,output)
            self.assertNotEqual(result.returncode,0)
            self.assertEqual(output.read_bytes(),before)

    def test_rejected_cli_input_preserves_or_does_not_create_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root/'truncated-visor'
            binary.write_bytes(self.data[:64])
            for existing in (False,True):
                output = root/('prior.json' if existing else 'absent.json')
                if existing:output.write_bytes(b'preserve earlier evidence\n')
                result = self.invoke(binary,output)
                self.assertNotEqual(result.returncode,0)
                self.assertIn('size/SHA256 differs',result.stderr)
                if existing:self.assertEqual(output.read_bytes(),b'preserve earlier evidence\n')
                else:self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
