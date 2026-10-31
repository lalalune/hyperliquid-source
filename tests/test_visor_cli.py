"""Captured visor argument fields: real-byte evidence and corruption controls."""
import json
import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import visor_cli as cli
from elf_index import sections

PACKET = ROOT/'research/work-items/RE-013-visor-cli-fields/record.json'


class VisorCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = cli.TARGET.read_bytes()
        cls.secs = sections(cls.data)
        cls.record = json.loads(PACKET.read_text(encoding='utf-8'))

    def offset(self,va):
        s = next(s for s in self.secs if s['type'] != 8 and s['address'] <= va < s['address']+s['size'])
        return s['offset']+va-s['address']

    def changed(self,offset):
        data = bytearray(self.data)
        data[offset] ^= 1
        return bytes(data)

    def test_actual_target_regenerates_fields(self):
        self.assertEqual(cli.build(self.data),self.record)
        self.assertEqual([x['value'] for x in self.record['numeric_builder_settings']],[0x404,0x426])
        self.assertEqual(self.record['observed_fallback_words']['words'],[0,8,0])
        self.assertEqual(bytes.fromhex(self.record['inline_child_key_equality']['compared_key_bytes']),b'child-args')
        self.assertFalse(self.record['coverage']['full_CFG_or_parser_behavior'])
        self.assertFalse(self.record['observed_output_stores']['complete_layout_or_Rust_type_proved'])

    def test_public_reader_rejects_corrupted_or_truncated_target(self):
        for data in (self.data[:64],self.changed(self.offset(0x5b59d0))):
            with self.subTest(size=len(data)),self.assertRaisesRegex(ValueError,'visor identity differs'):
                cli.build(data)

    def test_numeric_setting_corruptions_are_rejected(self):
        for va in (0x5b59d0,0x5b5c99):
            with self.subTest(va=hex(va)),self.assertRaisesRegex(ValueError,'instruction control differs'):
                cli._derive(self.changed(self.offset(va)))

    def test_name_slices_and_inline_key_corruptions_are_rejected(self):
        for va,message in ((0xb72c6,'CLI literal differs'),(0xb72d3,'CLI literal differs'),
                           (0x5b9165,'instruction control differs'),(0x5b91b7,'instruction control differs')):
            with self.subTest(va=hex(va)),self.assertRaisesRegex(ValueError,message):
                cli._derive(self.changed(self.offset(va)))

    def test_fallback_output_and_branch_corruptions_are_rejected(self):
        for va in (0x5b91fb,0x5b9240,0x5b9117):
            with self.subTest(va=hex(va)),self.assertRaisesRegex(ValueError,'instruction control differs'):
                cli._derive(self.changed(self.offset(va)))

    def test_builder_call_binding_corruption_is_rejected(self):
        row = next(r for r in self.record['relocations'] if r['slot']=='0x7e76e0')
        with self.assertRaisesRegex(ValueError,'CLI relocation differs'):
            cli._derive(self.changed(row['file_offset']+16))

    def test_fde_range_corruption_is_rejected(self):
        row = self.record['fde_ranges'][1]
        with self.assertRaisesRegex(ValueError,'CLI FDE extent differs'):
            cli._derive(self.changed(self.offset(int(row['fde_va'],16))+12))

    def listing_checker(self):
        spec = importlib.util.spec_from_file_location('visor_cli_listing_check',PACKET.parent/'check_listings.py')
        checker = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(checker)
        return checker

    def test_retained_gnu_listings_match_target_bytes_and_boundaries(self):
        self.assertEqual(self.listing_checker().verify(PACKET.parent,self.data),{
            'decodedRows':399,'rawBytes':2496,'selectedWindows':12,'fullCFG':False,'targetExecuted':False})

    def test_listing_comparator_rejects_repinned_byte_and_false_total(self):
        checker = self.listing_checker()
        with tempfile.TemporaryDirectory() as tmp:
            packet = Path(tmp)/'packet'
            shutil.copytree(PACKET.parent,packet)
            path = packet/'BOUNDARY-AUDIT.json'
            original = path.read_bytes()
            audit = json.loads(original)
            listing = packet/'disassembly'/Path(audit['ranges'][0]['file']).name
            raw = listing.read_bytes()
            changed = raw.replace(b'55 ',b'54 ',1)
            self.assertNotEqual(raw,changed)
            listing.write_bytes(changed)
            audit['ranges'][0]['sha256'] = hashlib.sha256(changed).hexdigest()
            path.write_text(json.dumps(audit))
            with self.assertRaisesRegex(ValueError,'instruction bytes differ'):
                checker.verify(packet,self.data)
            listing.write_bytes(raw)
            audit = json.loads(original)
            audit['decodedRows'] -= 1
            path.write_text(json.dumps(audit))
            with self.assertRaisesRegex(ValueError,'listing totals differ'):
                checker.verify(packet,self.data)

    def invoke(self,binary,output):
        return subprocess.run([sys.executable,'-B',str(ROOT/'tools/visor_cli.py'),
                               '--binary',str(binary),'--output',str(output)],
                              env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1'),
                              capture_output=True,text=True,timeout=30)

    def test_real_cli_preserves_existing_output_and_accepts_spaces(self):
        with tempfile.TemporaryDirectory(prefix='visor fields ') as tmp:
            output = Path(tmp)/'record with spaces.json'
            result = self.invoke(cli.TARGET,output)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(json.loads(output.read_text()),self.record)
            before = output.read_bytes()
            result = self.invoke(cli.TARGET,output)
            self.assertNotEqual(result.returncode,0)
            self.assertEqual(output.read_bytes(),before)

    def test_rejected_input_does_not_publish(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root/'truncated-visor'
            binary.write_bytes(self.data[:64])
            for prior in (False,True):
                output = root/('prior.json' if prior else 'absent.json')
                if prior:output.write_bytes(b'preserve prior evidence\n')
                result = self.invoke(binary,output)
                self.assertNotEqual(result.returncode,0)
                self.assertIn('visor identity differs',result.stderr)
                if prior:self.assertEqual(output.read_bytes(),b'preserve prior evidence\n')
                else:self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
