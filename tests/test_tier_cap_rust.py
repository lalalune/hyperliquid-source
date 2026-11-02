"""Target-bound receipt checks for the independent RE007 tier cap."""
import base64
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
PACKET=ROOT/'research/work-items/RE-007-tier-cap-rust-94'

def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod);return mod

class TierCapRustEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.check=module('tier_cap_receipts',PACKET/'verify.py')
        cls.native=module('tier_cap_native',PACKET/'native.py')
        cls.archive_path=PACKET/'compiled.json.gz.b64'
        cls.archive=json.loads(gzip.decompress(base64.b64decode(cls.archive_path.read_bytes().strip(),validate=True)))

    def changed_archive(self,change):
        archive=json.loads(json.dumps(self.archive));change(archive)
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'changed.gz.b64'
            p.write_bytes(base64.b64encode(gzip.compress(json.dumps(archive).encode(),mtime=0))+b'\n')
            with self.assertRaises(ValueError):self.check.audit(p)

    @staticmethod
    def edit_report(archive,change):
        report=json.loads(base64.b64decode(archive['REPORT.json']))
        change(report)
        archive['REPORT.json']=base64.b64encode(json.dumps(report).encode()).decode()

    def test_frozen_external_corpus_and_ten_normal_mutants(self):
        rows,_,expected,controls,_=self.check.corpus(PACKET/'pre-source')
        self.assertEqual(len(rows),925)
        self.assertEqual(len(expected),925*5)
        self.assertEqual(len(controls),10)
        self.assertTrue(all(c['witness']['expected_cap']!=c['witness']['wrong_cap'] for c in controls))
        self.assertEqual(hashlib.sha256((PACKET/'pre-source/PRE-RUST-FREEZE.json').read_bytes()).hexdigest(),'70b67fdbf4c71988a658c52a36b0d01962d14941369e601dda14bba41b5906f9')

    def test_actual_streams_and_exact_current_source_tree(self):
        result=self.check.audit(self.archive_path)
        self.assertEqual((result['baseline_builds'],result['cases_per_baseline'],result['normal_cap_mutants'],result['framing_policy_controls']),(4,925,10,3))

    def test_changed_baseline_output_rejects(self):
        def change(report):
            r=report['records'][report['baseline'][0]['output_record']]
            b=bytearray(base64.b64decode(r['stdout_b64']));b[4]^=1
            r['stdout_b64']=base64.b64encode(b).decode()
        self.changed_archive(lambda a:self.edit_report(a,change))

    def test_changed_nonoperative_mutant_compiler_input_rejects(self):
        self.changed_archive(lambda a:self.edit_report(a,lambda r:r['mutants'][0]['component_manifest'].__setitem__('Cargo.toml','0'*64)))

    def test_changed_mutant_witness_output_rejects(self):
        def change(report):
            m=report['mutants'][0];r=report['records'][m['output_record']]
            b=bytearray(base64.b64decode(r['stdout_b64']));b[5*m['witness']['id']+4]=m['witness']['expected_cap']
            r['stdout_b64']=base64.b64encode(b).decode()
        self.changed_archive(lambda a:self.edit_report(a,change))

    def test_changed_framing_exit_rejects(self):
        self.changed_archive(lambda a:self.edit_report(a,lambda r:r['records'][r['framing_policy'][0]['record']].__setitem__('exit',0)))

    def test_changed_frozen_input_or_source_rejects(self):
        def change(a):
            name=next(n for n in a['snapshot'] if n.endswith('pre-source/input.bin.b64'))
            b=bytearray(base64.b64decode(a['snapshot'][name]));b[-1]^=1;a['snapshot'][name]=base64.b64encode(b).decode()
        self.changed_archive(change)

    def test_native_fde_exports_caller_and_identity_controls(self):
        target=Path(os.environ.get('TIER_CAP_TARGET',ROOT/'artifacts/node/94/hl-node'))
        raw=target.read_bytes();result=self.native.authenticate(raw)
        self.assertEqual((result['functions'],result['new_cap_plus_selected_helper_instructions'],result['identity_windows']),(5,421,22))
        # These reject by frozen whole-target identity, not semantic execution.
        # Full positive authentication independently matches each original window.
        frozen=json.loads((PACKET/'native/NATIVE-FREEZE.json').read_text())
        elf=self.native.Elf(raw)
        for c in frozen['coordinate_controls']:
            changed=bytearray(raw);offset=elf.off(int(c['va'],16));changed[offset]^=1
            with self.assertRaisesRegex(ValueError,'target identity'):self.native.authenticate(changed)

if __name__=='__main__':unittest.main()
