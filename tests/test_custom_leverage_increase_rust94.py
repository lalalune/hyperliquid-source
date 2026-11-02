"""Native-bound decision/receipt controls; no captured target execution."""
import base64,gzip,hashlib,importlib.util,json,os,posixpath,re,tempfile,unittest
from pathlib import Path,PurePosixPath
ROOT=Path(__file__).resolve().parents[1];PACKET=ROOT/'research/work-items/RE-007-custom-leverage-increase-rust-94'
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
class CustomLeverageIncreaseRust94(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.check=load('custom_increase_receipts',PACKET/'verify.py')
        cls.archive_path=PACKET/'compiled.json.gz.b64'
        cls.archive=json.loads(gzip.decompress(base64.b64decode(cls.archive_path.read_bytes().strip(),validate=True)))
        cls.report=json.loads(base64.b64decode(cls.archive['REPORT.json'],validate=True))
    def altered(self,change):
        data=json.loads(json.dumps(self.archive));report=json.loads(base64.b64decode(data['REPORT.json']));change(data,report);data['REPORT.json']=base64.b64encode(json.dumps(report).encode()).decode()
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'changed.gz.b64';p.write_bytes(base64.b64encode(gzip.compress(json.dumps(data).encode(),mtime=0))+b'\n')
            with self.assertRaises(ValueError):self.check.audit(p)
    def test_frozen_semantics_and_separate_policy_classes(self):
        rows,policies,_,_,controls,_=self.check.corpus(PACKET/'pre-source')
        self.assertEqual((len(rows),len(policies),len(controls)),(487,4,9))
        self.assertEqual(sum(c['different_commit_vs_refusal_cases']>0 for c in controls),7)
        self.assertEqual(hashlib.sha256((PACKET/'pre-source/PRE-RUST-FREEZE.json').read_bytes()).hexdigest(),'437595b12eb512837c97fd70bd46025e41008250e07f191758bbe5519051dadc')
    def test_actual_streams_and_current_combined_component(self):
        r=self.check.audit(self.archive_path,current_component=True)
        self.assertEqual((r['qualified_cases'],r['policy_cases'],r['baseline_builds'],r['snapshot_files']),(487,4,4,35))
        for c in self.report['cargo']:
            raw=base64.b64decode(self.report['records'][c['record']]['stdout_b64']).decode()
            self.assertEqual(sum(map(int,re.findall(r'test result: ok\. (\d+) passed;',raw))),48)
    def test_changed_baseline_decision_rejects(self):
        def change(a,r):
            rec=r['records'][r['baseline'][0]['output_record']];b=bytearray(base64.b64decode(rec['stdout_b64']));b[4]^=1;rec['stdout_b64']=base64.b64encode(b).decode()
        self.altered(change)
    def test_refusal_only_mutant_wrong_tag_is_distinguished(self):
        def change(a,r):
            m=next(m for m in r['mutants'] if m['name']=='cap-before-mode');self.assertEqual(m['control']['different_commit_vs_refusal_cases'],0)
            rec=r['records'][m['output_record']];b=bytearray(base64.b64decode(rec['stdout_b64']));at=12*m['control']['witness_id']+5;b[at:at+2]=int(m['control']['expected'][1]).to_bytes(2,'little');rec['stdout_b64']=base64.b64encode(b).decode()
        self.altered(change)
    def test_full_mutant_compiler_tree_binding(self):
        self.altered(lambda a,r:r['mutants'][0]['component_manifest'].__setitem__('Cargo.toml','0'*64))
    def test_policy_row_cannot_be_counted_as_enter_commit(self):
        def change(a,r):
            rec=r['records'][r['baseline'][0]['output_record']];b=bytearray(base64.b64decode(rec['stdout_b64']));b[487*12+4]=0;rec['stdout_b64']=base64.b64encode(b).decode()
        self.altered(change)
    def test_framing_exit_is_not_native_semantic_success(self):
        self.altered(lambda a,r:r['records'][r['framing'][0]['record']].__setitem__('exit',0))
    def test_frozen_external_input_mutation_rejects(self):
        def change(a,r):
            key=next(n for n in a['snapshot'] if n.endswith('pre-source/inputs.json'));b=bytearray(base64.b64decode(a['snapshot'][key]));b[1]^=1;a['snapshot'][key]=base64.b64encode(b).decode()
        self.altered(change)
    def test_actual_dep_info_project_source_closure(self):
        receipt=json.loads((PACKET/'COMPILER-READS.json').read_text());freeze=json.loads(base64.b64decode(self.archive['SOURCE-FREEZE.json']))
        self.assertEqual(receipt['source_freeze_sha256'],self.report['source_freeze_sha256'])
        self.assertEqual(receipt['report_sha256'],hashlib.sha256(base64.b64decode(self.archive['REPORT.json'])).hexdigest())
        command=next(r for r in self.report['records'] if '--crate-type' in r['argv']);original_root=PurePosixPath(command['cwd']).parents[1];found={}
        self.assertEqual(len(receipt['dep_info_records']),18)
        for record in receipt['dep_info_records']:
            raw=base64.b64decode(record['raw_base64'],validate=True);self.assertEqual(hashlib.sha256(raw).hexdigest(),record['sha256'])
            for line in raw.decode().splitlines():
                if ': ' not in line:continue
                for token in line.split(': ',1)[1].split():
                    path=PurePosixPath(token)
                    name=str(path.relative_to(original_root)) if path.is_absolute() else posixpath.normpath('src/node94-margin-risk/'+token)
                    self.assertIn(name,freeze['files']);found[name]=freeze['files'][name]
        self.assertEqual(found,receipt['project_compiler_inputs']);self.assertEqual(len(found),21)
    def test_native_full_caller_and_selected_bypass_bytes(self):
        native=load('custom_increase_native',PACKET/'native.py');target=Path(os.environ.get('TIER_CAP_TARGET',ROOT/'artifacts/node/94/hl-node'));r=native.authenticate(target.read_bytes())
        self.assertEqual((r['caller_bytes'],r['caller_instructions'],r['coordinate_identity_controls']),(2849,600,15));self.assertTrue(r['EnterCommit_is_not_success'])
if __name__=='__main__':unittest.main()
