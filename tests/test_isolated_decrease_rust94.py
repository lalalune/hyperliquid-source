"""Conditional native bridge and actual compiled-output controls; no target run."""
from pathlib import Path
import base64,gzip,hashlib,importlib.util,json,os,tempfile,unittest
from unittest import mock
ROOT=Path(__file__).resolve().parents[1]
PACKET=ROOT/'research/work-items/RE-007-isolated-decrease-rust-94'
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
class IsolatedDecreaseRust94(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.check=module('isolated_decrease_receipts',PACKET/'observed.py');cls.native=module('isolated_decrease_native',PACKET/'native.py')
        cls.archive_path=PACKET/'compiled.json.gz.b64';cls.archive=json.loads(gzip.decompress(base64.b64decode(cls.archive_path.read_bytes().strip(),validate=True)))
        cls.report=json.loads(base64.b64decode(cls.archive['REPORT.json'],validate=True))
    def changed(self,edit):
        archive=json.loads(json.dumps(self.archive));report=json.loads(base64.b64decode(archive['REPORT.json']));edit(archive,report);archive['REPORT.json']=base64.b64encode(json.dumps(report).encode()).decode()
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'changed.gz.b64';p.write_bytes(base64.b64encode(gzip.compress(json.dumps(archive).encode(),mtime=0))+b'\n')
            with self.assertRaises(ValueError):self.check.audit(p)
    def test_pre_rust_values_and_separate_policy_denominator(self):
        rows,controls,oracle,streams=self.check.corpus(PACKET/'pre-source',PACKET)
        self.assertEqual((len(rows),len(controls)),(341,8));self.assertEqual(len(streams['qualified-expected.bin.b64']),4092);self.assertEqual(len(streams['policy-expected.bin.b64']),108)
        self.assertEqual(sum(c['changed_commit_vs_refusal']>0 for c in controls),7)
        self.assertEqual(hashlib.sha256((PACKET/'pre-source/PRE-RUST-FREEZE.json').read_bytes()).hexdigest(),'602c9b097c03ffdac3444f5c60d4f5bff2015fdd1ca33440d21b4c3f67949fb0')
        self.assertEqual([sum(oracle.value(r)[1]==tag for r in rows) for tag in [None,0x43,0x50,0x47]],[136,61,48,96])
    def test_actual_streams_current_tree_and_project_input_closure(self):
        r=self.check.audit(self.archive_path)
        self.assertEqual((r['snapshot_files'],r['project_compiler_inputs'],r['dep_info_records']),(43,23,20));self.assertEqual(r['cargo_tests_per_profile'],[52,52]);self.assertEqual((r['commands'],r['channels']),(48,96))
    def test_changed_baseline_refusal_rejects(self):
        def edit(a,r):
            rec=r['records'][r['baseline'][0]['qualified_record']];b=bytearray(base64.b64decode(rec['stdout_b64']));b[5]^=1;rec['stdout_b64']=base64.b64encode(b).decode()
        self.changed(edit)
    def test_policy_cannot_be_counted_as_native_enter_commit(self):
        def edit(a,r):
            rec=r['records'][r['baseline'][0]['policy_record']];b=bytearray(base64.b64decode(rec['stdout_b64']));b[4]=0;rec['stdout_b64']=base64.b64encode(b).decode()
        self.changed(edit)
    def test_refusal_only_mutant_tag_is_distinguished(self):
        def edit(a,r):
            m=next(x for x in r['mutants'] if x['name']=='wrong-cross-refusal-tag');self.assertEqual(m['control']['changed_commit_vs_refusal'],0)
            rec=r['records'][m['output_record']];b=bytearray(base64.b64decode(rec['stdout_b64']));at=12*m['control']['witness_id']+5;b[at:at+2]=(0x47).to_bytes(2,'little');rec['stdout_b64']=base64.b64encode(b).decode()
        self.changed(edit)
    def test_full_mutant_component_manifest_rejects_unrelated_change(self):
        self.changed(lambda a,r:r['mutants'][0]['component_manifest'].__setitem__('Cargo.toml','0'*64))
    def test_changed_external_frozen_input_rejects(self):
        def edit(a,r):
            name=next(n for n in a['snapshot'] if n.endswith('/inputs.json'));b=bytearray(base64.b64decode(a['snapshot'][name]));b[1]^=1;a['snapshot'][name]=base64.b64encode(b).decode()
        self.changed(edit)
    def test_framing_exit_is_not_native_success(self):
        self.changed(lambda a,r:r['records'][r['framing'][0]['record']].__setitem__('exit',0))
    def test_compile_exit2_cannot_be_reclassified_as_framing(self):
        self.changed(lambda a,r:r['records'][3].__setitem__('exit',2))
    def test_missing_and_foreign_dependency_inputs_reject(self):
        original=Path.read_text;target=PACKET/'COMPILER-READS.json'
        for payload in [b'',b'fake: ../../foreign.rs\n']:
            report=json.loads(json.dumps(self.report));record=report['cargo_dep_info'][0];record['raw_base64']=base64.b64encode(payload).decode();record['sha256']=hashlib.sha256(payload).hexdigest();raw=json.dumps(report).encode()
            receipt=json.loads(original(target));receipt['dep_info_records']=report['cargo_dep_info'];receipt['report_sha256']=hashlib.sha256(raw).hexdigest()
            def read(p,*a,**k):return json.dumps(receipt) if p==target else original(p,*a,**k)
            with mock.patch.object(Path,'read_text',read):
                with self.assertRaises(ValueError):self.check.compiler_reads(report,json.loads(base64.b64decode(self.archive['SOURCE-FREEZE.json'])),raw)
    def test_current_decrease_source_still_bound(self):
        target=ROOT/'src/node94-margin-risk/src/isolated_decrease.rs';original=Path.read_bytes
        def read(p):
            b=original(p);return b+b'\n' if p==target else b
        with mock.patch.object(Path,'read_bytes',read):
            with self.assertRaisesRegex(ValueError,'exact current source/input .*isolated_decrease.rs'):self.check.audit(self.archive_path)
    def test_source_relocation_cannot_redirect_frozen_inputs(self):
        target=PACKET/'SOURCE-PATHS.json';original=Path.read_text
        def read(p,*args,**kwargs):
            b=original(p,*args,**kwargs)
            if p==target:
                obj=json.loads(b);key=next(k for k in obj if k.endswith('/inputs.json'));obj[key]='src/node94-margin-risk/Cargo.toml';return json.dumps(obj)
            return b
        with mock.patch.object(Path,'read_text',read):
            with self.assertRaisesRegex(ValueError,'explicit receipt source relocation'):self.check.audit(self.archive_path)
    def test_native_identity_and_selected_binding(self):
        path=Path(os.environ.get('TIER_CAP_TARGET',ROOT/'artifacts/node/94/hl-node'));raw=path.read_bytes();r=self.native.authenticate(raw)
        self.assertEqual((r['functions'],r['body_bytes'],r['dual_decoder_instructions']),(10,8450,1856));self.assertEqual((r['coordinate_byte_identity_controls'],r['relocations'],r['caller_calls']),(25,6,4))
        # Deliberately byte-identity controls, not native semantic execution.
        for va in [0x33ebb78,0x370a283]:
            b=bytearray(raw);b[self.native.Elf(raw).off(va)]^=1
            with self.assertRaisesRegex(ValueError,'whole target identity'):self.native.authenticate(bytes(b))
if __name__=='__main__':unittest.main()
