"""Pinned byte-policy evidence, native counterfacts and real own-code Rust."""
import hashlib,importlib.util,json,os,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import numeric_selector115_rust as t
RUSTC=os.environ.get('HYPERLIQUID_NUMERIC_SELECTOR_RUSTC')
class NumericRustTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=(t.ROOT/t.BINARY).read_bytes();cls.p,cls.table,cls.record=t.native_record(cls.data)
    def test_complete_target_fde_references_and_original_imports(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(),t.SHA256)
        self.assertEqual((self.record['owner']['start'],self.record['owner']['end'],self.record['owner']['bytes'],self.record['owner']['instructions']),('0x46aa760','0x46aab78',1048,269))
        self.assertEqual({r['symbol'] for r in self.record['relocations'].values() if r['symbol']},{'memcpy','bcmp'})
        self.assertEqual(len(self.record['formatter_division_certificates']),3)
        with self.assertRaises(ValueError):t.native_record(self.data[:-1])
    def test_actual_code_table_and_relocation_corruptions_refused(self):
        image=t.engine.Image(self.data)
        for va in (0x46aa788,0x46aa7a9,0x46aa875,0x46aab07,0x46ea12,105772296,self.record['owner']['frames']['fde']['va']):
            if isinstance(va,str):va=int(va,16)
            changed=bytearray(self.data);changed[image.off(va,1)]^=1
            with self.assertRaises(ValueError):t.native_record(bytes(changed))
    def test_canonical_zero_upper_bound_saturation_and_fallback_bytes(self):
        p=self.p;table=self.table;M=(1<<64)-1
        for b,value in ((b'PURR/USDC',0),(b'#0',100000000),(b'@1',1),(b'@99999999',99999999),(b'#18446744073709551615',M),(b'#18446744073609551615',M)):
            self.assertEqual(t.expected(b,p,table),[418,value,0,0])
        for b in (b'',b'@0',b'@100000000',b'#01',b'#+1',b'#18446744073709551616',b'PURR/USDD',b'\xff'):
            self.assertEqual(t.expected(b,p,table),[104,0,t.engine.BUFFER,len(b)])
        rows=[dict(input_hex=b.hex(),expected=t.native.numeric_projection(b,p,table)) for b in t.corpus()]
        stream=('\n'.join(json.dumps(r,sort_keys=True) for r in rows)+'\n').encode()
        self.assertEqual(len(rows),33356);self.assertEqual(hashlib.sha256(stream).hexdigest(),t.FROZEN_EXPECTED_SHA256)
    def test_capture_never_enters_object_or_compiler_dispatch(self):
        target=t.ROOT/t.BINARY
        with self.assertRaises(ValueError):t.own_machine(target)
        with patch.object(t.subprocess,'run',side_effect=AssertionError('Captured dispatch forbidden')):
            with self.assertRaisesRegex(ValueError,'Captured artifact'):t.verify(target,t.ROOT/'work/forbidden-numeric-compiler')
        with self.assertRaises(t.engine.Unmodelled):t.NoExternalMemory().read(0x1234,8)
    def test_retained_source_frozen_expectations_and_explicit_limits(self):
        r=json.loads((t.PACKET/'rust-validation.json').read_bytes())
        self.assertEqual(r['native'],self.record)
        self.assertEqual(r['source_sha256'],{n:hashlib.sha256((t.CRATE/n).read_bytes()).hexdigest() for n in ('Cargo.toml','Cargo.lock','src/lib.rs')})
        self.assertEqual(r['checker_sha256'],hashlib.sha256(Path(t.__file__).read_bytes()).hexdigest())
        self.assertEqual(r['native_model_sha256'],hashlib.sha256(Path(t.native.__file__).read_bytes()).hexdigest())
        self.assertEqual(r['shared_engine_sha256'],hashlib.sha256(Path(t.engine.__file__).read_bytes()).hexdigest())
        self.assertEqual((r['raw_corpus_cases'],r['alignments'],r['evaluations'],r['mismatches']),(33356,8,266848,0))
        self.assertFalse(r['captured_executed']);self.assertFalse(r['target_code_identity_measured'])
    @unittest.skipUnless(RUSTC and importlib.util.find_spec('capstone'),'Explicit HYPERLIQUID_NUMERIC_SELECTOR_RUSTC and Capstone required; not a compiler pass')
    def test_real_compiler_all_inputs_alignments_and_operative_controls(self):
        root=t.ROOT/'work/numeric-rust-tests';root.mkdir(parents=True,exist_ok=True);out=Path(tempfile.mkdtemp(dir=root))/'comparison'
        actual=t.verify(Path(RUSTC),out);old=json.loads((t.PACKET/'rust-validation.json').read_bytes())
        for key in ('native','source_sha256','checker_sha256','native_model_sha256','shared_engine_sha256','raw_corpus_cases','evaluations','mismatches','frozen_expected_sha256','own_code_sha256','compiled_source_controls','native_operand_controls'):
            self.assertEqual(actual[key],old[key],key)
        self.assertTrue(actual['own_objects_reproducible']);self.assertEqual(len(actual['compiled_source_controls']),7);self.assertEqual(len(actual['native_operand_controls']),6)
        for row in actual['compiled_source_controls']+actual['native_operand_controls']:
            self.assertTrue(row['rejected']);self.assertNotEqual(row['expected'],row['changed'])
if __name__=='__main__':unittest.main()
