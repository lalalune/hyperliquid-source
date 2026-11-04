"""Target-bound write progress, not socket or scheduler execution."""
import hashlib,importlib.util,json,os,sys,tempfile,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import tcp_write_progress115 as t
RUSTC=os.environ.get('HYPERLIQUID_WRITE_PROGRESS_RUSTC')
class WriteProgressTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=(t.ROOT/t.BINARY).read_bytes();cls.native=t.NativeStep(cls.data)
    def test_actual_capture_and_own_object_boundary(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(),t.SHA256)
        for bad in (b'',self.data[:-1]):
            with self.assertRaises(ValueError):t.NativeStep(bad)
        with self.assertRaises(ValueError):t.own_machine(t.ROOT/t.BINARY)
        with self.assertRaisesRegex(ValueError,'Captured artifact'):
            t.verify(t.ROOT/t.BINARY,t.ROOT/'work/forbidden-write-compiler')
    def test_actual_resume_tables_and_imports(self):
        r=t.native_record(self.data)
        self.assertEqual([x['symbol'] for x in r['imports']],['send','__errno_location'])
        self.assertEqual(r['tables'][1]['targets'][3],'0x2b7b31a')
        self.assertEqual(r['calls'][0]['target'],'0x5cdfc90')
        self.assertEqual(r['resume_dump'],['2b7b31a: 488b8b38020000 mov rcx, qword ptr [rbx + 0x238]','2b7b321: e98bfcffff jmp 0x2b7afb1'])
    def test_original_branches_and_counter_corruption_refused(self):
        im=t.engine.Image(self.data)
        for va in (0x2b7af90,0x2b7afc3,0x2b7afe2,0x2b7b00b,0x2b7b025,0x2b7b030,0x604d18,0x5cdfd3e):
            bad=bytearray(self.data);bad[im.off(va,1)]^=1
            with self.assertRaises(ValueError):t.NativeStep(bytes(bad))
    def test_native_boundary_examples_and_counter_wrap(self):
        f=self.native.step;M=t.engine.MASK
        self.assertEqual(f(4096,0,2,M,M),[4096,0,1,0,1,M])
        self.assertEqual(f(4096,4,0,1,M),[4097,3,0,0,0,3])
        self.assertEqual(f(M,1,0,1,0),[0,0,0,0,0,1])
        self.assertEqual(f(4096,4,0,0,0),[4096,4,3,0x1700000003,1,4])
        self.assertEqual(f(4096,4,0,5,0),[1,0,4,0,0,4])
        self.assertEqual(f(4096,4,2,M,0),[4096,4,2,0,3,4])
        self.assertEqual(f(4096,4,3,M,0),[4096,4,3,M,1,4])
    def test_retained_source_identity_and_unclosed_scope(self):
        r=json.loads((t.PACKET/'rust-validation.json').read_bytes())
        self.assertEqual(r['source_sha256'],{n:hashlib.sha256((t.CRATE/n).read_bytes()).hexdigest() for n in ('Cargo.toml','Cargo.lock','src/lib.rs')})
        self.assertEqual(r['checker_sha256'],hashlib.sha256(Path(t.__file__).read_bytes()).hexdigest())
        self.assertEqual(r['cases'],3136);self.assertEqual(r['mismatches'],0)
        self.assertFalse(r['captured_binary_executed']);self.assertFalse(r['target_code_identity_measured'])
        self.assertEqual([(x['bytes'],x['instructions']) for x in r['owners']],[(4755,914),(443,120)])
    @unittest.skipUnless(RUSTC and importlib.util.find_spec('capstone'),'Explicit HYPERLIQUID_WRITE_PROGRESS_RUSTC and Capstone required; not a compiler pass')
    def test_real_own_rust_full_corpus_and_compiled_controls(self):
        root=t.ROOT/'work/write-progress-tests';root.mkdir(parents=True,exist_ok=True)
        out=Path(tempfile.mkdtemp(dir=root))/'comparison';r=t.verify(Path(RUSTC),out)
        old=json.loads((t.PACKET/'rust-validation.json').read_bytes())
        for key in ('source_sha256','checker_sha256','native','owners','cases','mismatches','own_body_sha256','own_body_bytes','own_instruction_count','compiled_source_controls','native_operand_controls'):
            self.assertEqual(r[key],old[key],key)
        self.assertTrue(r['repeated_objects_equal'])
        self.assertEqual(len(r['compiled_source_controls']),6);self.assertEqual(len(r['native_operand_controls']),4)
        for row in r['compiled_source_controls']+r['native_operand_controls']:
            self.assertTrue(row['rejected']);self.assertNotEqual(row['expected'],row['changed'])
if __name__=='__main__':unittest.main()
