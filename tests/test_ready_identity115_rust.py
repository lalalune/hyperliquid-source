import hashlib,importlib.util,json,os,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import ready_identity115_rust as t
RUSTC=os.environ.get('HYPERLIQUID_READY_IDENTITY_RUSTC')
class ReadyIdentityRustTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.data=(t.ROOT/t.BINARY).read_bytes();cls.record=t.native_record(cls.data);cls.image=t.engine.Image(cls.data);cls.code=cls.image.read(0x154cd10,299)
 def test_complete_probe_context_fdes_and_real_bcmp_import(self):
  self.assertEqual([(x['bytes'],x['instructions']) for x in self.record['owners']],[(299,80),(268,73),(247,67)])
  self.assertEqual(self.record['existing_certificate']['comparison_import']['symbol'],'bcmp')
  self.assertEqual(self.record['existing_certificate']['probe_layout']['fields'][1]['width'],4)
  with self.assertRaises(ValueError):t.native_record(self.data[:-1])
 def test_actual_native_offsets_and_import_corruptions_refused(self):
  for va in (0x154cd10+0x11,0x154cd10+0xcd,0x154cd10+0xd4,0x154cd10+0xdb,0x64df9f8,0x64015b8):
   b=bytearray(self.data);b[self.image.off(va,1)]^=1
   with self.assertRaises(ValueError):t.native_record(bytes(b))
  k=(b'abc',7,11);p=bytearray(self.code);p[0xcd]=32
  self.assertNotEqual(t.project(p,[k],k,0,1),t.project(self.code,[k],k,0,1))
 def test_byte_equality_all_fields_empty_vector_and_borrow_boundary(self):
  k=(b'abc',0xffffffff,0xffffffffffffffff)
  for rows,value in (([],False),([k],True),([(b'abx',k[1],k[2])],False),([(b'abc',0,k[2])],False),([(b'abc',k[1],0)],False),([(b'ab',k[1],k[2])],False),([(b'abcx',k[1],k[2]),k],True)):
   self.assertEqual(t.project(self.code,rows,k,(1<<63)-2,1),dict(selected_path=True,value=value,counter=(1<<63)-2))
  self.assertFalse(t.project(self.code,[k],k,(1<<63)-1,1)['selected_path'])
  self.assertEqual(t.project(self.code,[k],k,t.engine.MASK,2),dict(selected_path=True,value=False,counter=t.engine.MASK))
 def test_captured_object_compiler_and_external_memory_refused(self):
  p=t.ROOT/t.BINARY
  with self.assertRaises(ValueError):t.own_machine(p)
  with patch.object(t.subprocess,'run',side_effect=AssertionError('Forbidden dispatch')):
   with self.assertRaisesRegex(ValueError,'Captured artifact'):t.verify(p,t.ROOT/'work/forbidden-identity')
  with self.assertRaises(t.engine.Unmodelled):t.NoExternalMemory().read(1234,8)
 def test_retained_hashes_and_explicit_scope(self):
  r=json.loads((t.PACKET/'rust-validation.json').read_bytes());self.assertEqual(r['native'],self.record)
  for n,h in r['source_sha256'].items():self.assertEqual(hashlib.sha256((t.CRATE/n).read_bytes()).hexdigest(),h)
  for key,p in [('checker_sha256',Path(t.__file__)),('native_model_sha256',Path(t.native.__file__)),('shared_engine_sha256',Path(t.engine.__file__))]:self.assertEqual(hashlib.sha256(p.read_bytes()).hexdigest(),r[key])
  self.assertEqual((r['fixtures'],r['state_pairs'],r['alignments'],r['evaluations'],r['mismatches']),(738,4,8,23616,0));self.assertFalse(r['captured_executed']);self.assertFalse(r['target_code_identity_measured']);self.assertEqual(len(t.corpus()),738)
 @unittest.skipUnless(RUSTC and importlib.util.find_spec('capstone'),'Explicit HYPERLIQUID_READY_IDENTITY_RUSTC and Capstone required; not a compiler pass')
 def test_actual_compiler_shared_safe_scan_and_operative_controls(self):
  root=t.ROOT/'work/identity-rust-tests';root.mkdir(parents=True,exist_ok=True);out=Path(tempfile.mkdtemp(dir=root))/'comparison';r=t.verify(Path(RUSTC),out);old=json.loads((t.PACKET/'rust-validation.json').read_bytes())
  for key in ('native','source_sha256','checker_sha256','native_model_sha256','shared_engine_sha256','evaluations','corpus_sha256','mismatches','own_code_sha256','compiled_source_controls','native_operand_controls'):self.assertEqual(r[key],old[key],key)
  self.assertEqual((len(r['compiled_source_controls']),len(r['native_operand_controls'])),(7,6))
  for c in r['compiled_source_controls']+r['native_operand_controls']:self.assertTrue(c['rejected']);self.assertNotEqual(c['expected'],c['changed'])
if __name__=='__main__':unittest.main()
