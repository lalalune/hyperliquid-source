import hashlib,importlib.util,json,os,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import newline_requests115_rust as t
RUSTC=os.environ.get('HYPERLIQUID_NEWLINE_REQUESTS_RUSTC')
class NewlineRequestsRustTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.data=(t.ROOT/t.BINARY).read_bytes();cls.record=t.native_record(cls.data)
 def test_complete_actual_fdes_branches_callback_loads_and_stores(self):
  self.assertEqual([(x['bytes'],x['instructions']) for x in self.record['owners']],[(630,173),(390,109)])
  b=self.record['bindings'];self.assertEqual(b['branchCount'],32);self.assertEqual(len(b['explicitStores']),8);self.assertEqual(b['callbackSites'],['0x1686c52','0x1686e16']);self.assertEqual(len(b['relocations']),4)
  with self.assertRaises(ValueError):t.native_record(self.data[:-1])
 def test_actual_native_scalar_operands_literal_relocations_and_frames_refused(self):
  image=t.native.Image('115',self.data)
  for va in (0x1686cd3,0x1686c34,0x45a128,0x1686e03,0x1686dff,0x1686e36,0x6407910):
   b=bytearray(self.data);b[image.offset(va,1)]^=1
   with self.assertRaises(ValueError):t.native_record(bytes(b))
  mut=bytearray(self.data);off=int(self.record['owners'][0]['frames']['fileOffset'],16);mut[off]^=1
  with self.assertRaises(ValueError):t.native_record(bytes(mut))
 def test_dynamic_flag_error_ordering_empty_tail_and_deduplicated_frozen_inputs(self):
  self.assertEqual(t.reference(b'a\nb',2,[(0,1,0),(0,1,255),(128,1,2)],0),[1,2,3,[1,0x20202020,4,2],[0,0,2,1],[1,0x20202020,4,255]])
  self.assertEqual(t.reference(b'',255,[(128,1,0)],0),[0,255,0])
  self.assertEqual(t.reference(b'\n',0,[],0),[0,1,1,[0,0,1,1]])
  rows,n=t.corpus();self.assertEqual((len(rows),n),(3493,34));self.assertEqual(len({(x['data'],x['initial'],x['actions']) for x in rows}),len(rows))
 def test_captured_object_compiler_and_external_memory_refused(self):
  p=t.ROOT/t.BINARY
  with self.assertRaises(ValueError):t.own_machine(p)
  with patch.object(t.subprocess,'run',side_effect=AssertionError('Forbidden dispatch')):
   with self.assertRaisesRegex(ValueError,'Captured artifact'):t.verify(p,t.ROOT/'work/forbidden-newline')
  with self.assertRaises(t.engine.Unmodelled):t.NoExternalMemory().read(1234,8)
 def test_retained_source_models_raw_trace_hash_and_explicit_scope(self):
  r=json.loads((t.PACKET/'rust-validation.json').read_bytes());self.assertEqual(r['native'],self.record)
  for n,h in r['source_sha256'].items():self.assertEqual(hashlib.sha256((t.CRATE/n).read_bytes()).hexdigest(),h)
  for key,p in [('checker_sha256',Path(t.__file__)),('oracle_sha256',t.ORACLE_PATH),('native_collector_sha256',t.NATIVE_PACKET/'collect.py'),('frozen_vectors_sha256',t.oracle.VECTORS),('shared_engine_sha256',Path(t.engine.__file__))]:self.assertEqual(hashlib.sha256(p.read_bytes()).hexdigest(),r[key])
  self.assertEqual((r['unique_cases'],r['frozen_vectors_included'],r['alignments'],r['evaluations'],r['mismatches']),(3493,34,8,27944,0));self.assertEqual(len(r['raw_comparisons_sha256']),64);self.assertFalse(r['captured_executed']);self.assertFalse(r['target_code_identity_measured'])
 @unittest.skipUnless(RUSTC and importlib.util.find_spec('capstone'),'Explicit HYPERLIQUID_NEWLINE_REQUESTS_RUSTC and Capstone required; not a compiler pass')
 def test_actual_compiler_same_generic_protocol_raw_traces_and_operative_controls(self):
  root=t.ROOT/'work/newline-rust-tests';root.mkdir(parents=True,exist_ok=True);out=Path(tempfile.mkdtemp(dir=root))/'comparison';r=json.loads(json.dumps(t.verify(Path(RUSTC),out)));old=json.loads((t.PACKET/'rust-validation.json').read_bytes())
  for key in ('native','source_sha256','checker_sha256','oracle_sha256','native_collector_sha256','frozen_vectors_sha256','shared_engine_sha256','evaluations','corpus_sha256','raw_comparisons_sha256','mismatches','own_code_sha256','compiled_source_controls','native_operand_controls'):self.assertEqual(r[key],old[key],key)
  self.assertEqual((len(r['compiled_source_controls']),len(r['native_operand_controls'])),(7,6))
  for c in r['compiled_source_controls']+r['native_operand_controls']:self.assertTrue(c['rejected']);self.assertNotEqual(c['expected'],c['changed'])
if __name__=='__main__':unittest.main()
