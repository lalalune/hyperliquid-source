import hashlib,importlib.util,json,os,sys,tempfile,unittest,struct
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import priority_three115_rust as t
RUSTC=os.environ.get('HYPERLIQUID_PRIORITY_THREE_RUSTC')
class PriorityThreeRustTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.data=(t.ROOT/t.BINARY).read_bytes();cls.record=t.native_record(cls.data);cls.image=t.engine.Image(cls.data);cls.prefix=cls.image.read(t.native.OWNERS[0][0],t.native.PREFIX_SIZE)
 def test_three_complete_fdes_and_explicit_unknown_native_holes(self):
  self.assertEqual(len(self.record['owners']),3)
  for o in self.record['owners']:self.assertEqual((o['bytes'],o['instructions']),(1171,267))
  self.assertEqual(self.record['normal_combination_domain'],16777216);self.assertTrue(self.record['defined_projection_only']);self.assertEqual(len(self.record['unqualified_native_bytes']),3)
  with self.assertRaises(ValueError):t.native_record(self.data[:-1])
 def test_actual_native_operands_frames_and_diagnostic_corruptions(self):
  for va in (0x1839480+0x65,0x1839480+0xf4,0x1839480+0x110,0x641eec0):
   b=bytearray(self.data);b[self.image.off(va,1)]^=1
   with self.assertRaises(ValueError):t.native_record(bytes(b))
  p=bytearray(self.prefix);p[0xf4]=2
  self.assertNotEqual(t.native_projection(p,4096,7,(7,11,13)),t.native_projection(self.prefix,4096,7,(7,11,13)))
 def test_every_scalar_value_channel_and_counter_boundary(self):
  for n in range(256):
   for channel in range(3):
    values=tuple(n if i==channel else 0 for i in range(3));a=t.native_projection(self.prefix,4097,t.engine.MASK-3,values)['probe_words']
    self.assertEqual(a,[1,4100,t.engine.MASK,0,0,*[int.from_bytes(struct.pack('<d',v),'little') for v in values],0])
  for args in ((0,0,(0,0,0)),(4096,t.engine.MASK,(0,0,0)),(4096,0,(256,0,0))):
   with self.assertRaises(ValueError):t.native_projection(self.prefix,*args)
 def test_captured_input_refused_before_compiler_or_object_dispatch(self):
  p=t.ROOT/t.BINARY
  with self.assertRaises(ValueError):t.own_machine(p)
  with patch.object(t.subprocess,'run',side_effect=AssertionError('Forbidden dispatch')):
   with self.assertRaisesRegex(ValueError,'Captured artifact'):t.verify(p,t.ROOT/'work/forbidden-priority')
  with self.assertRaises(t.engine.Unmodelled):t.NoExternalMemory().read(1234,8)
 def test_retained_source_models_and_exact_comparison_scope(self):
  r=json.loads((t.PACKET/'rust-validation.json').read_bytes());self.assertEqual(r['native'],self.record)
  for n,h in r['source_sha256'].items():self.assertEqual(hashlib.sha256((t.CRATE/n).read_bytes()).hexdigest(),h)
  for key,p in [('checker_sha256',Path(t.__file__)),('native_model_sha256',Path(t.native.__file__)),('shared_engine_sha256',Path(t.engine.__file__))]:self.assertEqual(hashlib.sha256(p.read_bytes()).hexdigest(),r[key])
  self.assertEqual((r['unique_triples'],r['state_pairs'],r['evaluations'],r['mismatches']),(9467,9,85203,0));self.assertFalse(r['captured_executed']);self.assertFalse(r['target_code_identity_measured'])
 @unittest.skipUnless(RUSTC and importlib.util.find_spec('capstone'),'Explicit HYPERLIQUID_PRIORITY_THREE_RUSTC and Capstone required; not a compiler pass')
 def test_actual_compiler_all_states_and_operative_controls(self):
  root=t.ROOT/'work/priority-rust-tests';root.mkdir(parents=True,exist_ok=True);out=Path(tempfile.mkdtemp(dir=root))/'comparison';r=t.verify(Path(RUSTC),out);old=json.loads((t.PACKET/'rust-validation.json').read_bytes())
  for key in ('native','source_sha256','checker_sha256','native_model_sha256','shared_engine_sha256','evaluations','mismatches','own_code_sha256','compiled_source_controls','native_operand_controls'):self.assertEqual(r[key],old[key],key)
  self.assertEqual((len(r['compiled_source_controls']),len(r['native_operand_controls'])),(7,6))
  for c in r['compiled_source_controls']+r['native_operand_controls']:self.assertTrue(c['rejected']);self.assertNotEqual(c['expected'],c['changed'])
if __name__=='__main__':unittest.main()
