"""Target-grounded private length and transformed duplicate guard obligations."""
from pathlib import Path
import hashlib,importlib.util,json,tempfile,unittest
from unittest import mock
ROOT=Path(__file__).resolve().parents[1];P=ROOT/'research/work-items/RE-012-subaccount-label-guard-115'
spec=importlib.util.spec_from_file_location('subaccount_label_collect115',P/'collect.py');c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
class LabelGuard(unittest.TestCase):
 @classmethod
 def setUpClass(cls):cls.data=(ROOT/'artifacts/node/115/hl-node').read_bytes()
 def test_target_and_complete_role_extents(self):
  d=json.loads((P/'records.json').read_text());self.assertEqual(hashlib.sha256(self.data).hexdigest(),c.SHA);self.assertEqual((d['new_helper_bytes'],d['credited_context_bytes'],d['exported_bytes']),(425,1649,2074));self.assertEqual(d['implementation_bytes'],0);self.assertEqual(d['requested_gates'],[])
  for w in d['windows']:self.assertEqual(hashlib.sha256(c.read(self.data,int(w['start'],16),w['bytes'])[1]).hexdigest(),w['sha256'])
 def test_actual_unsigned_length_gate(self):
  for at,raw in [(0x366b361,'498d40ef'),(0x366b365,'4883f8ef'),(0x366b369,'770c'),(0x366b36b,'6641c70424e800')]:self.assertEqual(c.read(self.data,at,len(bytes.fromhex(raw)))[1].hex(),raw)
 def test_actual_byte_corruption_controls(self):
  rows=json.loads((P/'controls.json').read_text());self.assertEqual(len(rows),26)
  for x in rows:
   off,b=c.read(self.data,int(x['va'],16),1);self.assertEqual(b[0],x['old']);changed=bytearray(self.data);changed[off]=x['new']
   with self.assertRaises(ValueError):c.anchors(changed)
 def test_identity_precedes_tools_and_output(self):
  with tempfile.TemporaryDirectory() as tmp:
   out=Path(tmp)/'absent';changed=bytearray(self.data);changed[0]^=1
   with mock.patch.object(c.subprocess,'check_output',side_effect=AssertionError('premature tools')):
    with self.assertRaisesRegex(ValueError,'identity mismatch'):c.collect(changed,out)
   self.assertFalse(out.exists())
 def test_transformation_import_and_source_binding(self):
  d=json.loads((P/'records.json').read_text());bs={x['slot']:x for x in d['bindings']};self.assertEqual(bs['0x64df650']['addend'],'0x141cc40');self.assertEqual(bs['0x64df9f8']['symbol'],'bcmp');self.assertTrue(any(x.get('target')=='0x366b350' for x in d['windows'][1]['calls']));loc=d['source_locations'][0];self.assertEqual((loc['path'],loc['line'],loc['column']),('l1/src/sub_account.rs',75,13));self.assertTrue(loc['xrefs'])
 def test_duplicate_and_final_store_cleanup_order(self):
  for at,raw in [(0x366b3bb,'48c1e306'),(0x366b426,'48396c2440'),(0x366b42b,'7543'),(0x366b423,'41ffd4'),(0x366b4bc,'66b9e600'),(0x366b48d,'66b9a201'),(0x366b491,'6641890c24')]:self.assertEqual(c.read(self.data,at,len(bytes.fromhex(raw)))[1].hex(),raw)
  d=json.loads((P/'records.json').read_text());calls={x['pc']:x for x in d['windows'][0]['calls']};self.assertEqual(calls['0x366b45d']['slot'],'0x64df4a0');self.assertEqual(calls['0x366b4a7']['slot'],'0x64df4a0');self.assertEqual(c.read(self.data,0x366b3f0,2)[1].hex(),'85ed')
 def test_static_scope_and_full_u64_partition(self):
  p=json.loads((P/'label-plan.json').read_text());self.assertFalse(p['native_or_rust_execution']);self.assertFalse(p['whole_label_model']);self.assertFalse(p['helper_results_supplied']);self.assertGreaterEqual(len(p['length_math_illustrations']),40)
  for x in p['length_math_illustrations']:self.assertEqual(x['admitted'],1<=x['raw_length']<=16)
if __name__=='__main__':unittest.main()
