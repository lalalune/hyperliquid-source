"""Bind the private split's selected obligations and preserve static-only scope."""
from pathlib import Path
import hashlib,importlib.util,json,tempfile,unittest
from unittest import mock
ROOT=Path(__file__).resolve().parents[1];P=ROOT/'research/work-items/RE-004-quantity-signed-split-115'
spec=importlib.util.spec_from_file_location('quantity_split_collect',P/'collect.py');c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
class QuantitySplit(unittest.TestCase):
 @classmethod
 def setUpClass(cls):cls.data=(ROOT/'artifacts/node/115/hl-node').read_bytes()
 def test_whole_target_and_full_fde(self):
  d=json.loads((P/'records.json').read_text());self.assertEqual(hashlib.sha256(self.data).hexdigest(),c.SHA);self.assertEqual(len(d['windows']),1);w=d['windows'][0];self.assertEqual((w['start'],w['end'],w['bytes']),('0x3f10c10','0x3f10ecf',703));self.assertEqual(hashlib.sha256(c.read(self.data,0x3f10c10,703)[1]).hexdigest(),w['sha256']);self.assertEqual(d['implementation_bytes'],0);self.assertEqual(d['requested_gates'],[])
 def test_actual_signed_split_and_multiplier(self):
  f=c.anchors(self.data);self.assertEqual(f['positive_multiplier'],100);self.assertEqual(f['negative_min_word'],'0x8000000000000000');self.assertEqual(c.read(self.data,0x3f10dc8,2)[1],b'\x0f\x88');self.assertEqual(c.read(self.data,0x3f10dd4,2)[1],b'\x70\x80')
 def test_real_byte_corruption_controls(self):
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
 def test_helper_calls_and_diagnostic_source_location(self):
  d=json.loads((P/'records.json').read_text());calls={x['pc']:x for x in d['windows'][0]['calls']}
  for pc,target in [('0x3f10d51','0x3cde300'),('0x3f10db3','0x37c3750'),('0x3f10de3','0x3cd0da0'),('0x3f10deb','0x3f14f20')]:self.assertEqual(calls[pc]['target'],target)
  self.assertEqual(calls['0x3f10e13']['slot'],'0x64e4ea8');loc=d['source_locations'][0];self.assertEqual((loc['slot'],loc['path'],loc['line'],loc['column'],loc['xrefs']),('0x6487460','l1/src/qtys/mod.rs',835,1,['0x3f10e0c']))
 def test_saved_value_store_and_output_before_drop(self):
  self.assertEqual(c.read(self.data,0x3f10df0,6)[1].hex(),'4889c34c8b20');self.assertEqual(c.read(self.data,0x3f10e19,3)[1].hex(),'4d01f4');self.assertEqual(c.read(self.data,0x3f10e23,4)[1].hex(),'4c0f42e0')
  w=json.loads((P/'records.json').read_text())['windows'][0];self.assertTrue(any(x['pc']=='0x3f10e70' and x['target']=='0x39340c0' for x in w['calls']));self.assertEqual(c.read(self.data,0x3f10e51,4)[1].hex(),'0f114b30')
 def test_scope_and_illustrations_are_not_oracle(self):
  p=json.loads((P/'split-plan.json').read_text());self.assertFalse(p['native_or_rust_execution']);self.assertFalse(p['whole_transform_model']);self.assertFalse(p['helper_results_supplied']);self.assertEqual(p['positive_scale_unsigned_threshold'],184467440737095516);self.assertEqual(len(p['local_math_illustrations']),50);self.assertIn('duplicate-key policy',p['unclosed'])
if __name__=='__main__':unittest.main()
