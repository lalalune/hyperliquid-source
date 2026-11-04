import base64,copy,gzip,importlib.util,json,shutil,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
import h2_framing_115_static as c
P=ROOT/'research/work-items/RE-012-h2-framing-115'
spec=importlib.util.spec_from_file_location('h2_packet_verify',P/'verify.py');v=importlib.util.module_from_spec(spec)
old=sys.dont_write_bytecode
try:sys.dont_write_bytecode=True;spec.loader.exec_module(v)
finally:sys.dont_write_bytecode=old

class H2Framing115(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.data=c.TARGET.read_bytes();cls.image=c.Image(cls.data);cls.report=c.analyze(cls.data)
 def rejected(self,data):
  try:c.require(c.analyze(data,identity=False)==self.report,'changed extracted relation')
  except ValueError:return
  self.fail('actual target mutation admitted')
 def test_full_target_exports_and_selected_census(self):
  self.assertEqual(self.report,c.load_json(P/'static/records.json'));self.assertEqual(len(self.report['incoming_census']),7)
  for r in c.load_json(P/'static/commands.json'):
   b=self.report['bodies'][r['name']];raw=(P/f"static/{r['name']}.{r['provider']}.txt").read_text();rows,joins=c.native_rows(raw,int(b['start'],16),int(b['end'],16));self.assertEqual(rows,[(int(i['va'],16),bytes.fromhex(i['bytes']))for i in b['instructions']]);self.assertEqual(joins,r['lock_prefix_joins'])
 def test_actual_semantic_anchor_corruptions(self):
  for name,r in c.load_json(P/'spec.json')['anchors'].items():
   with self.subTest(anchor=name):
    changed=bytearray(self.data);off=self.image.offset(r['start'],1);changed[off]^=1;self.rejected(changed)
 def test_actual_fde_and_relocation_writers(self):
  for name in ['decoder','h2_constructor','split_to']:
   f=self.image.owner(int(self.report['bodies'][name]['start'],16));data=bytearray(self.data);data[self.image.offset(f['fde']+12,1)]^=1;self.rejected(data)
  for slot in [0x64e0c00,0x64e08e8,0x64df508,0x640ce08]:
   row=self.image.relocations[slot];data=bytearray(self.data);data[int(row['file_offset'],16)+16]^=1;self.rejected(data)
  row=self.image.relocations[0x64e0c00];data=bytearray(self.data);data[int(row['file_offset'],16)]^=4;self.rejected(data)
 def test_actual_source_descriptors_and_literals(self):
  for a in [0x640ce08,0x64c7098,0x43c3c1]:
   data=bytearray(self.data);data[self.image.offset(a,1)]^=1;self.rejected(data)
 def test_frozen_math_and_recorded_native_controls(self):
  cases,streams=v.verify_values();self.assertEqual(cases,28360);self.assertGreater(streams,90)
 def test_closed_inventory_unknown_file_directory_symlink(self):
  with tempfile.TemporaryDirectory()as d:
   target=Path(d)/'packet';shutil.copytree(P,target);v.inventory(target)
   q=target/'unexpected';q.write_text('x')
   with self.assertRaises(ValueError):v.inventory(target)
   q.unlink();q.mkdir()
   with self.assertRaises(ValueError):v.inventory(target)
   q.rmdir();q.symlink_to(target/'CONTRACT.md')
   with self.assertRaises(ValueError):v.inventory(target)
 def test_archive_corruption_duplicate_and_boolean_size(self):
  original=json.loads(gzip.decompress((P/'licensed-sources.json.gz').read_bytes()))
  mutations=[];d=copy.deepcopy(original);d['streams'].append(d['streams'][0]);mutations.append(d)
  d=copy.deepcopy(original);d['streams'][0]['bytes']=True;mutations.append(d)
  d=copy.deepcopy(original);d['streams'][0]['base64']=base64.b64encode(b'wrong bytes').decode();mutations.append(d)
  with tempfile.TemporaryDirectory()as tmp:
   p=Path(tmp)/'bad.gz'
   for d in mutations:
    p.write_bytes(gzip.compress(json.dumps(d).encode()))
    with self.assertRaises(ValueError):v.archive(p)
 def test_identity_precedes_decoding(self):
  data=bytearray(self.data);data[-1]^=1
  with self.assertRaisesRegex(ValueError,'identity'):c.analyze(data)

if __name__=='__main__':unittest.main()
