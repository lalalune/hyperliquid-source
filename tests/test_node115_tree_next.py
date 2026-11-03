"""Original-byte iterator snapshots, pointer observers and escaped-memory controls."""
import hashlib,importlib.util,json,mmap,subprocess,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
PACKET=ROOT/'research/work-items/RE-014-tree-next-115'
# Packet-local interpreter depends on its private read-only ELF view.
sys.path.insert(0,str(PACKET))
import native
spec=importlib.util.spec_from_file_location('tree_next_audit',PACKET/'audit.py')
audit=importlib.util.module_from_spec(spec);spec.loader.exec_module(audit)

class TreeNextTests(unittest.TestCase):
 def setUp(self):self.im=native.Image();self.addCleanup(self.im.close)
 def test_frozen_smoke_actual_bytes_and_state(self):
  for line in (PACKET/'target-smoke.tsv').read_text().splitlines():
   fields=line.split('\t');actual,_=native.evaluate(self.im,tuple(map(int,fields[:11])))
   self.assertEqual(actual,fields[11])
 def test_real_code_controls_reproduce_without_capture_write(self):
  for rec in json.loads((PACKET/'native-controls.json').read_text()):
   changed=native.Image();self.addCleanup(changed.close)
   changed.data=mmap.mmap(changed.view.file.fileno(),0,access=mmap.ACCESS_COPY)
   va=int(rec['va'],16);self.assertEqual(changed.view.read(va,1).hex(),rec['original_byte'])
   changed.data[changed.view.offset(va)]=int(rec['mutant_byte'],16)
   h,fan,leaf,shape,ready,index=rec['fixture'];values=[]
   for image in (self.im,changed):
    machine,_=native.fixture(image,h,fan,leaf,shape=shape,ready=ready,index=index,level=0)
    result=native.step(machine);state=[machine.load(native.STATE+8*i,8) for i in range(9)]
    values.append(json.loads(json.dumps((result,state))))
   self.assertEqual(values,[rec['before'],rec['after']]);self.assertNotEqual(*values)
  self.assertEqual(hashlib.sha256(self.im.data).hexdigest(),native.SHA)
 def test_empty_bad_tag_and_lazy_canonicalization_order(self):
  for tag,remaining,expected in [(0,0,'NONE'),(0,3,'TAG'),((1<<32)|1,3,'ITEM')]:
   machine,_=native.fixture(self.im,tag=tag,remaining=remaining)
   before=native.snapshot(machine);kind,_=native.step(machine);after=native.snapshot(machine)
   self.assertEqual(kind,expected);self.assertEqual(after[4:8],before[4:8])
   self.assertEqual(after[8],remaining-int(remaining!=0))
   self.assertEqual(after[0],1 if kind=='ITEM' else tag)
 def test_bounds_cover_spill_reload_and_node_readonly(self):
  machine,_=native.fixture(self.im)
  for action in [lambda:machine.store(native.NODES,8,0),lambda:machine.spill(native.NODES,0,8),lambda:machine.reload(0,native.STATE+71,8),lambda:machine.load(native.NODES+415,2)]:
   with self.assertRaisesRegex(ValueError,'footprint'):action()
 def test_static_callers_source_unwind_and_coverage_denominators(self):
  report=audit.audit();self.assertEqual((report['bytes'],report['instructions']),(1223,311))
  freeze=json.loads((PACKET/'FREEZE.json').read_text())
  rows=[line.split('\t') for line in (PACKET/'owners.capstone.tsv').read_text().splitlines()]
  core=[r for r in rows if native.START<=int(r[0],16)<native.END]
  missing=[r for r in core if int(r[0],16) not in freeze['visited_addresses']]
  self.assertEqual(len(missing),5);self.assertEqual(sorted(r[2] for r in missing),['call','call','jmp','ud2','ud2'])
 def test_freeze_refuses_post_rust_under_python_optimized(self):
  with tempfile.TemporaryDirectory() as d:
   p=subprocess.run([sys.executable,'-O',str(PACKET/'freeze-producer.py'),'--output',str(Path(d)/'out'),'--objdump','/no/tool'],capture_output=True)
   self.assertNotEqual(p.returncode,0);self.assertIn(b'freeze refuses existing Rust',p.stderr);self.assertFalse((Path(d)/'out').exists())
if __name__=='__main__':unittest.main()
