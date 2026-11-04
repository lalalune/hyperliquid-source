"""Per-invocation authenticated byte snapshots for repeated comparison sources."""
from collections import Counter
import errno,json,os,shutil,sys,tempfile,unittest
from pathlib import Path
from unittest import mock
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
import byte_progress
class EvidenceSnapshotTests(unittest.TestCase):
 def fixture(self,root):
  registry=json.loads((ROOT/'research/byte-windows.json').read_text())
  source=Counter(w['source']['path'] for w in registry['windows']).most_common(1)[0][0]
  if source.startswith('artifacts/'):raise ValueError('snapshot fixture must mutate a copied source, never a linked capture')
  windows=[w for w in registry['windows'] if w['source']['path']==source][:2]
  if len(windows)!=2:raise ValueError('repeated-source baseline fixture required')
  registry['windows']=windows
  paths=set(registry['evidence_sha256'])|{'provenance/artifacts.json'}|{x['path'] for x in registry['targets'].values()}
  for name in paths:
   dest=root/name;dest.parent.mkdir(parents=True,exist_ok=True)
   if name.startswith('artifacts/'):
    try:os.link(ROOT/name,dest)
    except OSError as e:
     if e.errno!=errno.EXDEV:raise
     shutil.copyfile(ROOT/name,dest)
   else:shutil.copyfile(ROOT/name,dest)
  p=root/'research/byte-windows.json';p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(registry))
  components=json.loads((ROOT/'research/components.json').read_text())['components']
  return components,(root/source).resolve()
 def test_repeated_source_is_authenticated_once_in_one_invocation(self):
  with tempfile.TemporaryDirectory() as folder:
   root=Path(folder);components,source=self.fixture(root);original=Path.read_bytes;reads=[]
   def observed(path):
    if path.resolve()==source:reads.append(path)
    return original(path)
   with mock.patch.object(Path,'read_bytes',new=observed):result=byte_progress.load_coverage(root,'research/byte-windows.json',components)
   self.assertEqual(len(result['windows']),2);self.assertEqual(len(reads),1)
 def test_changed_source_is_reauthenticated_on_next_invocation(self):
  with tempfile.TemporaryDirectory() as folder:
   root=Path(folder);components,source=self.fixture(root)
   byte_progress.load_coverage(root,'research/byte-windows.json',components)
   data=bytearray(source.read_bytes());data[0]^=1;source.write_bytes(data)
   with self.assertRaisesRegex(ValueError,'Byte evidence digest changed'):byte_progress.load_coverage(root,'research/byte-windows.json',components)
if __name__=='__main__':unittest.main()
