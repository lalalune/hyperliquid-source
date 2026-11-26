"""Verify one pinned node115 FDE using static bytes only."""
import hashlib,pathlib,re,subprocess,tempfile
ROOT=pathlib.Path(__file__).resolve().parents[3]; BIN=ROOT/'artifacts/node/115/hl-node'; START,END=0x141a8c0,0x141a9f7; FDE='0x141a8c0\t0x141a9f7\t311\t.text'; DIGEST='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
W={0x141a8c0:'4157', 0x141a8e4:'498b4e08', 0x141a90a:'4889da', 0x141a934:'4889c6', 0x141a964:'488d742408', 0x141a991:'48890424', 0x141a9c9:'4889c3'}
def c(x,m):
    if not x: raise AssertionError(m)
d=BIN.read_bytes(); c(hashlib.sha256(d).hexdigest()==DIGEST,'digest')
with tempfile.TemporaryDirectory() as td:
 o=pathlib.Path(td); subprocess.run(['python3',str(ROOT/'tools/fde_extents.py'),'--release','115','--output-dir',td],check=True,stdout=subprocess.DEVNULL); c(any(r.startswith(FDE+'\t') for r in (o/'node-115-fde.tsv').read_text().splitlines()),'fde')
 p=subprocess.run(['objdump','-d',f'--start-address={START:#x}',f'--stop-address={END:#x}',str(BIN)],check=True,text=True,capture_output=True); got={}
 for line in p.stdout.splitlines():
  m=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)',line)
  if m: got[int(m.group(1),16)]=''.join(m.group(2).split())
 for a,v in W.items():c(got.get(a,'').startswith(v),f'witness {a:#x}')
 for a,v in ((0x141a8c0,'ffff'), (0x141a8e4,'ffffffff')):c(not got.get(a,'').startswith(v),f'mutation {a:#x}')
print('RE-147 static FDE verification passed; 7 witnesses and 2 mutation negatives')
