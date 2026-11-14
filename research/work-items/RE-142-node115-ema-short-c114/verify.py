"""Verify one pinned node115 FDE using static bytes only."""
import hashlib,pathlib,subprocess,tempfile
ROOT=pathlib.Path(__file__).resolve().parents[3]; BIN=ROOT/'artifacts/node/115/hl-node'; START,END=0x4d44db0,0x4d44e89; FDE='0x4d44db0\t0x4d44e89\t217\t.text\t0xf18480'; DIGEST='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
W={0x4d44db0:'53',0x4d44db5:'4889fb',0x4d44db8:'0fb64620',0x4d44df0:'c60300',0x4d44e3a:'66c7030902',0x4d44e48:'885620',0x4d44e64:'c60309'}
def c(x,m):
    if not x: raise AssertionError(m)
d=BIN.read_bytes(); c(hashlib.sha256(d).hexdigest()==DIGEST,'digest')
with tempfile.TemporaryDirectory() as td:
 o=pathlib.Path(td); subprocess.run(['python3',str(ROOT/'tools/fde_extents.py'),'--release','115','--output-dir',td],check=True,stdout=subprocess.DEVNULL); c(any(r.startswith(FDE+'\t') for r in (o/'node-115-fde.tsv').read_text().splitlines()),'fde')
 p=subprocess.run(['/opt/homebrew/opt/binutils/bin/objdump','-d',f'--start-address={START:#x}',f'--stop-address={END:#x}',str(BIN)],check=True,text=True,capture_output=True); got={}
 for line in p.stdout.splitlines():
  if ':' not in line or '\t' not in line: continue
  a,r=line.split(':',1)
  try:a=int(a.strip(),16)
  except ValueError:continue
  f=r.split('\t');
  if len(f)>1:got[a]=''.join(f[1].split())
 for a,v in W.items():c(got.get(a,'').startswith(v),f'witness {a:#x}')
 for a,v in ((0x4d44db0,'52'),(0x4d44e64,'c60209')):c(not got.get(a,'').startswith(v),f'mutation {a:#x}')
print('RE-142 static FDE verification passed; 7 witnesses and 2 mutation negatives')
