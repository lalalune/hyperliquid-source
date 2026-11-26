"""Verify one pinned node115 FDE using static bytes only."""
import hashlib,pathlib,subprocess,tempfile
ROOT=pathlib.Path(__file__).resolve().parents[3]; BIN=ROOT/'artifacts/node/115/hl-node'; START,END=0x4d45330,0x4d4545b; FDE='0x4d45330\t0x4d4545b\t299\t.text\t0xf185c0'; DIGEST='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
W={0x4d45330:'4156',0x4d45333:'4881ec88000000',0x4d4533d:'0fb64620',0x4d45373:'c6430800',0x4d453d5:'31d2',0x4d45445:'b801000000',0x4d4544d:'4889d8'}
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
 for a,v in ((0x4d45330,'4056'),(0x4d45373,'c6430801')):c(not got.get(a,'').startswith(v),f'mutation {a:#x}')
print('RE-148 static FDE verification passed; 7 witnesses and 2 mutation negatives')
