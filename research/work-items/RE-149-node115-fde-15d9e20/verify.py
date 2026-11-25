"""Verify one pinned node115 FDE using static bytes only."""
import hashlib,pathlib,re,subprocess,tempfile
ROOT=pathlib.Path(__file__).resolve().parents[3]; BIN=ROOT/'artifacts/node/115/hl-node'; START,END=0x15d9e20,0x15d9ef2; FDE='0x15d9e20\t0x15d9ef2\t210\t.text'; DIGEST='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
W={0x15d9e20:'4157', 0x15d9e37:'7261', 0x15d9e4e:'488b5320', 0x15d9e68:'4c8b7b60', 0x15d9e83:'ff151756f004', 0x15d9ea0:'4883c310', 0x15d9ebc:'31d2'}
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
 for a,v in ((0x15d9e20,'ffff'), (0x15d9e37,'ffff')):c(not got.get(a,'').startswith(v),f'mutation {a:#x}')
print('RE-149 static FDE verification passed; 7 witnesses and 2 mutation negatives')
