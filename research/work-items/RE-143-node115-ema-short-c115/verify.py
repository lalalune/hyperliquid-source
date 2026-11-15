"""Verify one pinned node115 FDE using static bytes only."""
import hashlib, pathlib, subprocess, sys, tempfile
ROOT=pathlib.Path(__file__).resolve().parents[3]; BIN=ROOT/'artifacts/node/115/hl-node'; START,END=0x4d44e90,0x4d44f77; FDE='0x4d44e90\t0x4d44f77\t231\t.text\t0xf184bc'; DIGEST='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
W = {
    0x4D44E90: '53',
    0x4D44E95: '4889fb',
    0x4D44E98: '0fb64620',
    0x4D44ED0: 'c6430800',
    0x4D44F1E: '3cc0',
    0x4D44F22: '48b80100000000000080',
    0x4D44F2C: '48894308',
    0x4D44F30: '48c70300000000',
    0x4D44F40: '885620',
    0x4D44F46: '0fb65624',
    0x4D44F4F: 'e84cd4e8ff',
    0x4D44F5E: '0f114318',
    0x4D44F67: '0f114308',
    0x4D44F6B: '488903',
}
def c(x,m):
    if not x: raise AssertionError(m)
d=BIN.read_bytes(); c(hashlib.sha256(d).hexdigest()==DIGEST,'digest')
with tempfile.TemporaryDirectory() as td:
 o=pathlib.Path(td); subprocess.run([sys.executable, str(ROOT/'tools/fde_extents.py'),'--release','115','--output-dir',td],check=True,stdout=subprocess.DEVNULL); c(any(r.startswith(FDE+'\t') for r in (o/'node-115-fde.tsv').read_text().splitlines()),'fde')
 p=subprocess.run(['objdump','-d','--insn-width=16',f'--start-address={START:#x}',f'--stop-address={END:#x}',str(BIN)],check=True,text=True,capture_output=True); got={}
 for line in p.stdout.splitlines():
  if ':' not in line or '\t' not in line: continue
  a,r=line.split(':',1)
  try:a=int(a.strip(),16)
  except ValueError:continue
  f=r.split('\t');
  if len(f)>1:got[a]=''.join(f[1].split())
 def matches(observed):
     return all(observed.get(address) == code for address, code in W.items())
 c(matches(got), 'instruction witnesses differ')
 for address in (0x4d44e90, 0x4d44f6b):
     changed = got.copy()
     original = bytes.fromhex(changed[address])
     changed[address] = (bytes([original[0] ^ 1]) + original[1:]).hex()
     c(not matches(changed), f"accepted mutated witness {address:#x}")
print('RE-143 static FDE verification passed; 14 witnesses and 2 mutation negatives')
