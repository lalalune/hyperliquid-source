"""Verify one pinned node115 FDE using static bytes only."""
import hashlib, pathlib, subprocess, sys, tempfile
ROOT=pathlib.Path(__file__).resolve().parents[3]; BIN=ROOT/'artifacts/node/115/hl-node'; START,END=0x4d45070,0x4d4514f; FDE='0x4d45070\t0x4d4514f\t223\t.text\t0xf18524'; DIGEST='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
W = {
    0x4D45070: '53',
    0x4D45075: '4889fb',
    0x4D45078: '0fb64620',
    0x4D450B0: 'c60300',
    0x4D450F6: '3cc0',
    0x4D450FA: 'c7430400000000',
    0x4D45103: '885620',
    0x4D45109: '488d15c04e71fb',
    0x4D45113: 'b904000000',
    0x4D45118: 'e873d2a6ff',
    0x4D4511D: '803c2409',
    0x4D45121: '7513',
    0x4D45127: '894304',
    0x4D4512A: 'c60309',
    0x4D4513F: '0f114b10',
    0x4D45143: '0f1103',
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
 for address in (0x4d45070, 0x4d4512a):
     changed = got.copy()
     original = bytes.fromhex(changed[address])
     changed[address] = (bytes([original[0] ^ 1]) + original[1:]).hex()
     c(not matches(changed), f"accepted mutated witness {address:#x}")
print('RE-145 static FDE verification passed; 16 witnesses and 2 mutation negatives')
