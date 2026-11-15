"""Verify one pinned node115 FDE using static bytes only."""
import hashlib, pathlib, subprocess, sys, tempfile
ROOT=pathlib.Path(__file__).resolve().parents[3]; BIN=ROOT/'artifacts/node/115/hl-node'; START,END=0x4d45150,0x4d4523a; FDE='0x4d45150\t0x4d4523a\t234\t.text\t0xf18558'; DIGEST='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
W = {
    0x4D45150: '53',
    0x4D45155: '4889fb',
    0x4D45158: '0fb64620',
    0x4D45190: 'c60300',
    0x4D451D6: '3cc0',
    0x4D451DA: '48c7430800000000',
    0x4D451EA: '488d15b10fbffb',
    0x4D451F4: 'b902000000',
    0x4D451F9: 'e822f2a7ff',
    0x4D451FE: '803c2409',
    0x4D45202: '751d',
    0x4D45209: '48c7430801000000',
    0x4D45211: '48894310',
    0x4D45215: 'c60309',
    0x4D4522A: '0f114b10',
    0x4D4522E: '0f1103',
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
 for address in (0x4d45150, 0x4d45215):
     changed = got.copy()
     original = bytes.fromhex(changed[address])
     changed[address] = (bytes([original[0] ^ 1]) + original[1:]).hex()
     c(not matches(changed), f"accepted mutated witness {address:#x}")
print('RE-146 static FDE verification passed; 16 witnesses and 2 mutation negatives')
