"""Verify one pinned node115 FDE using static bytes only."""
import hashlib, pathlib, subprocess, sys, tempfile
ROOT=pathlib.Path(__file__).resolve().parents[3]; BIN=ROOT/'artifacts/node/115/hl-node'; START,END=0x4d44990,0x4d44ae0; FDE='0x4d44990\t0x4d44ae0\t336\t.text\t0xf183b8'; DIGEST='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
W = {
    0x4D44990: '4156',
    0x4D44997: '4889fb',
    0x4D4499A: '488b4e20',
    0x4D449A5: '0f83c5000000',
    0x4D449D0: '440fb64c02fe',
    0x4D449FC: '4183f96e',
    0x4D44A0C: '49be0100000000000080',
    0x4D44A30: '4080ff75',
    0x4D44A48: '4180f86c',
    0x4D44A60: '80f96c',
    0x4D44A63: '7432',
    0x4D44A65: '48c744240809000000',
    0x4D44A70: '49be0100000000000080',
    0x4D44A7F: 'e8ac620600',
    0x4D44A84: '4c39742408',
    0x4D44A89: '7511',
    0x4D44A90: '48894308',
    0x4D44A94: '49ffc6',
    0x4D44A97: '4c8933',
    0x4D44AA6: '0f114b10',
    0x4D44AAA: '0f1103',
    0x4D44AB8: '48c744240805000000',
    0x4D44ACC: 'e8cf5b5100',
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
 for address in (0x4d44990, 0x4d44a97):
     changed = got.copy()
     original = bytes.fromhex(changed[address])
     changed[address] = (bytes([original[0] ^ 1]) + original[1:]).hex()
     c(not matches(changed), f"accepted mutated witness {address:#x}")
print('RE-138 static FDE verification passed; 23 witnesses and 2 mutation negatives')
