"""Verify one pinned node115 FDE using static bytes only."""
import hashlib, pathlib, subprocess, tempfile
ROOT=pathlib.Path(__file__).resolve().parents[3]; BIN=ROOT/'artifacts/node/115/hl-node'
START,END=0x4d44870,0x4d44988; FDE='0x4d44870\t0x4d44988\t280\t.text\t0xf18384'; DIGEST='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
W={0x4d44870:'53',0x4d44875:'4889fb',0x4d44878:'0fb64620',0x4d44902:'c7434800000000',0x4d44919:'885620',0x4d4492f:'837c244800',0x4d4497c:'488903'}
def check(x,m):
    if not x: raise AssertionError(m)
data=BIN.read_bytes(); check(hashlib.sha256(data).hexdigest()==DIGEST,'target digest mismatch')
with tempfile.TemporaryDirectory() as td:
    out=pathlib.Path(td); subprocess.run(['python3',str(ROOT/'tools/fde_extents.py'),'--release','115','--output-dir',td],check=True,stdout=subprocess.DEVNULL)
    check(any(r.startswith(FDE+'\t') for r in (out/'node-115-fde.tsv').read_text().splitlines()),'exact FDE row missing')
    p=subprocess.run(['/opt/homebrew/opt/binutils/bin/objdump','-d',f'--start-address={START:#x}',f'--stop-address={END:#x}',str(BIN)],check=True,text=True,capture_output=True); got={}
    for line in p.stdout.splitlines():
        if ':' not in line or '\t' not in line: continue
        a,rest=line.split(':',1)
        try: a=int(a.strip(),16)
        except ValueError: continue
        f=rest.split('\t');
        if len(f)>1: got[a]=''.join(f[1].split())
    for a,prefix in W.items(): check(got.get(a,'').startswith(prefix),f'witness {a:#x}')
    for a,prefix in ((0x4d44870,'52'),(0x4d4497c,'488902')): check(not got.get(a,'').startswith(prefix),f'mutation accepted {a:#x}')
print('RE-137 static FDE verification passed; 7 witnesses and 2 mutation negatives')
