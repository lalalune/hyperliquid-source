"""Verify one pinned node115 FDE using static bytes only."""
import hashlib, pathlib, subprocess, sys, tempfile
ROOT=pathlib.Path(__file__).resolve().parents[3]; BIN=ROOT/'artifacts/node/115/hl-node'
START,END=0x4d44870,0x4d44988; FDE='0x4d44870\t0x4d44988\t280\t.text\t0xf18384'; DIGEST='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
W = {
    0x4D44870: '53',
    0x4D44875: '4889fb',
    0x4D44878: '0fb64620',
    0x4D44902: 'c7434800000000',
    0x4D44909: '48c70300000000',
    0x4D44919: '885620',
    0x4D44924: '31d2',
    0x4D44926: 'e8a5cfb7ff',
    0x4D4492F: '837c244800',
    0x4D44934: '7430',
    0x4D4493B: '48894840',
    0x4D4495F: '0f1100',
    0x4D44962: '31c0',
    0x4D44966: '0f10442408',
    0x4D44974: '0f1100',
    0x4D44977: 'b801000000',
    0x4D4497C: '488903',
}
def check(x,m):
    if not x: raise AssertionError(m)
data=BIN.read_bytes(); check(hashlib.sha256(data).hexdigest()==DIGEST,'target digest mismatch')
with tempfile.TemporaryDirectory() as td:
    out=pathlib.Path(td); subprocess.run([sys.executable, str(ROOT/'tools/fde_extents.py'),'--release','115','--output-dir',td],check=True,stdout=subprocess.DEVNULL)
    check(any(r.startswith(FDE+'\t') for r in (out/'node-115-fde.tsv').read_text().splitlines()),'exact FDE row missing')
    p=subprocess.run(['objdump','-d','--insn-width=16',f'--start-address={START:#x}',f'--stop-address={END:#x}',str(BIN)],check=True,text=True,capture_output=True); got={}
    for line in p.stdout.splitlines():
        if ':' not in line or '\t' not in line: continue
        a,rest=line.split(':',1)
        try: a=int(a.strip(),16)
        except ValueError: continue
        f=rest.split('\t');
        if len(f)>1: got[a]=''.join(f[1].split())
    def matches(observed):
        return all(observed.get(address) == code for address, code in W.items())
    check(matches(got), 'instruction witnesses differ')
    for address in (0x4d44870, 0x4d4497c):
        changed = got.copy()
        original = bytes.fromhex(changed[address])
        changed[address] = (bytes([original[0] ^ 1]) + original[1:]).hex()
        check(not matches(changed), f"accepted mutated witness {address:#x}")
print('RE-137 static FDE verification passed; 17 witnesses and 2 mutation negatives')
