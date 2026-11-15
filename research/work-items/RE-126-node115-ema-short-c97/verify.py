#!/usr/bin/env python3
import hashlib, pathlib, subprocess, sys, tempfile
ROOT = pathlib.Path(__file__).resolve().parents[3]
BIN = ROOT / 'artifacts/node/115/hl-node'
START, END, FDE = 0x4D43D00, 0x4D43DE2, 0xF181AC
TARGET = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
W = {
    0x4D43D00: '53',
    0x4D43D05: '4889fb',
    0x4D43D08: '0fb64620',
    0x4D43D10: 'c6462001',
    0x4D43D2E: '48895610',
    0x4D43D8A: '48c7430800000000',
    0x4D43D9A: '488d15fe23bffb',
    0x4D43DA4: 'b902000000',
    0x4D43DA9: 'e89258a7ff',
    0x4D43DAE: '803c2409',
    0x4D43DB9: '48894308',
    0x4D43DBD: 'c60309',
    0x4D43DE1: 'c3',
}
if hashlib.sha256(BIN.read_bytes()).hexdigest() != TARGET: raise SystemExit('target hash mismatch')
with tempfile.TemporaryDirectory() as td:
    subprocess.check_call([sys.executable,str(ROOT/'tools/fde_extents.py'),'--release','115','--output-dir',td],stdout=subprocess.DEVNULL)
    rows=(pathlib.Path(td)/'node-115-fde.tsv').read_text().splitlines()
    if not any(r.startswith(f'{START:#x}\t{END:#x}\t{END-START}\t.text\t{FDE:#x}') for r in rows): raise SystemExit('FDE boundary mismatch')
obj=subprocess.check_output(['objdump','-d','--insn-width=16',f'--start-address={START:#x}',f'--stop-address={END:#x}',str(BIN)],text=True)
got={}
for line in obj.splitlines():
    if ':' not in line: continue
    a,rest=line.split(':',1)
    try: a=int(a.strip(),16)
    except ValueError: continue
    f=rest.split('\t'); got[a]=''.join(f[1].split()) if len(f)>1 else ''
def ok(w): return all(got.get(a)==b for a,b in w.items())
if not ok(W): raise SystemExit('witness mismatch')
mut=dict(W); mut[START]='52'
if ok(mut): raise SystemExit('entry mutation not rejected')
mut=dict(W); mut[0x4D43D8A]='48c7430801000000'
if ok(mut): raise SystemExit('marker mutation not rejected')
print({'fde_start':hex(START),'fde_end':hex(END),'fde_bytes':END-START,'eh_frame_offset':hex(FDE),'witnesses':len(W),'identity_controls':2})
