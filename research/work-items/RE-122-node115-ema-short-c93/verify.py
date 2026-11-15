#!/usr/bin/env python3
import hashlib, pathlib, subprocess, sys, tempfile
ROOT = pathlib.Path(__file__).resolve().parents[3]
BIN = ROOT / 'artifacts/node/115/hl-node'
START, END, FDE = 0x4D43930, 0x4D43A3C, 0xF180E4
TARGET = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
W = {
    0x4D43930: '4156',
    0x4D43937: '4889fb',
    0x4D4393A: '49be0000000000000080',
    0x4D43944: '0fb64620',
    0x4D4394C: 'c6462001',
    0x4D4396A: '48895610',
    0x4D4396E: '48894e18',
    0x4D439BC: '3cc0',
    0x4D439BE: '742e',
    0x4D439CB: '31d2',
    0x4D439CD: 'e84e10ebff',
    0x4D439D2: '4c39742408',
    0x4D439E3: '0f114b18',
    0x4D439E7: '0f114308',
    0x4D439EB: '49ffc6',
    0x4D439EE: '4c8933',
    0x4D439F8: '0f114360',
    0x4D43A2E: '0f1103',
    0x4D43A3B: 'c3',
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
mut=dict(W); mut[START]='4157'
if ok(mut): raise SystemExit('entry mutation not rejected')
mut=dict(W); mut[0x4D439EE]='4c893b'
if ok(mut): raise SystemExit('marker mutation not rejected')
print({'fde_start':hex(START),'fde_end':hex(END),'fde_bytes':END-START,'eh_frame_offset':hex(FDE),'witnesses':len(W),'identity_controls':2})
