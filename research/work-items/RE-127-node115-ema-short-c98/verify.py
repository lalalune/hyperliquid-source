#!/usr/bin/env python3
import hashlib, pathlib, subprocess, sys, tempfile
ROOT = pathlib.Path(__file__).resolve().parents[3]
BIN = ROOT / 'artifacts/node/115/hl-node'
START, END, FDE = 0x4D43DF0, 0x4D43EDA, 0xF181E0
TARGET = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
W = {
    0x4D43DF0: '53',
    0x4D43DF5: '4889fb',
    0x4D43DF8: '0fb64620',
    0x4D43E00: 'c6462001',
    0x4D43E1E: '48895610',
    0x4D43E7A: '48c7430800000000',
    0x4D43E8A: '488d154d41bffb',
    0x4D43E94: 'b90c000000',
    0x4D43E99: 'e8f278a5ff',
    0x4D43E9E: '803c2409',
    0x4D43EA9: '48c7430801000000',
    0x4D43EB1: '48894310',
    0x4D43EB5: 'c60309',
    0x4D43ED9: 'c3',
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
mut=dict(W); mut[0x4D43E7A]='48c7430801000000'
if ok(mut): raise SystemExit('marker mutation not rejected')
print({'fde_start':hex(START),'fde_end':hex(END),'fde_bytes':END-START,'eh_frame_offset':hex(FDE),'witnesses':len(W),'identity_controls':2})
