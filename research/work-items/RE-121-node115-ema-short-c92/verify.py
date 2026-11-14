#!/usr/bin/env python3
import hashlib, pathlib, subprocess, sys, tempfile
ROOT = pathlib.Path(__file__).resolve().parents[3]
BIN = ROOT / 'artifacts/node/115/hl-node'
START, END, FDE = 0x4D437A0, 0x4D43922, 0xF180B8
TARGET = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
W = {
    0x4D437A0: '4156',
    0x4D437A7: '4889fb',
    0x4D437AA: '488b4e20',
    0x4D437B2: '4839c8',
    0x4D437F6: '4c894e28',
    0x4D4380C: '4183f96e',
    0x4D4381C: '49be0000000000000080',
    0x4D43840: '4080ff75',
    0x4D43860: '4180f86c',
    0x4D4387C: '80f96c',
    0x4D43885: '4c8933',
    0x4D4388A: '488d154363befb',
    0x4D4389B: 'b912000000',
    0x4D438A6: 'e875a15200',
    0x4D438B1: '711b',
    0x4D438C6: '48ffc0',
    0x4D438C9: '488903',
    0x4D438DB: '0f1103',
    0x4D438E8: 'c3',
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
mut=dict(W); mut[0x4D43885]='4c893b'
if ok(mut): raise SystemExit('marker mutation not rejected')
print({'fde_start':hex(START),'fde_end':hex(END),'fde_bytes':END-START,'eh_frame_offset':hex(FDE),'witnesses':len(W),'identity_controls':2})
