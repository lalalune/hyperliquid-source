#!/usr/bin/env python3
import hashlib, pathlib, subprocess, sys, tempfile

ROOT=pathlib.Path(__file__).resolve().parents[3]
BIN=ROOT/'artifacts/node/115/hl-node'; START,END,FDE=0x4d3e0c0,0x4d3e194,0xf17824
W={0x4d3e0c0:'0fb6472a',0x4d3e0c8:'3c03',0x4d3e0f2:'483b4608',0x4d3e138:'488b5720',0x4d3e15a:'ff1598187a01',0x4d3e120:'0fb64728',0x4d3e178:'0fb64729'}
TARGET='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
if hashlib.sha256(BIN.read_bytes()).hexdigest()!=TARGET: raise SystemExit('target hash mismatch')
with tempfile.TemporaryDirectory() as td:
    subprocess.check_call([sys.executable,str(ROOT/'tools/fde_extents.py'),'--release','115','--output-dir',td],stdout=subprocess.DEVNULL)
    rows=(pathlib.Path(td)/'node-115-fde.tsv').read_text().splitlines()
    if not any(r.startswith(f'{START:#x}\t{END:#x}\t') for r in rows): raise SystemExit('FDE boundary mismatch')
obj=subprocess.check_output(['/opt/homebrew/opt/binutils/bin/objdump','-d','--start-address='+hex(START),'--stop-address='+hex(END),str(BIN)],text=True)
got={}
for line in obj.splitlines():
    if ':' not in line: continue
    a,rest=line.split(':',1)
    try: addr=int(a.strip(),16)
    except ValueError: continue
    f=rest.split('\t'); got[addr]=''.join(f[1].split()) if len(f)>1 else ''
def matches(w): return all(got.get(a,'').startswith(b) for a,b in w.items())
if not matches(W): raise SystemExit('witness mismatch')
bad=dict(W); bad[0x4d3e0c8]='3d03'
if matches(bad): raise SystemExit('identity mutation not rejected')
bad=dict(W); bad[0x4d3e15a]='ff1598187b01'
if matches(bad): raise SystemExit('call-site mutation not rejected')
print({'fde_start':hex(START),'fde_end':hex(END),'fde_bytes':END-START,'eh_frame_offset':hex(FDE),'witnesses':len(W),'identity_controls':2})
