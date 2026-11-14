#!/usr/bin/env python3
import hashlib, pathlib, subprocess, sys, tempfile

ROOT=pathlib.Path(__file__).resolve().parents[3]
BIN=ROOT/'artifacts/node/115/hl-node'; START,END,FDE=0x4d3e400,0x4d3e44a,0xf178c4
W={0x4d3e400:'4156',0x4d3e408:'483b5610',0x4d3e41c:'ff15d6157a01',0x4d3e430:'4983c618',0x4d3e434:'4883c318',0x4d3e445:'e9c6980c00'}
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
bad=dict(W); bad[0x4d3e408]='483b5710'
if matches(bad): raise SystemExit('identity mutation not rejected')
bad=dict(W); bad[0x4d3e41c]='ff15d6157b01'
if matches(bad): raise SystemExit('call-site mutation not rejected')
print({'fde_start':hex(START),'fde_end':hex(END),'fde_bytes':END-START,'eh_frame_offset':hex(FDE),'witnesses':len(W),'identity_controls':2})
