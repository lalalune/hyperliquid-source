#!/usr/bin/env python3
import hashlib, pathlib, subprocess, sys, tempfile
ROOT=pathlib.Path(__file__).resolve().parents[3]; BIN=ROOT/'artifacts/node/115/hl-node'
START,END,FDE=0x4D3F940,0x4D42472,0x12F2794
TARGET='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
W={0x4D3F940:'55',0x4D3F995:'e836079500',0x4D4245F:'e8ec290b00',0x4D42467:'e8e4e56a01',0x4D4246C:'ff154ed07901'}
if hashlib.sha256(BIN.read_bytes()).hexdigest()!=TARGET: raise SystemExit('target hash mismatch')
with tempfile.TemporaryDirectory() as td:
 subprocess.check_call([sys.executable,str(ROOT/'tools/fde_extents.py'),'--release','115','--output-dir',td],stdout=subprocess.DEVNULL)
 rows=(pathlib.Path(td)/'node-115-fde.tsv').read_text().splitlines()
 if not any(r.startswith(f'{START:#x}\t{END:#x}\t{END-START}\t.text\t{FDE:#x}') for r in rows): raise SystemExit('FDE boundary mismatch')
obj=subprocess.check_output(['/opt/homebrew/opt/binutils/bin/objdump','-d',f'--start-address={START:#x}',f'--stop-address={END:#x}',str(BIN)],text=True)
got={}
for line in obj.splitlines():
 if ':' not in line: continue
 a,rest=line.split(':',1)
 try: a=int(a.strip(),16)
 except ValueError: continue
 f=rest.split('\t'); got[a]=''.join(f[1].split()) if len(f)>1 else ''
def ok(w): return all(got.get(a,'').startswith(b) for a,b in w.items())
if not ok(W): raise SystemExit('witness mismatch')
b=dict(W); b[START]='54'
if ok(b): raise SystemExit('entry mutation not rejected')
b=dict(W); b[0x4D3F995]='e936079500'
if ok(b): raise SystemExit('call mutation not rejected')
print({'fde_start':hex(START),'fde_end':hex(END),'fde_bytes':END-START,'eh_frame_offset':hex(FDE),'witnesses':len(W),'identity_controls':2})
