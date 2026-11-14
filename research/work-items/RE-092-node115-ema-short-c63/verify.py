#!/usr/bin/env python3
import hashlib, pathlib, subprocess, sys, tempfile

ROOT=pathlib.Path(__file__).resolve().parents[3]
BIN=ROOT/'artifacts/node/115/hl-node'; START,END,FDE=0x4d3ee20,0x4d3ef2d,0xf17b44
W={0x4d3ee20:'4157',0x4d3ee33:'803f05',0x4d3ee5c:'4c397818',0x4d3ee6e:'ff15ec067a01',0x4d3ee82:'0f1103',0x4d3eec0:'ff15f25e7a01',0x4d3eed7:'0f1103',0x4d3eee7:'4883c318'}
TARGET='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
if hashlib.sha256(BIN.read_bytes()).hexdigest()!=TARGET: raise SystemExit('target hash mismatch')
with tempfile.TemporaryDirectory() as td:
    subprocess.check_call([sys.executable,str(ROOT/'tools/fde_extents.py'),'--release','115','--output-dir',td],stdout=subprocess.DEVNULL)
    rows=(pathlib.Path(td)/'node-115-fde.tsv').read_text().splitlines()
    if not any(r.startswith(f'{START:#x}\t{END:#x}\t{END-START}\t.text\t{FDE:#x}\t') for r in rows): raise SystemExit('FDE boundary mismatch')
obj=subprocess.check_output(['objdump','-d','--insn-width=16','--start-address='+hex(START),'--stop-address='+hex(END),str(BIN)],text=True)
got={}
for line in obj.splitlines():
    if ':' not in line: continue
    a,rest=line.split(':',1)
    try: addr=int(a.strip(),16)
    except ValueError: continue
    f=rest.split('\t'); got[addr]=''.join(f[1].split()) if len(f)>1 else ''
cursor = START
partition = bytearray()
for address, encoded in sorted(got.items()):
    if address != cursor or not encoded:
        raise SystemExit('non-contiguous disassembly partition')
    instruction = bytes.fromhex(encoded)
    partition.extend(instruction)
    cursor += len(instruction)
if cursor != END or hashlib.sha256(partition).hexdigest() != '7a3cdda38c477aaeca4568fd37914d606c52c66eb77d6ecbddc0e4ed5919cb81':
    raise SystemExit('disassembly partition differs from the authenticated body')
def matches(w): return all(got.get(a,'').startswith(b) for a,b in w.items())
if not matches(W): raise SystemExit('witness mismatch')
bad=dict(W); bad[0x4d3ee33]='803f04'
if matches(bad): raise SystemExit('identity mutation not rejected')
bad=dict(W); bad[0x4d3ee6e]='ff15ec067b01'
if matches(bad): raise SystemExit('call-site mutation not rejected')
print({'fde_start':hex(START),'fde_end':hex(END),'fde_bytes':END-START,'eh_frame_offset':hex(FDE),'witnesses':len(W),'identity_controls':2})
