"""Retain a complete static decode and original FDE/CIE; optional Capstone 5.0.6."""
from pathlib import Path
import struct
import sys
import capstone

ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'tools'))
import time_delta_lowering_static as tool

if capstone.__version__!='5.0.6':raise SystemExit('Use Capstone 5.0.6')
data=(ROOT/'artifacts/node/94/hl-node').read_bytes()
record=tool.build(data);secs=tool.sections(data)

def read(va,size):
    s=next(s for s in secs if s['type']!=8 and s['address']<=va and va+size<=s['address']+s['size'])
    off=s['offset']+va-s['address'];return data[off:off+size]

body=read(tool.START,tool.END-tool.START)
cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
instructions=list(cs.disasm(body,tool.START))
assert len(instructions)==77 and sum(i.size for i in instructions)==len(body)
assert all(a.address+a.size==b.address for a,b in zip(instructions,instructions[1:]))
lines=[f'Capstone {capstone.__version__}; x86-64 Intel syntax; static only',
       f'Target SHA-256 {tool.SHA256}',
       f'VA {tool.START:#x}..{tool.END:#x} exclusive; {len(body)} bytes; 77 instructions',
       f'Body SHA-256 {tool.BODY_SHA256}']
for kind in ('fde_va','cie_va'):
    va=int(record['range'][kind],16);size=struct.unpack('<I',read(va,4))[0]+4
    lines.append(f'{kind} {va:#x} raw {read(va,size).hex()}')
lines += [f'{i.address:#x} {i.bytes.hex():30} {i.mnemonic} {i.op_str}'.rstrip() for i in instructions]
Path(__file__).with_name('window.capstone.txt').write_text('\n'.join(lines)+'\n',encoding='utf8',newline='\n')
print('All 343 bytes / 77 instructions exported; no captured execution.')
