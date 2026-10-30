"""Static full-window export with the optional Capstone 5.0.6 decoder."""
from pathlib import Path
import struct
import sys
import capstone

ROOT=Path(__file__).resolve().parents[3];sys.path.insert(0,str(ROOT/'tools'))
import compound_ascii_static as tool

if capstone.__version__!='5.0.6':raise SystemExit('Use Capstone 5.0.6')
data=(ROOT/'artifacts/node/94/hl-node').read_bytes();record=tool.build(data);secs=tool.sections(data)

def read(va,size):
    s=next(s for s in secs if s['type']!=8 and s['address']<=va and va+size<=s['address']+s['size'])
    off=s['offset']+va-s['address'];return data[off:off+size]

body=read(tool.START,tool.END-tool.START);cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
instructions=list(cs.disasm(body,tool.START))
assert len(instructions)==83 and sum(i.size for i in instructions)==len(body)
assert all(a.address+a.size==b.address for a,b in zip(instructions,instructions[1:]))
addresses={i.address for i in instructions}
assert all(va in addresses for va in [0x284b431,0x284b442,0x284b44d,0x284b45f,0x284b47a,
    0x284b492,0x284b4af,0x284b4b6,0x284b4d2,0x284b4f0,0x284b4fd,0x284b515,0x284b532,0x284b539])
lines=[f'Capstone {capstone.__version__}; x86-64 Intel syntax; static only',f'Target SHA-256 {tool.SHA256}',
       f'VA {tool.START:#x}..{tool.END:#x} exclusive; 283 bytes; 83 instructions',f'Body SHA-256 {tool.BODY_SHA256}']
for kind in ('fde_va','cie_va'):
    va=int(record['range'][kind],16);size=struct.unpack('<I',read(va,4))[0]+4
    lines.append(f'{kind} {va:#x} raw {read(va,size).hex()}')
lines += [f'{i.address:#x} {i.bytes.hex():30} {i.mnemonic} {i.op_str}'.rstrip() for i in instructions]
Path(__file__).with_name('window.capstone.txt').write_text('\n'.join(lines)+'\n',encoding='utf8',newline='\n')
print('All 283 bytes / 83 instructions exported; no captured execution.')
