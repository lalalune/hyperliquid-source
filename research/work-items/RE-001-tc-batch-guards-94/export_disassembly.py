"""Complete static TC-path export; optional pinned Capstone 5.0.6 decoder."""
from pathlib import Path
import struct
import sys
import capstone

ROOT=Path(__file__).resolve().parents[3];sys.path.insert(0,str(ROOT/'tools'))
import tc_batch_guards_static as tool

if capstone.__version__!='5.0.6':raise SystemExit('Use Capstone 5.0.6')
data=(ROOT/'artifacts/node/94/hl-node').read_bytes();record=tool.build(data);secs=tool.sections(data)

def read(va,size):
    s=next(s for s in secs if s['type']!=8 and s['address']<=va and va+size<=s['address']+s['size'])
    off=s['offset']+va-s['address'];return data[off:off+size]

cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
body=read(tool.START,tool.END-tool.START);instructions=list(cs.disasm(body,tool.START))
assert len(instructions)==244 and sum(i.size for i in instructions)==len(body)
assert all(a.address+a.size==b.address for a,b in zip(instructions,instructions[1:]))
addresses={i.address for i in instructions}
assert all(va in addresses for va in [0x475950a,0x4759515,0x4759519,0x47595a4,0x47595a9,
    0x47595ac,0x47595ba,0x47595e1,0x47595e5,0x47595e8,0x47595ee,0x47595f2,0x4759600,
    0x4759605,0x4759608,0x475960a,0x4759610,0x4759613,0x4759655,0x4759659,0x4759663,
    0x4759667,0x475966a,0x4759673,0x4759677,0x475967f,0x4759689,0x475968d,0x4759690,0x4759694])
lines=[f'Capstone {capstone.__version__}; x86-64 Intel syntax; static only',f'Target SHA-256 {tool.SHA256}',
       f'VA {tool.START:#x}..{tool.END:#x} exclusive; 1139 bytes; 244 instructions',f'Body SHA-256 {tool.BODY_SHA256}']
for kind in ('fde_va','cie_va'):
    va=int(record['range'][kind],16);size=struct.unpack('<I',read(va,4))[0]+4
    lines.append(f'{kind} {va:#x} raw {read(va,size).hex()}')
lines += [f'{i.address:#x} {i.bytes.hex():30} {i.mnemonic} {i.op_str}'.rstrip() for i in instructions]
Path(__file__).with_name('window.capstone.txt').write_text('\n'.join(lines)+'\n',encoding='utf8',newline='\n')
print('All 1139 bytes / 244 instructions exported; no captured code executed.')
