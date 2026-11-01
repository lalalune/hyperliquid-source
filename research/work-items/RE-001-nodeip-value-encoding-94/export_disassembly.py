"""Complete owners; Capstone 5.0.6 x86-64 Intel; static only."""
from pathlib import Path
import struct
import sys
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
ROOT=Path(__file__).resolve().parents[3];sys.path.insert(0,str(ROOT/'tools'))
import nodeip_value_encoding as tool
data=(ROOT/tool.BINARY).read_bytes();record=tool.build(data);image=tool.Image(data)
cs=Cs(CS_ARCH_X86,CS_MODE_64);total=count=0
lines=['Node94 bounded static research. Capstone 5.0.6 x86-64 Intel.',
       'Target SHA-256 '+tool.SHA256,'ELF VAs, no masks. Complete owners, selected models only.']
for owner in record['owners']:
    start,end=int(owner['start'],16),int(owner['end_exclusive'],16)
    instructions=list(cs.disasm(image.read(start,end-start),start))
    assert sum(i.size for i in instructions)==end-start
    assert all(a.address+a.size==b.address for a,b in zip(instructions,instructions[1:]))
    total+=end-start;count+=len(instructions)
    lines.append(f'\nComplete owner {start:#x}..{end:#x}: {end-start} bytes / {len(instructions)} instructions; SHA-256 '+owner['sha256'])
    for kind in ('fde','cie'):
        va=int(owner[kind],16);size=struct.unpack('<I',image.read(va,4))[0]+4
        lines.append(f'{kind} {va:#x} raw '+image.read(va,size).hex())
    lines.extend(f'{i.address:#x} {i.bytes.hex():30} {i.mnemonic} {i.op_str}'.rstrip() for i in instructions)
lines.append(f'Complete exports: {total} bytes / {count} instructions; no captured executable or callee runs.')
Path(__file__).with_name('owners.capstone.txt').write_text('\n'.join(lines)+'\n',encoding='utf8',newline='\n')
print(lines[-1])
