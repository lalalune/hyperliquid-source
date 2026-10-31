"""Optional Capstone full-window export; never executes captured code."""
import sys
import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'tools'))
import address_parser_static as tool

data=(ROOT/tool.BINARY).read_bytes();record=tool.build(data);img=tool.Image(data)
cs=Cs(CS_ARCH_X86,CS_MODE_64)
lines=['Static node94 address parser and hex iterator; Capstone 5.0.6 x86-64 Intel.',
       'Target SHA-256 '+tool.SHA256,'No target execution. Addresses are ELF VAs.']
total_bytes=total_insns=0;boundaries=set()
for owner in record['owners']:
    start,end=int(owner['start'],16),int(owner['end_exclusive'],16)
    instructions=list(cs.disasm(img.read(start,end-start),start))
    assert sum(i.size for i in instructions)==end-start
    assert all(a.address+a.size==b.address for a,b in zip(instructions,instructions[1:]))
    boundaries.update(i.address for i in instructions)
    total_bytes+=end-start;total_insns+=len(instructions)
    lines.append(f'\nFDE {start:#x}..{end:#x}; {end-start} bytes / {len(instructions)} instructions; SHA-256 '+owner['sha256'])
    for kind in ('fde','cie'):
        va=int(owner[kind],16);size=struct.unpack('<I',img.read(va,4))[0]+4
        lines.append(f'{kind} {va:#x} raw '+img.read(va,size).hex())
    lines.extend(f'{i.address:#x} {i.bytes.hex():30} {i.mnemonic} {i.op_str}'.rstrip() for i in instructions)
assert set(tool.ANCHORS)<=boundaries
lines.append(f'\nComplete selected windows: {total_bytes} bytes / {total_insns} instructions. No helper/error/caller closure claim.')
Path(__file__).with_name('windows.capstone.txt').write_text('\n'.join(lines)+'\n',encoding='utf8',newline='\n')
print(lines[-1])
