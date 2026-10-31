"""Complete selected four-owner static export; Capstone 5.0.6 x86-64 Intel."""
import sys
import struct
from pathlib import Path
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
ROOT=Path(__file__).resolve().parents[3];sys.path.insert(0,str(ROOT/'tools'))
import restart_token_filter as tool
data=(ROOT/tool.BINARY).read_bytes();record=tool.build(data);img=tool.Image(data)
cs=Cs(CS_ARCH_X86,CS_MODE_64);boundaries=set();total_bytes=total_insns=0
lines=['Node94 restart-command selected token pipeline; Capstone 5.0.6 x86-64 Intel.',
       'Target SHA-256 '+tool.SHA256,'ELF VAs, no masks, no command/process/captured executable execution.']
for owner in record['owners']:
    start,end=int(owner['start'],16),int(owner['end_exclusive'],16)
    ins=list(cs.disasm(img.read(start,end-start),start))
    assert sum(i.size for i in ins)==end-start
    assert all(a.address+a.size==b.address for a,b in zip(ins,ins[1:]))
    boundaries.update(i.address for i in ins);total_bytes+=end-start;total_insns+=len(ins)
    lines.append(f'\nComplete owner {start:#x}..{end:#x}: {end-start} bytes / {len(ins)} instructions; SHA-256 '+owner['sha256'])
    for kind in ('fde','cie'):
        va=int(owner[kind],16);size=struct.unpack('<I',img.read(va,4))[0]+4
        lines.append(f'{kind} {va:#x} raw '+img.read(va,size).hex())
    lines += [f'{i.address:#x} {i.bytes.hex():30} {i.mnemonic} {i.op_str}'.rstrip() for i in ins]
for va in (0x1438eb7,0x1438eeb,0x1438f3a,0x1438f5e,0x13df3f9,0x13df410,0x13df5b5,0x13df5d3,0x13df5e2,0x14b135f,0x14b1398):assert va in boundaries
lines.append('Join table 0x21b94c raw '+img.read(0x21b94c,20).hex())
lines.append(f'Complete exports: {total_bytes} bytes / {total_insns} instructions; only selected ASCII post-replacement token protocol modeled.')
Path(__file__).with_name('owners.capstone.txt').write_text('\n'.join(lines)+'\n',encoding='utf8',newline='\n')
print(lines[-1])
