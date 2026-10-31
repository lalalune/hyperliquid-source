"""Complete two-owner export; Capstone 5.0.6 x86-64 Intel; static only."""
import sys
import struct
from pathlib import Path
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
ROOT=Path(__file__).resolve().parents[3];sys.path.insert(0,str(ROOT/'tools'))
import abci_latency_split as tool
data=(ROOT/tool.BINARY).read_bytes();record=tool.build(data);img=tool.Image(data)
cs=Cs(CS_ARCH_X86,CS_MODE_64);boundaries=set();total_bytes=total_insns=0
lines=['Node94 selected ABCI latency dataflow; Capstone 5.0.6 x86-64 Intel.',
       'Target SHA-256 '+tool.SHA256,'ELF VAs, no masks, no native clock/metric/captured executable execution.']
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
for va in (0x3d225cc,0x3d225d0,0x3d225e5,0x3d225f5,0x3d22603,0x3d22609,0x3d2282e,0x3d22839,0x3d2293d,0x3d229b0,0x3d229d4,0x3d22a44,0x3d22a6b):assert va in boundaries
lines.append(f'Complete exports: {total_bytes} bytes / {total_insns} instructions; selected normal finite latency dataflow only.')
Path(__file__).with_name('owners.capstone.txt').write_text('\n'.join(lines)+'\n',encoding='utf8',newline='\n')
print(lines[-1])
