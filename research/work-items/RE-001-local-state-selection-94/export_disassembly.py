"""Optional bounded exports validated against the complete owner decode."""
import sys
import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
ROOT=Path(__file__).resolve().parents[3];sys.path.insert(0,str(ROOT/'tools'))
import local_state_selection_static as tool

data=(ROOT/tool.BINARY).read_bytes();record=tool.build(data);img=tool.Image(data)
cs=Cs(CS_ARCH_X86,CS_MODE_64)
ins=list(cs.disasm(img.read(tool.START,tool.END-tool.START),tool.START))
assert sum(i.size for i in ins)==tool.END-tool.START
assert all(a.address+a.size==b.address for a,b in zip(ins,ins[1:]))
boundaries={i.address for i in ins}
assert (set(tool.ANCHORS)|{0x226987c,0x226ab49,0x226ab81})<=boundaries
lines=['Node94 raw local-state selection; Capstone 5.0.6 x86-64 Intel.',
       'Target SHA-256 '+tool.SHA256,'No target execution. ELF VAs, no masks.',
       f'Boundary-only complete owner {tool.START:#x}..{tool.END:#x}: {tool.END-tool.START} bytes / {len(ins)} instructions.',
       'Owner SHA-256 '+tool.BODY_SHA]
for kind in ('fde','cie'):
    va=int(record['owner'][kind],16);size=struct.unpack('<I',img.read(va,4))[0]+4
    lines.append(f'{kind} {va:#x} raw '+img.read(va,size).hex())
total_bytes=total_insns=0
for lo,hi in tool.RANGES:
    selected=[i for i in ins if lo<=i.address<hi]
    assert selected[0].address==lo and selected[-1].address+selected[-1].size==hi
    assert sum(i.size for i in selected)==hi-lo
    total_bytes+=hi-lo;total_insns+=len(selected)
    lines.append(f'\nRetained {lo:#x}..{hi:#x}: {hi-lo} bytes / {len(selected)} instructions')
    lines += [f'{i.address:#x} {i.bytes.hex():30} {i.mnemonic} {i.op_str}'.rstrip() for i in selected]
lines.append(f'Selected scope: {total_bytes} bytes / {total_insns} instructions. Full poller/producer semantics unproved.')
Path(__file__).with_name('excerpts.capstone.txt').write_text('\n'.join(lines)+'\n',encoding='utf8',newline='\n')
print(lines[-1])
