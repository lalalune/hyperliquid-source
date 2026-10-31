"""Optional complete Capstone export, never executes target code."""
import sys
import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
ROOT=Path(__file__).resolve().parents[3];sys.path.insert(0,str(ROOT/'tools'))
import checkpoint_flow_static as tool

data=(ROOT/tool.BINARY).read_bytes();record=tool.build(data);img=tool.Image(data)
cs=Cs(CS_ARCH_X86,CS_MODE_64)
ins=list(cs.disasm(img.read(tool.START,tool.END-tool.START),tool.START))
assert sum(i.size for i in ins)==tool.END-tool.START
assert all(a.address+a.size==b.address for a,b in zip(ins,ins[1:]))
boundaries={i.address for i in ins}
assert (set(tool.ANCHORS)|set(tool.CALLS)|{m[0] for m in tool.MESSAGES}|{m[3] for m in tool.MESSAGES})<=boundaries
lines=['Node94 checkpoint wrapper; Capstone 5.0.6 x86-64 Intel.',
       'Target SHA-256 '+tool.SHA256,'No target execution. ELF VAs, no masks.',
       f'Complete FDE {tool.START:#x}..{tool.END:#x}: {tool.END-tool.START} bytes / {len(ins)} instructions.',
       'Body SHA-256 '+tool.BODY_SHA]
for kind in ('fde','cie'):
    va=int(record['owner'][kind],16);size=struct.unpack('<I',img.read(va,4))[0]+4
    lines.append(f'{kind} {va:#x} raw '+img.read(va,size).hex())
lines += [f'{i.address:#x} {i.bytes.hex():30} {i.mnemonic} {i.op_str}'.rstrip() for i in ins]
Path(__file__).with_name('window.capstone.txt').write_text('\n'.join(lines)+'\n',encoding='utf8',newline='\n')
print(lines[3])
