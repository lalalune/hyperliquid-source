"""Complete owner static export; Capstone 5.0.6 x86-64 Intel."""
import sys
import struct
from pathlib import Path
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
ROOT=Path(__file__).resolve().parents[3];sys.path.insert(0,str(ROOT/'tools'))
import validator_history_member as tool
data=(ROOT/tool.BINARY).read_bytes();record=tool.build(data);img=tool.Image(data)
ins=list(Cs(CS_ARCH_X86,CS_MODE_64).disasm(img.read(tool.START,tool.END-tool.START),tool.START))
assert sum(i.size for i in ins)==tool.END-tool.START
assert all(a.address+a.size==b.address for a,b in zip(ins,ins[1:]))
boundaries={i.address for i in ins}
for va in (0x44b305f,0x44b3066,0x44b30d4,0x44b30eb,0x44b3114,0x44b312a,0x44b3146,0x44b3179,0x44b3181,0x44b31b5,0x44b31c0,0x44b31e5,0x44b31e9):assert va in boundaries
lines=['Node94 selected history-result membership; Capstone 5.0.6 x86-64 Intel.',
       'Target SHA-256 '+tool.SHA256,'ELF VAs, no masks, no native history/snapshot/captured executable execution.',
       f'Complete owner {tool.START:#x}..{tool.END:#x}: {tool.END-tool.START} bytes / {len(ins)} instructions; SHA-256 '+tool.BODY]
for kind in ('fde','cie'):
    va=int(record['owner'][kind],16);size=struct.unpack('<I',img.read(va,4))[0]+4
    lines.append(f'{kind} {va:#x} raw '+img.read(va,size).hex())
lines += [f'{i.address:#x} {i.bytes.hex():30} {i.mnemonic} {i.op_str}'.rstrip() for i in ins]
Path(__file__).with_name('owner.capstone.txt').write_text('\n'.join(lines)+'\n',encoding='utf8',newline='\n')
print(lines[3])
