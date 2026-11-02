"""Re-export complete digest-bound FDE owners using Capstone5.0.6; no execution."""
from pathlib import Path
import struct,sys
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
ROOT=Path(__file__).resolve().parents[3];sys.path.insert(0,str(ROOT/'tools'))
import mempool_hit_preparation as tool
data=(ROOT/tool.BINARY).read_bytes();record=tool.build(data);image=tool.Image(data)
cs=Cs(CS_ARCH_X86,CS_MODE_64);total=count=0
lines=['Capstone5.0.6, x86-64 Intel. Complete FDE owners; static only.','Target SHA-256 '+tool.SHA256]
for owner in record['owners']:
 start,end=int(owner['start'],16),int(owner['end_exclusive'],16)
 ins=list(cs.disasm(image.read(start,end-start),start))
 assert sum(i.size for i in ins)==end-start and all(a.address+a.size==b.address for a,b in zip(ins,ins[1:]))
 total+=end-start;count+=len(ins)
 lines.append(f'\nOwner {start:#x}..{end:#x}; SHA-256 '+owner['sha256'])
 for kind in ('fde','cie'):
  va=int(owner[kind],16);size=struct.unpack('<I',image.read(va,4))[0]+4
  lines.append(f'{kind} {va:#x} '+image.read(va,size).hex())
 lines.extend(f'{i.address:#x} {i.bytes.hex():30} {i.mnemonic} {i.op_str}'.rstrip() for i in ins)
lines.append(f'Complete owners: {total} bytes / {count} instructions. No native execution.')
Path(__file__).with_name('owners.capstone.txt').write_text('\n'.join(lines)+'\n',encoding='utf8',newline='\n')
print(lines[-1])
