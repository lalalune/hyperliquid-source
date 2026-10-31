"""Optional complete five-owner static export; Capstone 5.0.6 x86-64 Intel."""
import sys
import struct
from pathlib import Path
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
ROOT=Path(__file__).resolve().parents[3];sys.path.insert(0,str(ROOT/'tools'))
import string_result_wrappers as tool
data=(ROOT/tool.BINARY).read_bytes();record=tool.build(data);img=tool.Image(data)
cs=Cs(CS_ARCH_X86,CS_MODE_64);total_bytes=total_insns=0
lines=['Node94 selected string-result output arms; Capstone 5.0.6 x86-64 Intel.',
       'Target SHA-256 '+tool.SHA256,'ELF VAs, no masks, no native decode/runtime execution.']
for owner in record['owners']:
    start,end=int(owner['start'],16),int(owner['end_exclusive'],16)
    ins=list(cs.disasm(img.read(start,end-start),start))
    assert sum(i.size for i in ins)==end-start
    assert all(a.address+a.size==b.address for a,b in zip(ins,ins[1:]))
    boundaries={i.address for i in ins}
    for key in ('tag_compare','success','error','join','dispatch'):
        assert int(owner[key],16) in boundaries
    assert all(int(t,16) in boundaries for t in owner['cleanup_targets'])
    total_bytes+=end-start;total_insns+=len(ins)
    lines.append(f'\nComplete owner {start:#x}..{end:#x}: {end-start} bytes / {len(ins)} instructions; SHA-256 '+owner['sha256'])
    for kind in ('fde','cie'):
        va=int(owner[kind],16);size=struct.unpack('<I',img.read(va,4))[0]+4
        lines.append(f'{kind} {va:#x} raw '+img.read(va,size).hex())
    lines += [f'{i.address:#x} {i.bytes.hex():30} {i.mnemonic} {i.op_str}'.rstrip() for i in ins]
    table=int(owner['table'],16);lines.append(f'Table {table:#x} raw '+img.read(table,32).hex())
lines.append(f'Complete exports: {total_bytes} bytes / {total_insns} instructions; only selected output arms modeled.')
Path(__file__).with_name('owners.capstone.txt').write_text('\n'.join(lines)+'\n',encoding='utf8',newline='\n')
print(lines[-1])
