"""Full classifier and selected real caller export, optional Capstone only."""
import sys
import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
ROOT=Path(__file__).resolve().parents[3];sys.path.insert(0,str(ROOT/'tools'))
import rpc_code_static as tool

data=(ROOT/tool.BINARY).read_bytes();record=tool.build(data);img=tool.Image(data)
cs=Cs(CS_ARCH_X86,CS_MODE_64);boundaries=set();lines=[
    'Node94 static raw code classifier; Capstone 5.0.6 x86-64 Intel.',
    'Target SHA-256 '+tool.SHA256,'No captured code execution. ELF VAs, no masks.']
for owner in record['owners']:
    start,end=int(owner['start'],16),int(owner['end_exclusive'],16)
    ins=list(cs.disasm(img.read(start,end-start),start))
    assert sum(i.size for i in ins)==end-start
    assert all(a.address+a.size==b.address for a,b in zip(ins,ins[1:]))
    boundaries.update(i.address for i in ins)
    lines.append(f'\nOwner {start:#x}..{end:#x}; boundary decode {end-start} bytes / {len(ins)} instructions; SHA-256 '+owner['sha256'])
    for kind in ('fde','cie'):
        va=int(owner[kind],16);size=struct.unpack('<I',img.read(va,4))[0]+4
        lines.append(f'{kind} {va:#x} raw '+img.read(va,size).hex())
    lo,hi=(start,end) if start==0x15bb930 else (0x161434b,0x1614386)
    selected=[i for i in ins if lo<=i.address<hi]
    assert selected[0].address==lo and selected[-1].address+selected[-1].size==hi
    lines.append(f'Retained {lo:#x}..{hi:#x}; {hi-lo} bytes / {len(selected)} instructions')
    lines += [f'{i.address:#x} {i.bytes.hex():30} {i.mnemonic} {i.op_str}'.rstrip() for i in selected]
assert (set(tool.ANCHORS)|set(tool.HANDLERS))<=boundaries
lines.append('\nOriginal relative jump table 0x261458 raw '+img.read(0x261458,16).hex())
Path(__file__).with_name('windows.capstone.txt').write_text('\n'.join(lines)+'\n',encoding='utf8',newline='\n')
print('\n'.join(l for l in lines if l.startswith(('Owner','Retained'))))
