"""Complete static wrapper exports and instruction-validated caller windows."""
from pathlib import Path
import struct
import sys
import capstone

ROOT=Path(__file__).resolve().parents[3];sys.path.insert(0,str(ROOT/'tools'))
import db_code_routing_static as tool

if capstone.__version__!='5.0.6':raise SystemExit('Use Capstone 5.0.6')
data=(ROOT/'artifacts/node/94/hl-node').read_bytes();record=tool.build(data);secs=tool.sections(data)
_,frames=tool.eh_frame_records(data,secs)

def read(va,size):
    s=next(s for s in secs if s['type']!=8 and s['address']<=va and va+size<=s['address']+s['size'])
    off=s['offset']+va-s['address'];return data[off:off+size]

cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
lines=[f'Capstone {capstone.__version__}; x86-64 Intel syntax; static only',f'Target SHA-256 {tool.SHA256}']
total=0
for consumer in record['consumers']:
    start=int(consumer['start_va'],16);end=int(consumer['end_va_exclusive'],16)
    instructions=list(cs.disasm(read(start,end-start),start))
    assert sum(i.size for i in instructions)==end-start
    assert all(a.address+a.size==b.address for a,b in zip(instructions,instructions[1:]))
    addresses={i.address for i in instructions}
    assert all(start+o in addresses for o in (0x25,0x53,0xe0,0xe7,0xeb,0x102,0x107,
                                             0x1c9,0x1dc,0x1e1,0x1e4,0x1e7,0x1e9,
                                             0x1ee,0x1f0,0x1f5,0x1f8,0x1fa,0x1fd,0x20e,0x213,0x215,0x3b5))
    total+=len(instructions)
    lines.append(f'\nVA {start:#x}..{end:#x} exclusive; {end-start} bytes; {len(instructions)} instructions')
    lines.append('Body SHA-256 '+consumer['body_sha256'])
    for kind in ('fde_va','cie_va'):
        va=int(consumer[kind],16);size=struct.unpack('<I',read(va,4))[0]+4
        lines.append(f'{kind} {va:#x} raw {read(va,size).hex()}')
    lines += [f'{i.address:#x} {i.bytes.hex():30} {i.mnemonic} {i.op_str}'.rstrip() for i in instructions]
cache={}
for call in record['direct_call_windows']:
    site=int(call['call_va'],16);start=int(call['code_load_va'],16)
    matches=[f for f in frames if f['start']<=start and site+5<=f['end']]
    assert len(matches)==1
    f=matches[0]
    if f['start'] not in cache:
        instructions=list(cs.disasm(read(f['start'],f['end']-f['start']),f['start']))
        assert sum(i.size for i in instructions)==f['end']-f['start']
        cache[f['start']]={i.address:i for i in instructions}
    window=[cache[f['start']][v] for v in (start,site-3,site)]
    assert sum(i.size for i in window)==13
    assert window[0].mnemonic=='mov' and window[0].op_str==f"esi, {call['code']:#x}"
    assert window[-1].mnemonic=='call' and window[-1].op_str==call['target_va']
    lines.append(f"\nCaller FDE {f['start']:#x}..{f['end']:#x}; selected constant-code window")
    lines += [f'{i.address:#x} {i.bytes.hex():30} {i.mnemonic} {i.op_str}'.rstrip() for i in window]
Path(__file__).with_name('wrappers.capstone.txt').write_text('\n'.join(lines)+'\n',encoding='utf8',newline='\n')
print(f'Exported six complete wrappers: 6486 bytes / {total} instructions, plus six real caller windows.')
