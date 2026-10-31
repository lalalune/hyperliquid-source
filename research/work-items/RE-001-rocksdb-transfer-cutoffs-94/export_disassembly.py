"""Decode complete owner frames, retain bounded predicate/diagnostic excerpts."""
from pathlib import Path
import struct
import sys
import capstone

ROOT=Path(__file__).resolve().parents[3];sys.path.insert(0,str(ROOT/'tools'))
import rocksdb_cutoffs_static as tool

if capstone.__version__!='5.0.6':raise SystemExit('Use Capstone 5.0.6')
data=(ROOT/'artifacts/node/94/hl-node').read_bytes();record=tool.build(data);secs=tool.sections(data)

def read(va,size):
    s=next(s for s in secs if s['type']!=8 and s['address']<=va and va+size<=s['address']+s['size'])
    off=s['offset']+va-s['address'];return data[off:off+size]

cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
lines=[f'Capstone {capstone.__version__}; x86-64 Intel syntax; static only',f'Target SHA-256 {tool.SHA256}']
owner_bytes=owner_insns=excerpt_bytes=excerpt_insns=0
for case,result in zip(tool.CASES,record['comparisons']):
    start,end=case['owner_start'],case['owner_end']
    ins=list(cs.disasm(read(start,end-start),start))
    assert sum(i.size for i in ins)==end-start
    assert all(a.address+a.size==b.address for a,b in zip(ins,ins[1:]))
    addresses={i.address for i in ins};owner_bytes+=end-start;owner_insns+=len(ins)
    assert all(v in addresses for v in [case['load'],case['cmp']-4,case['cmp'],case['branch'],
               case['large_arm'],case['template_lea'],case['location_lea'],case['call']])
    lines.append(f'\nOwner FDE {start:#x}..{end:#x}; {end-start} bytes / {len(ins)} instructions decoded for boundaries')
    lines.append('Owner SHA-256 '+case['owner_sha256'])
    for kind in ('fde_va','cie_va'):
        va=int(result['owner'][kind],16);size=struct.unpack('<I',read(va,4))[0]+4
        lines.append(f'{kind} {va:#x} raw {read(va,size).hex()}')
    for lo,hi in result['excerpt_ranges']:
        lo,hi=int(lo,16),int(hi,16)
        selected=[i for i in ins if lo<=i.address<hi]
        assert selected[0].address==lo and selected[-1].address+selected[-1].size==hi
        assert sum(i.size for i in selected)==hi-lo
        excerpt_bytes+=hi-lo;excerpt_insns+=len(selected)
        lines.append(f'Excerpt {lo:#x}..{hi:#x}; {hi-lo} bytes / {len(selected)} instructions')
        lines += [f'{i.address:#x} {i.bytes.hex():30} {i.mnemonic} {i.op_str}'.rstrip() for i in selected]
summary=(f'Boundary decoding only: {owner_bytes} owner bytes / {owner_insns} owner instructions. '
         f'Retained selected scope: {excerpt_bytes} bytes / {excerpt_insns} instructions. No target execution.')
lines.append('\n'+summary)
Path(__file__).with_name('excerpts.capstone.txt').write_text('\n'.join(lines)+'\n',encoding='utf8',newline='\n')
print(summary)
