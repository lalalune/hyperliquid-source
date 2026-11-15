from hashlib import sha256
from pathlib import Path
import sys
sys.path.insert(0,str(Path('tools').resolve()))
from elf_index import sections
from fde_extents import eh_frame_records
TARGET='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
d=Path('artifacts/node/115/hl-node').read_bytes()
if sha256(d).hexdigest()!=TARGET: raise ValueError('wrong artifact')
secs=sections(d);_,fs=eh_frame_records(d,secs)
if [(f['start'],f['end']) for f in fs if f['start']==0x4d3ae00] != [(0x4d3ae00,0x4d3b4cb)]: raise ValueError('unexpected FDE')
def read(a,n):
 h=[s for s in secs if s['type']!=8 and s['address']<=a<=s['address']+s['size']-n]
 if len(h)!=1: raise ValueError('unmapped')
 s=h[0];o=s['offset']+a-s['address'];return d[o:o+n]
w={0x4d3ae00:'5541574156415541545350',0x4d3ae0b:'4c8b3f',0x4d3ae15:'b801000000',0x4d3ae1a:'480f42c8',0x4d3ae2c:'4839d1',0x4d3ae35:'7519',0x4d3ae45:'ffe1',0x4d3ae47:'0fb64708',0x4d3ae4e:'eb02',0x4d3aea4:'48bb0000000000000080',0x4d3aec0:'4839d9',0x4d3aed2:'0f84ed000000'}
for a,e in w.items():
 b=bytes.fromhex(e)
 if read(a,len(b))!=b: raise ValueError(f'witness mismatch {a:#x}')
for a,e in w.items():
 b=bytearray(bytes.fromhex(e));b[0]^=1
 if read(a,len(b))==bytes(b): raise RuntimeError('mutation accepted')
print(f'Verified node #115, 1739-byte FDE body, {len(w)} instruction witnesses and {len(w)} mutation controls.')
