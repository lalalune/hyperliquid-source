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
if [(f['start'],f['end']) for f in fs if f['start']==0x4d3ab20] != [(0x4d3ab20,0x4d3abea)]: raise ValueError('unexpected FDE')
def read(a,n):
 h=[s for s in secs if s['type']!=8 and s['address']<=a<=s['address']+s['size']-n]
 if len(h)!=1: raise ValueError('unmapped')
 s=h[0];o=s['offset']+a-s['address'];return d[o:o+n]
w={0x4d3ab20:'4889f8',0x4d3ab23:'488b0e',0x4d3ab2e:'4885d2',0x4d3ab37:'488d0cf1',0x4d3ab42:'4889d7',0x4d3ab49:'0f8490000000',0x4d3ab60:'488b31',0x4d3ab6a:'49ffc0',0x4d3ab70:'75ee',0x4d3ab80:'488b09',0x4d3abbf:'75bf',0x4d3abc1:'488930'}
for a,e in w.items():
 b=bytes.fromhex(e)
 if read(a,len(b))!=b: raise ValueError(f'witness mismatch {a:#x}')
for a,e in w.items():
 b=bytearray(bytes.fromhex(e));b[0]^=1
 if read(a,len(b))==bytes(b): raise RuntimeError('mutation accepted')
print(f'Verified node #115, 202-byte FDE body, {len(w)} instruction witnesses and {len(w)} mutation controls.')
