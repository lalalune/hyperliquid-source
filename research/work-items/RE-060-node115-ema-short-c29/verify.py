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
if [(f['start'],f['end']) for f in fs if f['start']==0x4d3a440] != [(0x4d3a440,0x4d3ab20)]: raise ValueError('unexpected FDE')
def read(a,n):
 h=[s for s in secs if s['type']!=8 and s['address']<=a<=s['address']+s['size']-n]
 if len(h)!=1: raise ValueError('unmapped')
 s=h[0];o=s['offset']+a-s['address'];return d[o:o+n]
w={0x4d3a440:'55415741564155415453',0x4d3a44e:'4889c8',0x4d3a454:'4c8b08',0x4d3a457:'4d85c9',0x4d3a460:'7509',0x4d3a473:'746e',0x4d3a4b3:'4439d6',0x4d3a4bd:'410f94c6',0x4d3a4c4:'0f85ae000000',0x4d3a51e:'4584db',0x4d3a521:'753c',0x4d3a52d:'4a63348b',0x4d3a534:'ffe6'}
for a,e in w.items():
 b=bytes.fromhex(e)
 if read(a,len(b))!=b: raise ValueError(f'witness mismatch {a:#x}')
for a,e in w.items():
 b=bytearray(bytes.fromhex(e));b[0]^=1
 if read(a,len(b))==bytes(b): raise RuntimeError('mutation accepted')
print(f'Verified node #115, 1760-byte FDE body, {len(w)} instruction witnesses and {len(w)} mutation controls.')
