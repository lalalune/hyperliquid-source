from hashlib import sha256
from pathlib import Path
import struct,sys
sys.path.insert(0,str(Path('tools').resolve()))
from elf_index import sections
from fde_extents import eh_frame_records
TARGET='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
d=Path('artifacts/node/115/hl-node').read_bytes()
if sha256(d).hexdigest()!=TARGET: raise ValueError('wrong artifact')
secs=sections(d);_,fs=eh_frame_records(d,secs)
if [(f['start'],f['end']) for f in fs if f['start']==0x4d388b0] != [(0x4d388b0,0x4d38993)]: raise ValueError('unexpected FDE')
def read(a,n):
 h=[s for s in secs if s['type']!=8 and s['address']<=a<=s['address']+s['size']-n]
 if len(h)!=1: raise ValueError('unmapped')
 s=h[0];o=s['offset']+a-s['address'];return d[o:o+n]
w={0x4d388b0:'554157415641554154534883ec18',0x4d388be:'4989cc',0x4d388c1:'48891424',0x4d388c5:'4989f6',0x4d388c8:'48897c2408',0x4d388d4:'450fb7be6a010000',0x4d388e1:'41c1e705',0x4d388f0:'4939df',0x4d38914:'4883c320',0x4d38918:'3c01'}
for a,e in w.items():
 b=bytes.fromhex(e)
 if read(a,len(b))!=b: raise ValueError(f'witness mismatch {a:#x}')
raw=read(0x4d3891b,1)
if 0x4d3891c+struct.unpack('<b',raw)[0]!=0x4d388f0: raise ValueError('wrong loop edge')
for a,e in w.items():
 b=bytearray(bytes.fromhex(e));b[0]^=1
 if read(a,len(b))==bytes(b): raise RuntimeError('mutation accepted')
print(f'Verified node #115, 227-byte FDE body, {len(w)} instruction witnesses, 1 edge and {len(w)} mutation controls.')
