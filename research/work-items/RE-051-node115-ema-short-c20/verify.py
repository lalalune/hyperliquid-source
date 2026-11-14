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
if [(f['start'],f['end']) for f in fs if f['start']==0x4d389a0] != [(0x4d389a0,0x4d38af2)]: raise ValueError('unexpected FDE')
def read(a,n):
 h=[s for s in secs if s['type']!=8 and s['address']<=a<=s['address']+s['size']-n]
 if len(h)!=1: raise ValueError('unmapped')
 s=h[0];o=s['offset']+a-s['address'];return d[o:o+n]
w={0x4d389a0:'55415653',0x4d389aa:'440fb64101',0x4d389af:'40f6c701',0x4d389b3:'0f84a7000000',0x4d389bd:'440fb79672020000',0x4d389c8:'41c1e304',0x4d389ed:'4939db',0x4d38a60:'440fb78e72020000',0x4d38a6b:'41c1e204',0x4d38a8c:'4d39da',0x4d38ad5:'48897008',0x4d38ad9:'48895010',0x4d38add:'48894818',0x4d38ae1:'488938'}
for a,e in w.items():
 b=bytes.fromhex(e)
 if read(a,len(b))!=b: raise ValueError(f'witness mismatch {a:#x}')
if 0x4d389b9+struct.unpack('<i',read(0x4d389b5,4))[0]!=0x4d38a60: raise ValueError('wrong tag edge')
if 0x4d38a99+struct.unpack('<b',read(0x4d38a98,1))[0]!=0x4d38a80: raise ValueError('wrong secondary loop edge')
for a,e in w.items():
 b=bytearray(bytes.fromhex(e));b[0]^=1
 if read(a,len(b))==bytes(b): raise RuntimeError('mutation accepted')
print(f'Verified node #115, 338-byte FDE body, {len(w)} instruction witnesses, 2 edges and {len(w)} mutation controls.')
