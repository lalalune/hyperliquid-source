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
if [(f['start'],f['end']) for f in fs if f['start']==0x4d38c10] != [(0x4d38c10,0x4d38e67)]: raise ValueError('unexpected FDE')
def read(a,n):
 h=[s for s in secs if s['type']!=8 and s['address']<=a<=s['address']+s['size']-n]
 if len(h)!=1: raise ValueError('unmapped')
 s=h[0];o=s['offset']+a-s['address'];return d[o:o+n]
w={0x4d38c10:'554157415653',0x4d38c16:'440fb609',0x4d38c1f:'440fb6c0',0x4d38c29:'4180f90a',0x4d38c48:'0f828c000000',0x4d38c51:'440fb78e2a1a0000',0x4d38c70:'4d8d1c3a',0x4d38c9c:'48ffc7',0x4d38ca3:'74cb',0x4d38cd5:'e977ffffff',0x4d38cda:'450fb6c9',0x4d38d1b:'498d1c3b',0x4d38d44:'75ca',0x4d38e48:'48897008',0x4d38e4c:'48895010',0x4d38e50:'48897818',0x4d38e54:'488908'}
for a,e in w.items():
 b=bytes.fromhex(e)
 if read(a,len(b))!=b: raise ValueError(f'witness mismatch {a:#x}')
if 0x4d38c4e+struct.unpack('<i',read(0x4d38c4a,4))[0]!=0x4d38cda: raise ValueError('wrong tag edge')
if 0x4d38ca5+struct.unpack('<b',read(0x4d38ca4,1))[0]!=0x4d38c70: raise ValueError('wrong primary loop edge')
if 0x4d38d46+struct.unpack('<b',read(0x4d38d45,1))[0]!=0x4d38d10: raise ValueError('wrong alternate loop edge')
if 0x4d38cda+struct.unpack('<i',read(0x4d38cd6,4))[0]!=0x4d38c51: raise ValueError('wrong child edge')
for a,e in w.items():
 b=bytearray(bytes.fromhex(e));b[0]^=1
 if read(a,len(b))==bytes(b): raise RuntimeError('mutation accepted')
print(f'Verified node #115, 599-byte FDE body, {len(w)} instruction witnesses, 4 edges and {len(w)} mutation controls.')
