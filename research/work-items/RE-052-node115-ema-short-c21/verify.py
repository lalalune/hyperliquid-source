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
if [(f['start'],f['end']) for f in fs if f['start']==0x4d38b00] != [(0x4d38b00,0x4d38c10)]: raise ValueError('unexpected FDE')
def read(a,n):
 h=[s for s in secs if s['type']!=8 and s['address']<=a<=s['address']+s['size']-n]
 if len(h)!=1: raise ValueError('unmapped')
 s=h[0];o=s['offset']+a-s['address'];return d[o:o+n]
w={0x4d38b00:'554157415641554154534883ec28',0x4d38b0e:'4989cc',0x4d38b11:'4889542408',0x4d38b16:'48897c2418',0x4d38b1b:'488b29',0x4d38b29:'440fb7b62a040000',0x4d38b42:'41c1e605',0x4d38b68:'4d85f6',0x4d38b75:'4c89ee',0x4d38b78:'41ffd7',0x4d38b89:'74c5',0x4d38b8d:'ebca',0x4d38bd5:'e94fffffff',0x4d38beb:'48895008',0x4d38bef:'48897010',0x4d38bf3:'48895818',0x4d38bf7:'488908'}
for a,e in w.items():
 b=bytes.fromhex(e)
 if read(a,len(b))!=b: raise ValueError(f'witness mismatch {a:#x}')
if 0x4d38b68+struct.unpack('<b',read(0x4d38b67,1))[0]!=0x4d38b90: raise ValueError('wrong comparator exit edge')
if 0x4d38b8f+struct.unpack('<b',read(0x4d38b8e,1))[0]!=0x4d38b59: raise ValueError('wrong compare loop edge')
if 0x4d38bda+struct.unpack('<i',read(0x4d38bd6,4))[0]!=0x4d38b29: raise ValueError('wrong child edge')
for a,e in w.items():
 b=bytearray(bytes.fromhex(e));b[0]^=1
 if read(a,len(b))==bytes(b): raise RuntimeError('mutation accepted')
print(f'Verified node #115, 272-byte FDE body, {len(w)} instruction witnesses, 3 edges and {len(w)} mutation controls.')
