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
if [(f['start'],f['end']) for f in fs if f['start']==0x4d391b0] != [(0x4d391b0,0x4d39388)]: raise ValueError('unexpected FDE')
def read(a,n):
 h=[s for s in secs if s['type']!=8 and s['address']<=a<=s['address']+s['size']-n]
 if len(h)!=1: raise ValueError('unmapped')
 s=h[0];o=s['offset']+a-s['address'];return d[o:o+n]
w={0x4d391b0:'554157415653',0x4d391b6:'4889f8',0x4d391be:'31ff',0x4d391c0:'440fb786ca020000',0x4d391cb:'41c1e103',0x4d391e0:'4d85c9',0x4d391fb:'80fb01',0x4d3921a:'488bb6d0020000',0x4d39221:'eb9d',0x4d39290:'4d8b19',0x4d3929e:'41c1e603',0x4d392b0:'4d85f6',0x4d392d5:'74d9',0x4d39360:'4885d2'}
for a,e in w.items():
 b=bytes.fromhex(e)
 if read(a,len(b))!=b: raise ValueError(f'witness mismatch {a:#x}')
if 0x4d391e5+struct.unpack('<b',read(0x4d391e4,1))[0]!=0x4d3920f: raise ValueError('wrong primary exit edge')
if 0x4d39200+struct.unpack('<b',read(0x4d391ff,1))[0]!=0x4d391e0: raise ValueError('wrong primary loop edge')
if 0x4d392d7+struct.unpack('<b',read(0x4d392d6,1))[0]!=0x4d392b0: raise ValueError('wrong secondary loop edge')
for a,e in w.items():
 b=bytearray(bytes.fromhex(e));b[0]^=1
 if read(a,len(b))==bytes(b): raise RuntimeError('mutation accepted')
print(f'Verified node #115, 472-byte FDE body, {len(w)} instruction witnesses, 3 edges and {len(w)} mutation controls.')
