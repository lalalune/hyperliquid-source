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
if [(f['start'],f['end']) for f in fs if f['start']==0x4d38fd0] != [(0x4d38fd0,0x4d391a8)]: raise ValueError('unexpected FDE')
def read(a,n):
 h=[s for s in secs if s['type']!=8 and s['address']<=a<=s['address']+s['size']-n]
 if len(h)!=1: raise ValueError('unmapped')
 s=h[0];o=s['offset']+a-s['address'];return d[o:o+n]
w={0x4d38fd0:'554157415653',0x4d38fd6:'4889f8',0x4d38fde:'31ff',0x4d38fe0:'440fb7866a010000',0x4d38feb:'41c1e103',0x4d39000:'4d85c9',0x4d3901e:'74e0',0x4d3903a:'488bb670010000',0x4d39041:'eb9d',0x4d390b0:'4d8b19',0x4d390be:'41c1e603',0x4d390d0:'4d85f6',0x4d390f5:'74d9',0x4d39180:'4885d2'}
for a,e in w.items():
 b=bytes.fromhex(e)
 if read(a,len(b))!=b: raise ValueError(f'witness mismatch {a:#x}')
if 0x4d39020+struct.unpack('<b',read(0x4d3901f,1))[0]!=0x4d39000: raise ValueError('wrong primary loop edge')
if 0x4d390f7+struct.unpack('<b',read(0x4d390f6,1))[0]!=0x4d390d0: raise ValueError('wrong secondary loop edge')
for a,e in w.items():
 b=bytearray(bytes.fromhex(e));b[0]^=1
 if read(a,len(b))==bytes(b): raise RuntimeError('mutation accepted')
print(f'Verified node #115, 472-byte FDE body, {len(w)} instruction witnesses, 2 edges and {len(w)} mutation controls.')
