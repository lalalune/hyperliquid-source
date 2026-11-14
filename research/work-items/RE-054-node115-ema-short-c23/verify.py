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
if [(f['start'],f['end']) for f in fs if f['start']==0x4d38e70] != [(0x4d38e70,0x4d38fce)]: raise ValueError('unexpected FDE')
def read(a,n):
 h=[s for s in secs if s['type']!=8 and s['address']<=a<=s['address']+s['size']-n]
 if len(h)!=1: raise ValueError('unmapped')
 s=h[0];o=s['offset']+a-s['address'];return d[o:o+n]
w={0x4d38e70:'554157415653',0x4d38e79:'4531c9',0x4d38e7c:'488d3d41a1bdfb',0x4d38e83:'4c63148f',0x4d38e8a:'41ffe2',0x4d38e90:'440fb74e62',0x4d38e98:'c1e303',0x4d38eb0:'4885db',0x4d38ef1:'74bd',0x4d38f1d:'41c1e603',0x4d38f71:'74bd',0x4d38fa6:'4a8b74ce68',0x4d38fb5:'41ffe2',0x4d38fb8:'488930',0x4d38fc3:'4c894810'}
for a,e in w.items():
 b=bytes.fromhex(e)
 if read(a,len(b))!=b: raise ValueError(f'witness mismatch {a:#x}')
if 0x4d38ef3+struct.unpack('<b',read(0x4d38ef2,1))[0]!=0x4d38eb0: raise ValueError('wrong primary loop edge')
if 0x4d38f73+struct.unpack('<b',read(0x4d38f72,1))[0]!=0x4d38f30: raise ValueError('wrong alternate loop edge')
for a,e in w.items():
 b=bytearray(bytes.fromhex(e));b[0]^=1
 if read(a,len(b))==bytes(b): raise RuntimeError('mutation accepted')
print(f'Verified node #115, 350-byte FDE body, {len(w)} instruction witnesses, 2 edges and {len(w)} mutation controls.')
