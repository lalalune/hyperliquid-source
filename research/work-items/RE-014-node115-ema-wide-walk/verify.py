from hashlib import sha256
from pathlib import Path
import struct,sys
sys.path.insert(0,str(Path('tools').resolve()))
from elf_index import sections
from fde_extents import eh_frame_records
TARGET='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301';d=Path('artifacts/node/115/hl-node').read_bytes()
if sha256(d).hexdigest()!=TARGET: raise ValueError('wrong artifact')
secs=sections(d);_,fs=eh_frame_records(d,secs)
if [(f['start'],f['end']) for f in fs if f['start']==0x4d32190] != [(0x4d32190,0x4d3249f)]: raise ValueError('unexpected FDE')
def read(a,n):
 h=[s for s in secs if s['type']!=8 and s['address']<=a<=s['address']+s['size']-n]
 if len(h)!=1: raise ValueError('unmapped')
 s=h[0];o=s['offset']+a-s['address'];return d[o:o+n]
w={0x4d32190:'534881ecc0000000',0x4d3219b:'488b06',0x4d3219e:'488b7e08',0x4d321a2:'488b4e10',0x4d321a6:'4885ff',0x4d321af:'488b8cc848020000',0x4d321e0:'440fb78946020000',0x4d321e8:'4a8b8cc948020000',0x4d321f0:'49ffc0',0x4d32210:'0fb7b146020000',0x4d32217:'488b8cf148020000'}
for a,e in w.items():
 b=bytes.fromhex(e)
 if read(a,len(b))!=b: raise ValueError(f'witness mismatch {a:#x}')
raw=read(0x4d321a9,6)
if 0x4d321a9+6+struct.unpack('<i',raw[2:])[0]!=0x4d323e2: raise ValueError('wrong root edge')
for a,e in w.items():
 b=bytearray(bytes.fromhex(e));b[0]^=1
 if read(a,len(b))==bytes(b): raise RuntimeError('mutation accepted')
print(f'Verified node #115, 783-byte FDE body, {len(w)} instruction witnesses, 1 edge and {len(w)} mutation controls.')
