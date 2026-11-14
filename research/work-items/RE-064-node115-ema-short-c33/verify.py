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
if [(f['start'],f['end']) for f in fs if f['start']==0x4d3ad70] != [(0x4d3ad70,0x4d3adff)]: raise ValueError('unexpected FDE')
def read(a,n):
 h=[s for s in secs if s['type']!=8 and s['address']<=a<=s['address']+s['size']-n]
 if len(h)!=1: raise ValueError('unmapped')
 s=h[0];o=s['offset']+a-s['address'];return d[o:o+n]
w={0x4d3ad70:'0fb65720',0x4d3ad79:'4c39c2',0x4d3ad85:'7532',0x4d3ad8f:'4839d1',0x4d3ad9a:'7562',0x4d3ad9c:'48b90000000000000080',0x4d3adae:'710c',0x4d3adb0:'4839ca',0x4d3adb8:'c3',0x4d3adc4:'488b4708',0x4d3ade4:'ff15664d7a01',0x4d3adf2:'4885db',0x4d3adfe:'c3'}
for a,e in w.items():
 b=bytes.fromhex(e)
 if read(a,len(b))!=b: raise ValueError(f'witness mismatch {a:#x}')
for a,e in w.items():
 b=bytearray(bytes.fromhex(e));b[0]^=1
 if read(a,len(b))==bytes(b): raise RuntimeError('mutation accepted')
print(f'Verified node #115, 143-byte FDE body, {len(w)} instruction witnesses and {len(w)} mutation controls.')
