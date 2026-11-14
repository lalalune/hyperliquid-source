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
if [(f['start'],f['end']) for f in fs if f['start']==0x4d3acc0] != [(0x4d3acc0,0x4d3ad62)]: raise ValueError('unexpected FDE')
def read(a,n):
 h=[s for s in secs if s['type']!=8 and s['address']<=a<=s['address']+s['size']-n]
 if len(h)!=1: raise ValueError('unmapped')
 s=h[0];o=s['offset']+a-s['address'];return d[o:o+n]
w={0x4d3acc0:'4889f8',0x4d3acc3:'488b0e',0x4d3acce:'4885d2',0x4d3acd3:'488d0cf1',0x4d3acdb:'4889d7',0x4d3ace2:'7473',0x4d3acf0:'488b31',0x4d3acf7:'49ffc0',0x4d3acfd:'75f1',0x4d3ad10:'488b09',0x4d3ad37:'75d7',0x4d3ad39:'488930'}
for a,e in w.items():
 b=bytes.fromhex(e)
 if read(a,len(b))!=b: raise ValueError(f'witness mismatch {a:#x}')
for a,e in w.items():
 b=bytearray(bytes.fromhex(e));b[0]^=1
 if read(a,len(b))==bytes(b): raise RuntimeError('mutation accepted')
print(f'Verified node #115, 162-byte FDE body, {len(w)} instruction witnesses and {len(w)} mutation controls.')
