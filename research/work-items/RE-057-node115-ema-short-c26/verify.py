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
if [(f['start'],f['end']) for f in fs if f['start']==0x4d39390] != [(0x4d39390,0x4d39617)]: raise ValueError('unexpected FDE')
def read(a,n):
 h=[s for s in secs if s['type']!=8 and s['address']<=a<=s['address']+s['size']-n]
 if len(h)!=1: raise ValueError('unmapped')
 s=h[0];o=s['offset']+a-s['address'];return d[o:o+n]
w={0x4d39390:'55415741564155415453',0x4d3939e:'48894c2418',0x4d393b2:'0fb79e4e030000',0x4d393c0:'4c8d3480',0x4d393e0:'4b8d042e',0x4d39400:'4898',0x4d39416:'74c8',0x4d3944b:'488bb650030000',0x4d39452:'e958ffffff',0x4d39467:'4885d2',0x4d3946a:'7425'}
for a,e in w.items():
 b=bytes.fromhex(e)
 if read(a,len(b))!=b: raise ValueError(f'witness mismatch {a:#x}')
if 0x4d39418+struct.unpack('<b',read(0x4d39417,1))[0]!=0x4d393e0: raise ValueError('wrong record loop edge')
if 0x4d39457+struct.unpack('<i',read(0x4d39453,4))[0]!=0x4d393af: raise ValueError('wrong child edge')
for a,e in w.items():
 b=bytearray(bytes.fromhex(e));b[0]^=1
 if read(a,len(b))==bytes(b): raise RuntimeError('mutation accepted')
print(f'Verified node #115, 647-byte FDE body, {len(w)} instruction witnesses, 2 edges and {len(w)} mutation controls.')
