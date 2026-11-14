from hashlib import sha256
from pathlib import Path
import struct,sys
sys.path.insert(0,str(Path('tools').resolve()))
from elf_index import sections
from fde_extents import eh_frame_records
TARGET='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301';d=Path('artifacts/node/115/hl-node').read_bytes()
if sha256(d).hexdigest()!=TARGET: raise ValueError('wrong artifact')
secs=sections(d);_,fs=eh_frame_records(d,secs)
if [(f['start'],f['end']) for f in fs if f['start']==0x4d31ef0] != [(0x4d31ef0,0x4d3218d)]: raise ValueError('unexpected FDE')
def read(a,n):
 h=[s for s in secs if s['type']!=8 and s['address']<=a<=s['address']+s['size']-n]
 if len(h)!=1: raise ValueError('unmapped')
 s=h[0];o=s['offset']+a-s['address'];return d[o:o+n]
w={0x4d31ef0:'534881ec90000000',0x4d31efb:'488b06',0x4d31efe:'488b7e08',0x4d31f02:'488b4e10',0x4d31f06:'4885ff',0x4d31f0f:'488b8cc870010000',0x4d31f40:'440fb7896a010000',0x4d31f48:'4a8b8cc970010000',0x4d31f50:'49ffc0',0x4d31f70:'0fb7b16a010000',0x4d31f77:'488b8cf170010000'}
for a,e in w.items():
 b=bytes.fromhex(e)
 if read(a,len(b))!=b: raise ValueError(f'witness mismatch {a:#x}')
raw=read(0x4d31f09,6)
if 0x4d31f09+6+struct.unpack('<i',raw[2:])[0]!=0x4d320e2: raise ValueError('wrong root edge')
for a,e in w.items():
 b=bytearray(bytes.fromhex(e));b[0]^=1
 if read(a,len(b))==bytes(b): raise RuntimeError('mutation accepted')
print(f'Verified node #115, 669-byte FDE body, {len(w)} instruction witnesses, 1 edge and {len(w)} mutation controls.')
