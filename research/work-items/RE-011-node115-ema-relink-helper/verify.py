from hashlib import sha256
from pathlib import Path
import struct,sys
sys.path.insert(0,str(Path('tools').resolve()))
from elf_index import sections
from fde_extents import eh_frame_records
TARGET='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301';d=Path('artifacts/node/115/hl-node').read_bytes()
if sha256(d).hexdigest()!=TARGET: raise ValueError('wrong artifact')
secs=sections(d);_,fs=eh_frame_records(d,secs)
if [(f['start'],f['end']) for f in fs if f['start']==0x4d31a70] != [(0x4d31a70,0x4d31c55)]: raise ValueError('unexpected FDE')
def read(a,n):
 h=[s for s in secs if s['type']!=8 and s['address']<=a<=s['address']+s['size']-n]
 if len(h)!=1: raise ValueError('unmapped')
 s=h[0];o=s['offset']+a-s['address'];return d[o:o+n]
w={0x4d31a70:'534883ec50',0x4d31a78:'488b06',0x4d31a7b:'488b7e08',0x4d31a7f:'488b4e10',0x4d31a83:'4885ff',0x4d31a8c:'488b4cc868',0x4d31ab0:'440fb74962',0x4d31ab5:'4a8b4cc968',0x4d31ad0:'0fb77162',0x4d31ad4:'488b4cf168',0x4d31b42:'e8b9c8feff',0x4d31b80:'488b4cf008',0x4d31b85:'48897cf008',0x4d31b8a:'4885d2'}
for a,e in w.items():
 b=bytes.fromhex(e)
 if read(a,len(b))!=b: raise ValueError(f'witness mismatch {a:#x}')
raw=read(0x4d31a86,6)
if 0x4d31a86+6+struct.unpack('<i',raw[2:])[0]!=0x4d31bcf: raise ValueError('wrong root edge')
for a,e in w.items():
 b=bytearray(bytes.fromhex(e));b[0]^=1
 if read(a,len(b))==bytes(b): raise RuntimeError('mutation accepted')
print(f'Verified node #115, 485-byte FDE body, {len(w)} instruction witnesses, 1 edge and {len(w)} mutation controls.')
