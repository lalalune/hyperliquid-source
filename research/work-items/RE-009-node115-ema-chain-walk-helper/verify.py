from hashlib import sha256
from pathlib import Path
import struct,sys
sys.path.insert(0,str(Path('tools').resolve()))
from elf_index import sections
from fde_extents import eh_frame_records
TARGET='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
d=Path('artifacts/node/115/hl-node').read_bytes()
if sha256(d).hexdigest()!=TARGET: raise ValueError('wrong node artifact')
secs=sections(d);_,frames=eh_frame_records(d,secs)
if [(f['start'],f['end']) for f in frames if f['start']==0x4d31430] != [(0x4d31430,0x4d317d5)]: raise ValueError('unexpected FDE')
def read(a,n):
 h=[s for s in secs if s['type']!=8 and s['address']<=a<=s['address']+s['size']-n]
 if len(h)!=1: raise ValueError('unmapped')
 s=h[0]; return d[s['offset']+a-s['address']:s['offset']+a-s['address']+n]
body=read(0x4d31430,933)
w={0x4d31430:'534881ec10010000',0x4d3143b:'488b06',0x4d3143e:'488b7e08',0x4d31442:'488b4e10',0x4d31446:'4885ff',0x4d3144f:'488b8cc830040000',0x4d31480:'440fb7892a040000',0x4d31488:'4a8b8cc930040000',0x4d31490:'49ffc0',0x4d3155f:'e8cc17ffff',0x4d315c5:'0fb7902a040000',0x4d315f6:'4c6bc158',0x4d315ff:'48897cc808'}
for a,e in w.items():
 b=bytes.fromhex(e)
 if read(a,len(b))!=b: raise ValueError(f'witness mismatch {a:#x}')
raw=read(0x4d31449,6)
if 0x4d31449+6+struct.unpack('<i',raw[2:])[0]!=0x4d316f5: raise ValueError('wrong root edge')
for a,e in w.items():
 b=bytearray(bytes.fromhex(e)); b[0]^=1
 if read(a,len(b))==bytes(b): raise RuntimeError('mutation accepted')
print(f'Verified node #115, 933-byte FDE body, {len(w)} instruction witnesses, 1 edge and {len(w)} mutation controls.')
