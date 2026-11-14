"""Verify selected node #115 EMA next-helper witnesses."""
from hashlib import sha256
from pathlib import Path
import struct,sys
sys.path.insert(0,str(Path("tools").resolve()))
from elf_index import sections
from fde_extents import eh_frame_records
TARGET="a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301";BODY="99637f617f3163972511a163c2d961ba4329d55d0c395e6ab103eccb976f180c"
data=Path("artifacts/node/115/hl-node").read_bytes()
if sha256(data).hexdigest()!=TARGET: raise ValueError("wrong node artifact")
secs=sections(data);_,frames=eh_frame_records(data,secs)
if [(f["start"],f["end"]) for f in frames if f["start"]==0x4D27B00] != [(0x4D27B00,0x4D28626)]: raise ValueError("unexpected FDE")
def read(a,n):
 hits=[s for s in secs if s["type"]!=8 and s["address"]<=a and a+n<=s["address"]+s["size"]]
 if len(hits)!=1: raise ValueError(f"unmapped {a:#x}")
 s=hits[0];o=s["offset"]+a-s["address"];return data[o:o+n]
if sha256(read(0x4D27B00,2854)).hexdigest()!=BODY: raise ValueError("body changed")
w={0x4D27B1E:"488b1e",0x4D27B25:"440fb7ab9a070000",0x4D27B2D:"4a8d7ce308",0x4D27B32:"4a8b44e308",0x4D27B44:"4d89e7",0x4D27B47:"49f7d7",0x4D27B55:"ff15",0x4D27B60:"4969eca8000000",0x4D27B6B:"4983c460",0x4D27B7F:"ff15",0x4D27BA3:"418d7dff",0x4D27BA7:"6689bb9a070000",0x4D27BAE:"4d8b7608",0x4D27BBF:"6683ff04",0x4D27BD6:"4d8d7e01",0x4D27BDA:"410fb7b42498070000",0x4D27BF8:"488b8cf598070000",0x4D27C3D:"440fb7819a070000",0x4D27C48:"4183fd0c"}
for a,e in w.items():
 raw=bytes.fromhex(e)
 if read(a,len(raw))!=raw: raise ValueError(f"witness mismatch {a:#x}")
def edge(site,prefix,target):
 raw=read(site,len(prefix)+4)
 if raw[:len(prefix)]!=prefix: raise ValueError(f"edge opcode {site:#x}")
 actual=site+len(raw)+struct.unpack("<i",raw[-4:])[0]
 if actual!=target: raise ValueError(f"edge target {site:#x}: {actual:#x}")
edge(0x4D27BC3,bytes.fromhex("0f87"),0x4D27FBE);edge(0x4D27BD0,bytes.fromhex("0f84"),0x4D27FBE);edge(0x4D27BEB,bytes.fromhex("0f84"),0x4D27FC8);edge(0x4D27C4C,bytes.fromhex("0f83"),0x4D28073)
for a,e in w.items():
 altered=bytearray(bytes.fromhex(e));altered[0]^=1
 if altered==read(a,len(altered)): raise RuntimeError(f"mutation accepted {a:#x}")
print(f"Verified node #115, 2854-byte FDE body, {len(w)} instruction witnesses, 4 edges and {len(w)} mutation controls.")
