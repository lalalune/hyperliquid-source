"""Verify selected node #115 EMA c2-helper witnesses."""
from hashlib import sha256
from pathlib import Path
import struct,sys
sys.path.insert(0,str(Path("tools").resolve()))
from elf_index import sections
from fde_extents import eh_frame_records
TARGET="a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301";BODY="ef7609725155b9334aad385e6b995a84f1b7342fa5df9eeb3be6cc704e8d9fbd"
data=Path("artifacts/node/115/hl-node").read_bytes()
if sha256(data).hexdigest()!=TARGET: raise ValueError("wrong node artifact")
secs=sections(data);_,frames=eh_frame_records(data,secs)
if [(f["start"],f["end"]) for f in frames if f["start"]==0x4D29260] != [(0x4D29260,0x4D29DF2)]: raise ValueError("unexpected FDE")
def read(a,n):
 hits=[s for s in secs if s["type"]!=8 and s["address"]<=a and a+n<=s["address"]+s["size"]]
 if len(hits)!=1: raise ValueError(f"unmapped {a:#x}")
 s=hits[0];o=s["offset"]+a-s["address"];return data[o:o+n]
if sha256(read(0x4D29260,2962)).hexdigest()!=BODY: raise ValueError("body changed")
w={0x4D2927E:"488b2e",0x4D29281:"4c8b6e10",0x4D29285:"0fb79dc2010000",0x4D2928C:"4c89e8",0x4D29297:"0f10440500",0x4D292A1:"0f298c24c0000000",0x4D292B1:"488d3428",0x4D292B9:"4d89ec",0x4D292BC:"49f7d4",0x4D292C9:"4c8b3d",0x4D292D0:"41ffd7",0x4D292D3:"4a8d3ced68010000",0x4D292DE:"4a8b84ed68010000",0x4D29304:"448d43ff",0x4D29308:"66448985c2010000",0x4D29310:"498b7608",0x4D29320:"664183f804",0x4D2932B:"4c8ba560010000",0x4D2933A:"0f84b9040000"}
for a,e in w.items():
 raw=bytes.fromhex(e)
 if read(a,len(raw))!=raw: raise ValueError(f"witness mismatch {a:#x}")
def edge(site,prefix,target):
 raw=read(site,len(prefix)+4)
 if raw[:len(prefix)]!=prefix: raise ValueError(f"edge opcode {site:#x}")
 actual=site+len(raw)+struct.unpack("<i",raw[-4:])[0]
 if actual!=target: raise ValueError(f"edge target {site:#x}: {actual:#x}")
edge(0x4D29325,bytes.fromhex("0f87"),0x4D29818);edge(0x4D2933A,bytes.fromhex("0f84"),0x4D297F9);edge(0x4D29351,bytes.fromhex("0f84"),0x4D2972D)
for a,e in w.items():
 altered=bytearray(bytes.fromhex(e));altered[0]^=1
 if altered==read(a,len(altered)): raise RuntimeError(f"mutation accepted {a:#x}")
print(f"Verified node #115, 2962-byte FDE body, {len(w)} instruction witnesses, 3 edges and {len(w)} mutation controls.")
