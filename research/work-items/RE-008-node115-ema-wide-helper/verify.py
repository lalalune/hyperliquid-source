"""Verify selected node #115 EMA wide-helper witnesses."""
from hashlib import sha256
from pathlib import Path
import struct,sys
sys.path.insert(0,str(Path("tools").resolve()))
from elf_index import sections
from fde_extents import eh_frame_records
TARGET="a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"; BODY="efa3f27223b0eb7517037703eea936089ebef03bf07650dc8335b02a33b34c1b"
data=Path("artifacts/node/115/hl-node").read_bytes()
if sha256(data).hexdigest()!=TARGET: raise ValueError("wrong node artifact")
secs=sections(data);_,frames=eh_frame_records(data,secs)
if [(f["start"],f["end"]) for f in frames if f["start"]==0x4D26FC0] != [(0x4D26FC0,0x4D27AF6)]: raise ValueError("unexpected FDE")
def read(a,n):
 hits=[s for s in secs if s["type"]!=8 and s["address"]<=a and a+n<=s["address"]+s["size"]]
 if len(hits)!=1: raise ValueError(f"unmapped {a:#x}")
 s=hits[0];o=s["offset"]+a-s["address"];return data[o:o+n]
if sha256(read(0x4D26FC0,2870)).hexdigest()!=BODY: raise ValueError("body changed")
w={0x4D26FDC:"488b1e",0x4D26FE3:"0fb7ab6a010000",0x4D26FEA:"4a8d7ceb08",0x4D26FEF:"4a8b44eb08",0x4D27001:"4d89ec",0x4D27004:"49f7d4",0x4D27011:"ff15",0x4D27017:"4c896c2430",0x4D27027:"488d7cc360",0x4D27031:"48898c2498000000",0x4D27058:"8d7dff",0x4D2705B:"6689bb6a010000",0x4D27062:"498b4608",0x4D27073:"6683ff04",0x4D27082:"4c8b33",0x4D27095:"0fb7b368010000",0x4D270B1:"498b8cf668010000",0x4D270F1:"440fb7816a010000",0x4D270FC:"83fa0c"}
for a,e in w.items():
 raw=bytes.fromhex(e)
 if read(a,len(raw))!=raw: raise ValueError(f"witness mismatch {a:#x}")
def edge(site,prefix,target):
 raw=read(site,len(prefix)+4)
 if raw[:len(prefix)]!=prefix: raise ValueError(f"edge opcode {site:#x}")
 actual=site+len(raw)+struct.unpack("<i",raw[-4:])[0]
 if actual!=target: raise ValueError(f"edge target {site:#x}: {actual:#x}")
edge(0x4D2707C,bytes.fromhex("0f87"),0x4D27571);edge(0x4D27088,bytes.fromhex("0f84"),0x4D27571);edge(0x4D270A4,bytes.fromhex("0f84"),0x4D27481);edge(0x4D270FF,bytes.fromhex("0f83"),0x4D27528)
for a,e in w.items():
 altered=bytearray(bytes.fromhex(e));altered[0]^=1
 if altered==read(a,len(altered)): raise RuntimeError(f"mutation accepted {a:#x}")
print(f"Verified node #115, 2870-byte FDE body, {len(w)} instruction witnesses, 4 edges and {len(w)} mutation controls.")
