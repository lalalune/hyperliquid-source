"""Verify selected node #115 EMA branch-helper witnesses."""
from hashlib import sha256
from pathlib import Path
import struct, sys
sys.path.insert(0, str(Path("tools").resolve()))
from elf_index import sections
from fde_extents import eh_frame_records
TARGET="a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
BODY="b6c4b10737cc18df141c18e1911a768ebe99727590850abedcf033ecbaa1f0de"
data=Path("artifacts/node/115/hl-node").read_bytes()
if sha256(data).hexdigest()!=TARGET: raise ValueError("wrong node artifact")
secs=sections(data); _,frames=eh_frame_records(data,secs)
if [(f["start"],f["end"]) for f in frames if f["start"]==0x4D26BD0] != [(0x4D26BD0,0x4D26FBD)]: raise ValueError("unexpected FDE")
def read(a,n):
 hits=[s for s in secs if s["type"]!=8 and s["address"]<=a and a+n<=s["address"]+s["size"]]
 if len(hits)!=1: raise ValueError(f"unmapped {a:#x}")
 s=hits[0]; o=s["offset"]+a-s["address"]; return data[o:o+n]
if sha256(read(0x4D26BD0,1005)).hexdigest()!=BODY: raise ValueError("body changed")
w={
0x4D26BEE:"4c8b2e",0x4D26BF5:"450fb7bdae040000",0x4D26BFD:"488d44ad00",0x4D26C02:"498dbc85d0030000",0x4D26C0A:"418b8c85e0030000",0x4D26C2F:"4989ee",0x4D26C32:"49f7d6",0x4D26C4B:"ffd3",0x4D26CB0:"418d47ff",0x4D26CB4:"66418985ae040000",0x4D26CBC:"4d8b642408",0x4D26D1F:"6683f804",0x4D26D29:"498b4500",0x4D26D3B:"410fb795ac040000",0x4D26D58:"48898424b0000000",0x4D26D68:"48899424c0000000",0x4D26D90:"0fb786ae040000",0x4D26D9A:"4183ff0c",0x4D26E3D:"e81ea3f7ff"}
for a,e in w.items():
 raw=bytes.fromhex(e)
 if read(a,len(raw))!=raw: raise ValueError(f"witness mismatch {a:#x}")
def edge(site,prefix,target):
 raw=read(site,len(prefix)+4)
 if raw[:len(prefix)]!=prefix: raise ValueError(f"edge opcode {site:#x}")
 actual=site+len(raw)+struct.unpack("<i",raw[-4:])[0]
 if actual!=target: raise ValueError(f"edge target {site:#x}: {actual:#x}")
edge(0x4D26D23,bytes.fromhex("0f87"),0x4D26DB3)
edge(0x4D26D30,bytes.fromhex("0f84"),0x4D26DBD)
edge(0x4D26D9E,bytes.fromhex("0f83"),0x4D26E5C)
for a,e in w.items():
 altered=bytearray(bytes.fromhex(e)); altered[0]^=1
 if altered==read(a,len(altered)): raise RuntimeError(f"mutation accepted {a:#x}")
print(f"Verified node #115, 1005-byte FDE body, {len(w)} instruction witnesses, 4 edges and {len(w)} mutation controls.")
