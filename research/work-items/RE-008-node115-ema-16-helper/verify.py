"""Verify selected node #115 EMA 16-byte-helper witnesses."""
from hashlib import sha256
from pathlib import Path
import struct,sys
sys.path.insert(0,str(Path("tools").resolve()))
from elf_index import sections
from fde_extents import eh_frame_records
TARGET="a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301";BODY="c64b5930b8c497e3a78c5614b3a4b79254ba3b0456d58fba686270d845d3a559"
data=Path("artifacts/node/115/hl-node").read_bytes()
if sha256(data).hexdigest()!=TARGET: raise ValueError("wrong node artifact")
secs=sections(data);_,frames=eh_frame_records(data,secs)
if [(f["start"],f["end"]) for f in frames if f["start"]==0x4D2CA30] != [(0x4D2CA30,0x4D2D699)]: raise ValueError("unexpected FDE")
def read(a,n):
 hits=[s for s in secs if s["type"]!=8 and s["address"]<=a and a+n<=s["address"]+s["size"]]
 if len(hits)!=1: raise ValueError(f"unmapped {a:#x}")
 s=hits[0];o=s["offset"]+a-s["address"];return data[o:o+n]
if sha256(read(0x4D2CA30,3177)).hexdigest()!=BODY: raise ValueError("body changed")
w={0x4D2CA54:"4c8b2e",0x4D2CA57:"488b5e10",0x4D2CA5B:"450fb7b596010000",0x4D2CA63:"488d049b",0x4D2CA67:"498dbc85b8000000",0x4D2CA6F:"418b8c85c8000000",0x4D2CA7E:"410f108485b8000000",0x4D2CA8F:"488d3485cc000000",0x4D2CA9A:"4989dc",0x4D2CA9D:"49f7d4",0x4D2CAAF:"488b2db22a7b01",0x4D2CAB6:"ffd5",0x4D2CAB8:"48895c2430",0x4D2CAC0:"48c1e004",0x4D2CAC4:"4a8d3c28",0x4D2CAC8:"410f10440500",0x4D2CAD6:"4a8d3428",0x4D2CAE5:"ffd5",0x4D2CAE7:"458d46ff",0x4D2CAEB:"6645898596010000",0x4D2CAF3:"4d8b6708",0x4D2CAF7:"488b8424f0000000",0x4D2CB2F:"664183f804"}
for a,e in w.items():
 raw=bytes.fromhex(e)
 if read(a,len(raw))!=raw: raise ValueError(f"witness mismatch {a:#x}")
raw=read(0x4D2CB34,6)
if raw[:2]!=bytes.fromhex("0f87"): raise ValueError("missing capacity edge")
if 0x4D2CB34+6+struct.unpack("<i",raw[2:])[0]!=0x4D2D05F: raise ValueError("wrong capacity edge")
for a,e in w.items():
 altered=bytearray(bytes.fromhex(e));altered[0]^=1
 if altered==read(a,len(altered)): raise RuntimeError(f"mutation accepted {a:#x}")
print(f"Verified node #115, 3177-byte FDE body, {len(w)} instruction witnesses, 1 edge and {len(w)} mutation controls.")
