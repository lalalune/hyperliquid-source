"""Verify selected node #115 EMA byte-helper witnesses."""
from hashlib import sha256
from pathlib import Path
import struct,sys
sys.path.insert(0,str(Path("tools").resolve()))
from elf_index import sections
from fde_extents import eh_frame_records
TARGET="a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301";BODY="2aacf0bbbda27794fd2736c4a29c5d6f588010388ad38caf169c6f2cf87fbd09"
data=Path("artifacts/node/115/hl-node").read_bytes()
if sha256(data).hexdigest()!=TARGET: raise ValueError("wrong node artifact")
secs=sections(data);_,frames=eh_frame_records(data,secs)
if [(f["start"],f["end"]) for f in frames if f["start"]==0x4D2C320] != [(0x4D2C320,0x4D2CA28)]: raise ValueError("unexpected FDE")
def read(a,n):
 hits=[s for s in secs if s["type"]!=8 and s["address"]<=a and a+n<=s["address"]+s["size"]]
 if len(hits)!=1: raise ValueError(f"unmapped {a:#x}")
 s=hits[0];o=s["offset"]+a-s["address"];return data[o:o+n]
if sha256(read(0x4D2C320,1800)).hexdigest()!=BODY: raise ValueError("body changed")
w={0x4D2C33C:"4c8b2e",0x4D2C33F:"488b5610",0x4D2C343:"410fb79dba000000",0x4D2C34B:"4889d0",0x4D2C34E:"48c1e004",0x4D2C352:"4a8d3c28",0x4D2C356:"410fb64c0500",0x4D2C360:"498b4c0508",0x4D2C36A:"4a8d3428",0x4D2C375:"48f7d2",0x4D2C37F:"ff15",0x4D2C385:"4c89ee",0x4D2C388:"8d43ff",0x4D2C38B:"66418985ba000000",0x4D2C393:"498b4c2408",0x4D2C398:"6683f804",0x4D2C3A2:"488b86b0000000",0x4D2C3A9:"4885c0",0x4D2C3C5:"4989f6",0x4D2C3D0:"48ffca"}
for a,e in w.items():
 raw=bytes.fromhex(e)
 if read(a,len(raw))!=raw: raise ValueError(f"witness mismatch {a:#x}")
raw=read(0x4D2C39C,6)
if raw[:2]!=bytes.fromhex("0f87"): raise ValueError("missing capacity edge")
if 0x4D2C39C+6+struct.unpack("<i",raw[2:])[0]!=0x4D2C555: raise ValueError("wrong capacity edge")
for a,e in w.items():
 altered=bytearray(bytes.fromhex(e));altered[0]^=1
 if altered==read(a,len(altered)): raise RuntimeError(f"mutation accepted {a:#x}")
print(f"Verified node #115, 1800-byte FDE body, {len(w)} instruction witnesses, 1 edge and {len(w)} mutation controls.")
