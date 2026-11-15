"""Verify selected node #115 EMA short-helper witnesses."""
from hashlib import sha256
from pathlib import Path
import sys
sys.path.insert(0,str(Path("tools").resolve()))
from elf_index import sections
from fde_extents import eh_frame_records
TARGET="a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301";BODY="a83ab47cb019d9fa8be750a79624326f43c71ad19b909a503f76eb31960db52d"
data=Path("artifacts/node/115/hl-node").read_bytes()
if sha256(data).hexdigest()!=TARGET: raise ValueError("wrong node artifact")
secs=sections(data);_,frames=eh_frame_records(data,secs)
if [(f["start"],f["end"]) for f in frames if f["start"]==0x4D29E00] != [(0x4D29E00,0x4D2A10E)]: raise ValueError("unexpected FDE")
def read(a,n):
 hits=[s for s in secs if s["type"]!=8 and s["address"]<=a and a+n<=s["address"]+s["size"]]
 if len(hits)!=1: raise ValueError(f"unmapped {a:#x}")
 s=hits[0];o=s["offset"]+a-s["address"];return data[o:o+n]
if sha256(read(0x4D29E00,782)).hexdigest()!=BODY: raise ValueError("body changed")
w={0x4D29E1E:"4c8b2e",0x4D29E21:"488b5e10",0x4D29E25:"410fb7adee010000",0x4D29E2D:"488d049b",0x4D29E31:"498dbc8510010000",0x4D29E39:"418b8c8520010000",0x4D29E48:"410f10848510010000",0x4D29E59:"488d348524010000",0x4D29E64:"4989de",0x4D29E67:"49f7d6",0x4D29E79:"4c8b3de8567b01",0x4D29E80:"41ffd7",0x4D29E88:"488d045b",0x4D29E97:"410f1044c508",0x4D29EA5:"498b4cc518",0x4D29EC5:"41ffd7",0x4D29EC8:"8d45ff",0x4D29ECB:"66418985ee010000",0x4D29ED3:"4d8b642408",0x4D29ED8:"6683f804"}
for a,e in w.items():
 raw=bytes.fromhex(e)
 if read(a,len(raw))!=raw: raise ValueError(f"witness mismatch {a:#x}")
for a,e in w.items():
 altered=bytearray(bytes.fromhex(e));altered[0]^=1
 if altered==read(a,len(altered)): raise RuntimeError(f"mutation accepted {a:#x}")
print(f"Verified node #115, 782-byte FDE body, {len(w)} instruction witnesses and {len(w)} mutation controls.")
