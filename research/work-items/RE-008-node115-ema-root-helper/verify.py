"""Verify selected node #115 EMA root-helper witnesses."""
from hashlib import sha256
from pathlib import Path
import struct,sys
sys.path.insert(0,str(Path("tools").resolve()))
from elf_index import sections
from fde_extents import eh_frame_records
TARGET="a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
BODY="b52853d538bd4371f7c9f8aea4db3487f959fd4c47cd8ad65110b5448d664fb3"
data=Path("artifacts/node/115/hl-node").read_bytes()
if sha256(data).hexdigest()!=TARGET: raise ValueError("wrong node artifact")
secs=sections(data);_,frames=eh_frame_records(data,secs)
if [(f["start"],f["end"]) for f in frames if f["start"]==0x4D24F70] != [(0x4D24F70,0x4D256D8)]: raise ValueError("unexpected FDE")
def read(a,n):
 hits=[s for s in secs if s["type"]!=8 and s["address"]<=a and a+n<=s["address"]+s["size"]]
 if len(hits)!=1: raise ValueError(f"unmapped {a:#x}")
 s=hits[0];o=s["offset"]+a-s["address"];return data[o:o+n]
if sha256(read(0x4D24F70,1896)).hexdigest()!=BODY: raise ValueError("body changed")
w={0x4D24F8E:"488b2e",0x4D24F95:"0fb79d8e000000",0x4D24F9C:"4a8d7cbd60",0x4D24FA1:"428b44bd60",0x4D24FB5:"4d89fd",0x4D24FB8:"49f7d5",0x4D24FC6:"4c8b359ba57b01",0x4D24FCD:"41ffd6",0x4D24FDB:"4a8b44fd08",0x4D25002:"8d43ff",0x4D25005:"6689858e000000",0x4D2500C:"4d8b742408",0x4D2502B:"0fb7968c000000",0x4D25049:"4889842498000000",0x4D25059:"48899424a8000000",0x4D25081:"0fb7868e000000",0x4D2508A:"83fb0c",0x4D25114:"0fb7828e000000"}
for a,e in w.items():
 raw=bytes.fromhex(e)
 if read(a,len(raw))!=raw: raise ValueError(f"witness mismatch {a:#x}")
def edge(site,prefix,target):
 raw=read(site,len(prefix)+4)
 if raw[:len(prefix)]!=prefix: raise ValueError(f"edge opcode {site:#x}")
 actual=site+len(raw)+struct.unpack("<i",raw[-4:])[0]
 if actual!=target: raise ValueError(f"edge target {site:#x}: {actual:#x}")
edge(0x4D25015,bytes.fromhex("0f87"),0x4D250AA)
edge(0x4D25021,bytes.fromhex("0f84"),0x4D250B9)
edge(0x4D25035,bytes.fromhex("0f84"),0x4D250C3)
edge(0x4D2508D,bytes.fromhex("0f83"),0x4D2513D)
for a,e in w.items():
 altered=bytearray(bytes.fromhex(e));altered[0]^=1
 if altered==read(a,len(altered)): raise RuntimeError(f"mutation accepted {a:#x}")
print(f"Verified node #115, 1896-byte FDE body, {len(w)} instruction witnesses, 4 edges and {len(w)} mutation controls.")
