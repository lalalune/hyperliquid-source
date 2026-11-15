"""Verify selected node #115 EMA c3-helper witnesses."""
from hashlib import sha256
from pathlib import Path
import struct,sys
sys.path.insert(0,str(Path("tools").resolve()))
from elf_index import sections
from fde_extents import eh_frame_records
TARGET="a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301";BODY="b1cebe748d290819bbe12608e8ed4119c6baa65ecd38d62a0ed0eeaf294aee8a"
data=Path("artifacts/node/115/hl-node").read_bytes()
if sha256(data).hexdigest()!=TARGET: raise ValueError("wrong node artifact")
secs=sections(data);_,frames=eh_frame_records(data,secs)
if [(f["start"],f["end"]) for f in frames if f["start"]==0x4D2C060] != [(0x4D2C060,0x4D2C31F)]: raise ValueError("unexpected FDE")
def read(a,n):
 hits=[s for s in secs if s["type"]!=8 and s["address"]<=a and a+n<=s["address"]+s["size"]]
 if len(hits)!=1: raise ValueError(f"unmapped {a:#x}")
 s=hits[0];o=s["offset"]+a-s["address"];return data[o:o+n]
if sha256(read(0x4D2C060,703)).hexdigest()!=BODY: raise ValueError("body changed")
w={0x4D2C07E:"488b2e",0x4D2C081:"4c8b6e10",0x4D2C085:"440fb7bde6000000",0x4D2C08D:"4a8d7ced08",0x4D2C092:"4a8b44ed08",0x4D2C0A7:"4d89ee",0x4D2C0AA:"49f7d6",0x4D2C0B8:"488b1da9347b01",0x4D2C0BF:"ffd3",0x4D2C0CC:"488d7c8560",0x4D2C0D1:"8b4c8568",0x4D2C0D9:"488b4c8560",0x4D2C0F6:"ffd3",0x4D2C0F8:"418d47ff",0x4D2C0FC:"668985e6000000",0x4D2C103:"4d8b642408",0x4D2C108:"6683f804",0x4D2C112:"488b4500",0x4D2C124:"0fb795e4000000"}
for a,e in w.items():
 raw=bytes.fromhex(e)
 if read(a,len(raw))!=raw: raise ValueError(f"witness mismatch {a:#x}")
def edge(site,prefix,target):
 raw=read(site,len(prefix)+4)
 if raw[:len(prefix)]!=prefix: raise ValueError(f"edge opcode {site:#x}")
 actual=site+len(raw)+struct.unpack("<i",raw[-4:])[0]
 if actual!=target: raise ValueError(f"edge target {site:#x}: {actual:#x}")
edge(0x4D2C10C,bytes.fromhex("0f87"),0x4D2C2A5);edge(0x4D2C119,bytes.fromhex("0f84"),0x4D2C223)
for a,e in w.items():
 altered=bytearray(bytes.fromhex(e));altered[0]^=1
 if altered==read(a,len(altered)): raise RuntimeError(f"mutation accepted {a:#x}")
print(f"Verified node #115, 703-byte FDE body, {len(w)} instruction witnesses, 2 edges and {len(w)} mutation controls.")
