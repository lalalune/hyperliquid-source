"""Verify selected node #115 EMA branch2-helper witnesses."""
from hashlib import sha256
from pathlib import Path
import struct,sys
sys.path.insert(0,str(Path("tools").resolve()))
from elf_index import sections
from fde_extents import eh_frame_records
TARGET="a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301";BODY="9420057981f340d870d8b1249d657c55828fdc44ce0eccb8ff11a55f04ef57cb"
data=Path("artifacts/node/115/hl-node").read_bytes()
if sha256(data).hexdigest()!=TARGET: raise ValueError("wrong node artifact")
secs=sections(data);_,frames=eh_frame_records(data,secs)
if [(f["start"],f["end"]) for f in frames if f["start"]==0x4D2AD00] != [(0x4D2AD00,0x4D2B46C)]: raise ValueError("unexpected FDE")
def read(a,n):
 hits=[s for s in secs if s["type"]!=8 and s["address"]<=a and a+n<=s["address"]+s["size"]]
 if len(hits)!=1: raise ValueError(f"unmapped {a:#x}")
 s=hits[0];o=s["offset"]+a-s["address"];return data[o:o+n]
if sha256(read(0x4D2AD00,1900)).hexdigest()!=BODY: raise ValueError("body changed")
w={0x4D2AD1E:"488b2e",0x4D2AD21:"4c8b6e10",0x4D2AD25:"0fb75d62",0x4D2AD29:"4a8d7ced08",0x4D2AD2E:"4a8b44ed08",0x4D2AD43:"4d89ee",0x4D2AD46:"49f7d6",0x4D2AD54:"4c8b3d0d487b01",0x4D2AD5B:"41ffd7",0x4D2AD66:"4c01e8",0x4D2AD69:"4c896c2408",0x4D2AD73:"488d7c0564",0x4D2AD78:"488b4c0571",0x4D2AD8A:"0f29842490000000",0x4D2ADA2:"41ffd7",0x4D2ADA5:"4889ee",0x4D2ADA8:"8d43ff",0x4D2ADAB:"66894562",0x4D2ADAF:"4d8b6c2408",0x4D2ADB4:"6683f804",0x4D2ADC4:"0f84"}
for a,e in w.items():
 raw=bytes.fromhex(e)
 if read(a,len(raw))!=raw: raise ValueError(f"witness mismatch {a:#x}")
def edge(site,prefix,target):
 raw=read(site,len(prefix)+4)
 if raw[:len(prefix)]!=prefix: raise ValueError(f"edge opcode {site:#x}")
 actual=site+len(raw)+struct.unpack("<i",raw[-4:])[0]
 if actual!=target: raise ValueError(f"edge target {site:#x}: {actual:#x}")
edge(0x4D2ADB8,bytes.fromhex("0f87"),0x4D2AE40);edge(0x4D2ADC4,bytes.fromhex("0f84"),0x4D2AE4A)
for a,e in w.items():
 altered=bytearray(bytes.fromhex(e));altered[0]^=1
 if altered==read(a,len(altered)): raise RuntimeError(f"mutation accepted {a:#x}")
print(f"Verified node #115, 1900-byte FDE body, {len(w)} instruction witnesses, 2 edges and {len(w)} mutation controls.")
