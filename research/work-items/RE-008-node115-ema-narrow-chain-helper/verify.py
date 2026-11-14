"""Verify selected node #115 EMA narrow-chain-helper witnesses."""
from hashlib import sha256
from pathlib import Path
import struct,sys
sys.path.insert(0,str(Path("tools").resolve()))
from elf_index import sections
from fde_extents import eh_frame_records
TARGET="a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301";BODY="3f4eba69a0feaf47082c0ce25eeefaba8c2307702035eb75df7d0278e8193476"
data=Path("artifacts/node/115/hl-node").read_bytes()
if sha256(data).hexdigest()!=TARGET: raise ValueError("wrong node artifact")
secs=sections(data);_,frames=eh_frame_records(data,secs)
if [(f["start"],f["end"]) for f in frames if f["start"]==0x4D2FE70] != [(0x4D2FE70,0x4D30055)]: raise ValueError("unexpected FDE")
def read(a,n):
 hits=[s for s in secs if s["type"]!=8 and s["address"]<=a and a+n<=s["address"]+s["size"]]
 if len(hits)!=1: raise ValueError(f"unmapped {a:#x}")
 s=hits[0];o=s["offset"]+a-s["address"];return data[o:o+n]
if sha256(read(0x4D2FE70,485)).hexdigest()!=BODY: raise ValueError("body changed")
w={0x4D2FE70:"534883ec50",0x4D2FE78:"488b06",0x4D2FE7B:"488b7e08",0x4D2FE7F:"488b4e10",0x4D2FE83:"4885ff",0x4D2FE8C:"488b4cc868",0x4D2FE94:"48ffc8",0x4D2FE9D:"4883c7fe",0x4D2FEB0:"440fb74962",0x4D2FEB5:"4a8b4cc968",0x4D2FEC5:"4883ff07",0x4D2FED0:"0fb77162",0x4D2FED4:"488b4cf168",0x4D2FF1E:"0fb74162",0x4D2FF22:"48ffc8",0x4D2FF42:"e8d9bafeff",0x4D2FF5B:"0fb74862",0x4D2FF80:"488b4cf008",0x4D2FF85:"48897cf008",0x4D2FF8A:"4885d2",0x4D2FFCF:"48890424",0x4D2FFE7:"e834bafeff",0x4D30039:"48890b",0x4D3003C:"48894308",0x4D30040:"48c7431000000000",0x4D30048:"48897318"}
for a,e in w.items():
 raw=bytes.fromhex(e)
 if read(a,len(raw))!=raw: raise ValueError(f"witness mismatch {a:#x}")
raw=read(0x4D2FE86,6)
if raw[:2]!=bytes.fromhex("0f84") or 0x4D2FE86+6+struct.unpack("<i",raw[2:])[0]!=0x4D2FFCF: raise ValueError("wrong empty-root edge")
for a,e in w.items():
 altered=bytearray(bytes.fromhex(e));altered[0]^=1
 if altered==read(a,len(altered)): raise RuntimeError(f"mutation accepted {a:#x}")
print(f"Verified node #115, 485-byte FDE body, {len(w)} instruction witnesses, 1 edge and {len(w)} mutation controls.")
