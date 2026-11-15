"""Verify selected node #115 EMA wider-chain-helper witnesses."""
from hashlib import sha256
from pathlib import Path
import struct,sys
sys.path.insert(0,str(Path("tools").resolve()))
from elf_index import sections
from fde_extents import eh_frame_records
TARGET="a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301";BODY="1b8a97ed9885a6303be2fbea560a6b714d7826cd33ed07281f3e45ceb28c28e3"
data=Path("artifacts/node/115/hl-node").read_bytes()
if sha256(data).hexdigest()!=TARGET: raise ValueError("wrong node artifact")
secs=sections(data);_,frames=eh_frame_records(data,secs)
if [(f["start"],f["end"]) for f in frames if f["start"]==0x4D30420] != [(0x4D30420,0x4D306FA)]: raise ValueError("unexpected FDE")
def read(a,n):
 hits=[s for s in secs if s["type"]!=8 and s["address"]<=a and a+n<=s["address"]+s["size"]]
 if len(hits)!=1: raise ValueError(f"unmapped {a:#x}")
 s=hits[0];o=s["offset"]+a-s["address"];return data[o:o+n]
if sha256(read(0x4D30420,730)).hexdigest()!=BODY: raise ValueError("body changed")
w={0x4D30420:"554157415641554154534881eca8010000",0x4D30434:"488b06",0x4D30437:"488b7e08",0x4D3043B:"488b4e10",0x4D3043F:"4885ff",0x4D30448:"488b8cc8a0070000",0x4D30453:"48ffc8",0x4D30470:"440fb7899a070000",0x4D30478:"4a8b8cc9a0070000",0x4D304A0:"0fb7b19a070000",0x4D304A7:"488b8cf1a0070000",0x4D3051E:"0fb7819a070000",0x4D30545:"e8b675ffff",0x4D3057F:"410fb7879a070000",0x4D305A8:"4969c4a8000000",0x4D305C0:"4f896ce708",0x4D305D9:"41ffd5",0x4D305EC:"41ffd5",0x4D305EF:"4885ed",0x4D30633:"4889442408",0x4D3064E:"e8ad74ffff",0x4D306B1:"488b0424",0x4D306B5:"488903",0x4D306C6:"ff153cee7a01",0x4D306CC:"4c89bbb0000000",0x4D306D3:"48c783b800000000000000",0x4D306DE:"4c89a3c0000000"}
for a,e in w.items():
 raw=bytes.fromhex(e)
 if read(a,len(raw))!=raw: raise ValueError(f"witness mismatch {a:#x}")
raw=read(0x4D30442,6)
if raw[:2]!=bytes.fromhex("0f84") or 0x4D30442+6+struct.unpack("<i",raw[2:])[0]!=0x4D30633: raise ValueError("wrong empty-root edge")
for a,e in w.items():
 altered=bytearray(bytes.fromhex(e));altered[0]^=1
 if altered==read(a,len(altered)): raise RuntimeError(f"mutation accepted {a:#x}")
print(f"Verified node #115, 730-byte FDE body, {len(w)} instruction witnesses, 1 edge and {len(w)} mutation controls.")
