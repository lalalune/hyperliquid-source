"""Verify selected node #115 EMA d112-helper witnesses."""
from hashlib import sha256
from pathlib import Path
import struct,sys
sys.path.insert(0,str(Path("tools").resolve()))
from elf_index import sections
from fde_extents import eh_frame_records
TARGET="a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301";BODY="f9e140eefe24a984da97d1138de1b81c09a4f856b9f70f58864f055ff2f887bd"
data=Path("artifacts/node/115/hl-node").read_bytes()
if sha256(data).hexdigest()!=TARGET: raise ValueError("wrong node artifact")
secs=sections(data);_,frames=eh_frame_records(data,secs)
if [(f["start"],f["end"]) for f in frames if f["start"]==0x4D2DA90] != [(0x4D2DA90,0x4D2E268)]: raise ValueError("unexpected FDE")
def read(a,n):
 hits=[s for s in secs if s["type"]!=8 and s["address"]<=a and a+n<=s["address"]+s["size"]]
 if len(hits)!=1: raise ValueError(f"unmapped {a:#x}")
 s=hits[0];o=s["offset"]+a-s["address"];return data[o:o+n]
if sha256(read(0x4D2DA90,2008)).hexdigest()!=BODY: raise ValueError("body changed")
w={0x4D2DAAC:"4c8b2e",0x4D2DAAF:"488b6e10",0x4D2DAB3:"410fb79d12010000",0x4D2DABB:"488d44ad00",0x4D2DAC0:"498d7c8508",0x4D2DAC5:"418b4c8518",0x4D2DAD1:"410f10448508",0x4D2DAEA:"4989ef",0x4D2DAED:"49f7d7",0x4D2DAFB:"ff15",0x4D2DB01:"488d3cad e4000000",0x4D2DB0C:"418b84ade4000000",0x4D2DB28:"4c89fa",0x4D2DB2B:"ff15",0x4D2DB31:"4c89ee",0x4D2DB34:"8d43ff",0x4D2DB37:"6641898512010000",0x4D2DB3F:"498b4c2408",0x4D2DB44:"6683f804"}
for a,e in w.items():
 raw=bytes.fromhex(e.replace(" ",""))
 if read(a,len(raw))!=raw: raise ValueError(f"witness mismatch {a:#x}")
raw=read(0x4D2DB48,6)
if raw[:2]!=bytes.fromhex("0f87"): raise ValueError("missing capacity edge")
if 0x4D2DB48+6+struct.unpack("<i",raw[2:])[0]!=0x4D2DBE4: raise ValueError("wrong capacity edge")
for a,e in w.items():
 altered=bytearray(bytes.fromhex(e.replace(" ","")));altered[0]^=1
 if altered==read(a,len(altered)): raise RuntimeError(f"mutation accepted {a:#x}")
print(f"Verified node #115, 2008-byte FDE body, {len(w)} instruction witnesses, 1 edge and {len(w)} mutation controls.")
