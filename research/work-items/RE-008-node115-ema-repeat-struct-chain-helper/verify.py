"""Verify selected node #115 EMA repeat-struct-chain witnesses."""
from hashlib import sha256
from pathlib import Path
import struct,sys
sys.path.insert(0,str(Path("tools").resolve()))
from elf_index import sections
from fde_extents import eh_frame_records
TARGET="a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301";BODY="748817fc4429b38c3abb6ea2f4cc8c4be07bf51ed0c86d0b92b35a4dcbfabb02"
data=Path("artifacts/node/115/hl-node").read_bytes()
if sha256(data).hexdigest()!=TARGET: raise ValueError("wrong node artifact")
secs=sections(data);_,frames=eh_frame_records(data,secs)
if [(f["start"],f["end"]) for f in frames if f["start"]==0x4D31070] != [(0x4D31070,0x4D3142D)]: raise ValueError("unexpected FDE")
def read(a,n):
 hits=[s for s in secs if s["type"]!=8 and s["address"]<=a and a+n<=s["address"]+s["size"]]
 if len(hits)!=1: raise ValueError(f"unmapped {a:#x}")
 s=hits[0];o=s["offset"]+a-s["address"];return data[o:o+n]
if sha256(read(0x4D31070,957)).hexdigest()!=BODY: raise ValueError("body changed")
w={0x4D31070:"534881ec30010000",0x4D3107B:"488b06",0x4D3107E:"488b7e08",0x4D31082:"488b4e10",0x4D31086:"4885ff",0x4D3108F:"488b8cc8b0040000",0x4D310C0:"440fb789ae040000",0x4D310C8:"4a8b8cc9b0040000",0x4D310F0:"0fb7b1ae040000",0x4D310F7:"488b8cf1b0040000",0x4D3116E:"0fb781ae040000",0x4D3119F:"e8dccefeff",0x4D31210:"0fb7b0ae040000",0x4D31236:"488d3c89",0x4D3123E:"448b84b8e0030000",0x4D3124B:"0f1084b8d0030000",0x4D31301:"4885d2",0x4D31345:"4889842490000000",0x4D3136C:"e80fcdfeff",0x4D313D1:"0f28442460",0x4D313D6:"0f114360",0x4D313DA:"0f28442450",0x4D313DF:"0f114350",0x4D313E3:"0f28442440",0x4D313E8:"0f114340",0x4D313EC:"0f280424",0x4D313F0:"0f284c2410",0x4D313F5:"0f28542420",0x4D313FA:"0f285c2430",0x4D313FF:"0f115b30",0x4D31403:"0f115320",0x4D31407:"0f114b10",0x4D3140B:"0f1103",0x4D3140E:"48894370",0x4D31412:"48c7437800000000",0x4D3141A:"48898b80000000",0x4D31421:"4889d8",0x4D31424:"4881c430010000",0x4D3142B:"5b",0x4D3142C:"c3"}
for a,e in w.items():
 raw=bytes.fromhex(e)
 if read(a,len(raw))!=raw: raise ValueError(f"witness mismatch {a:#x}")
raw=read(0x4D31089,6)
if raw[:2]!=bytes.fromhex("0f84") or 0x4D31089+6+struct.unpack("<i",raw[2:])[0]!=0x4D31345: raise ValueError("wrong empty-root edge")
for a,e in w.items():
 altered=bytearray(bytes.fromhex(e));altered[0]^=1
 if altered==read(a,len(altered)): raise RuntimeError(f"mutation accepted {a:#x}")
print(f"Verified node #115, 957-byte FDE body, {len(w)} instruction witnesses, 1 edge and {len(w)} mutation controls.")
