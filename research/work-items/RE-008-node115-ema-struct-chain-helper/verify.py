"""Verify selected node #115 EMA struct-chain-helper witnesses."""
from hashlib import sha256
from pathlib import Path
import struct,sys
sys.path.insert(0,str(Path("tools").resolve()))
from elf_index import sections
from fde_extents import eh_frame_records
TARGET="a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301";BODY="829df9f31ee511a6fb9aec13f54cd73b0f49accef032c5539a74da9144cbd944"
data=Path("artifacts/node/115/hl-node").read_bytes()
if sha256(data).hexdigest()!=TARGET: raise ValueError("wrong node artifact")
secs=sections(data);_,frames=eh_frame_records(data,secs)
if [(f["start"],f["end"]) for f in frames if f["start"]==0x4D30060] != [(0x4D30060,0x4D3041D)]: raise ValueError("unexpected FDE")
def read(a,n):
 hits=[s for s in secs if s["type"]!=8 and s["address"]<=a and a+n<=s["address"]+s["size"]]
 if len(hits)!=1: raise ValueError(f"unmapped {a:#x}")
 s=hits[0];o=s["offset"]+a-s["address"];return data[o:o+n]
if sha256(read(0x4D30060,957)).hexdigest()!=BODY: raise ValueError("body changed")
w={0x4D30060:"534881ec30010000",0x4D3006B:"488b06",0x4D3006E:"488b7e08",0x4D30072:"488b4e10",0x4D30076:"4885ff",0x4D3007F:"488b8cc8b0040000",0x4D3008A:"48ffc8",0x4D300B0:"440fb789ae040000",0x4D300B8:"4a8b8cc9b0040000",0x4D300E0:"0fb7b1ae040000",0x4D300E7:"488b8cf1b0040000",0x4D3015E:"0fb781ae040000",0x4D3018F:"e80cd5ffff",0x4D30200:"0fb7b0ae040000",0x4D30226:"488d3c89",0x4D3022E:"448b84b8e0030000",0x4D3023B:"0f1084b8d0030000",0x4D3025F:"0f1184b8d0030000",0x4D302F1:"4885d2",0x4D30335:"4889842490000000",0x4D3035C:"e83fd3ffff",0x4D303C1:"0f28442460",0x4D303C6:"0f114360",0x4D303CF:"0f114350",0x4D303D8:"0f114340"}
for a,e in w.items():
 raw=bytes.fromhex(e)
 if read(a,len(raw))!=raw: raise ValueError(f"witness mismatch {a:#x}")
raw=read(0x4D30079,6)
if raw[:2]!=bytes.fromhex("0f84") or 0x4D30079+6+struct.unpack("<i",raw[2:])[0]!=0x4D30335: raise ValueError("wrong empty-root edge")
for a,e in w.items():
 altered=bytearray(bytes.fromhex(e));altered[0]^=1
 if altered==read(a,len(altered)): raise RuntimeError(f"mutation accepted {a:#x}")
print(f"Verified node #115, 957-byte FDE body, {len(w)} instruction witnesses, 1 edge and {len(w)} mutation controls.")
