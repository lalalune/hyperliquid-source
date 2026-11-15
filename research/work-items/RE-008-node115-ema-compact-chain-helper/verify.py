"""Verify selected node #115 EMA compact-chain-helper witnesses."""
from hashlib import sha256
from pathlib import Path
import struct,sys
sys.path.insert(0,str(Path("tools").resolve()))
from elf_index import sections
from fde_extents import eh_frame_records
TARGET="a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301";BODY="d89e1e44dd0b56b36f401191ece7471ba97cf810202318411e6441e0a186498b"
data=Path("artifacts/node/115/hl-node").read_bytes()
if sha256(data).hexdigest()!=TARGET: raise ValueError("wrong node artifact")
secs=sections(data);_,frames=eh_frame_records(data,secs)
if [(f["start"],f["end"]) for f in frames if f["start"]==0x4D30700] != [(0x4D30700,0x4D3098B)]: raise ValueError("unexpected FDE")
def read(a,n):
 hits=[s for s in secs if s["type"]!=8 and s["address"]<=a and a+n<=s["address"]+s["size"]]
 if len(hits)!=1: raise ValueError(f"unmapped {a:#x}")
 s=hits[0];o=s["offset"]+a-s["address"];return data[o:o+n]
if sha256(read(0x4D30700,651)).hexdigest()!=BODY: raise ValueError("body changed")
w={0x4D30700:"534881ec80000000",0x4D3070B:"488b06",0x4D3070E:"488b7e08",0x4D30712:"488b4e10",0x4D30716:"4885ff",0x4D3071F:"488b8cc8e8000000",0x4D3072A:"48ffc8",0x4D30750:"440fb789e6000000",0x4D30758:"4a8b8cc9e8000000",0x4D30780:"0fb7b1e6000000",0x4D30787:"488b8cf1e8000000",0x4D307FE:"0fb781e6000000",0x4D30823:"e8886cfeff",0x4D30848:"0fb7b0e6000000",0x4D30876:"488d3492",0x4D30882:"0f1044b008",0x4D3089D:"4885c9",0x4D308E2:"4889442450",0x4D308FD:"e8ae6bfeff",0x4D30961:"8b4c2410",0x4D30965:"894b10",0x4D30968:"0f280424",0x4D3096C:"0f1103",0x4D3096F:"48894318",0x4D30973:"48c7432000000000",0x4D3097B:"48895328"}
for a,e in w.items():
 raw=bytes.fromhex(e)
 if read(a,len(raw))!=raw: raise ValueError(f"witness mismatch {a:#x}")
raw=read(0x4D30719,6)
if raw[:2]!=bytes.fromhex("0f84") or 0x4D30719+6+struct.unpack("<i",raw[2:])[0]!=0x4D308E2: raise ValueError("wrong empty-root edge")
for a,e in w.items():
 altered=bytearray(bytes.fromhex(e));altered[0]^=1
 if altered==read(a,len(altered)): raise RuntimeError(f"mutation accepted {a:#x}")
print(f"Verified node #115, 651-byte FDE body, {len(w)} instruction witnesses, 1 edge and {len(w)} mutation controls.")
