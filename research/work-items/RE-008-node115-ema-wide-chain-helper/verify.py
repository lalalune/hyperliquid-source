"""Verify selected node #115 EMA wide-chain-helper witnesses."""
from hashlib import sha256
from pathlib import Path
import struct, sys
sys.path.insert(0, str(Path("tools").resolve()))
from elf_index import sections
from fde_extents import eh_frame_records
TARGET="a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"; BODY="fb3b0b157e5c676ab79af41c8aa97a6754fcb8014e1e4ef5e8f37ec004df7bb0"
data=Path("artifacts/node/115/hl-node").read_bytes()
if sha256(data).hexdigest()!=TARGET: raise ValueError("wrong node artifact")
secs=sections(data); _,frames=eh_frame_records(data,secs)
if [(f["start"],f["end"]) for f in frames if f["start"]==0x4D2FB90] != [(0x4D2FB90,0x4D2FE6A)]: raise ValueError("unexpected FDE")
def read(a,n):
 hits=[s for s in secs if s["type"]!=8 and s["address"]<=a and a+n<=s["address"]+s["size"]]
 if len(hits)!=1: raise ValueError(f"unmapped {a:#x}")
 s=hits[0];o=s["offset"]+a-s["address"];return data[o:o+n]
if sha256(read(0x4D2FB90,730)).hexdigest()!=BODY: raise ValueError("body changed")
w={0x4D2FBA4:"488b06",0x4D2FBA7:"488b7e08",0x4D2FBAB:"488b4e10",0x4D2FBAF:"4885ff",0x4D2FBB8:"488b8cc8b0090000",0x4D2FBC3:"48ffc8",0x4D2FBD3:"4883e607",0x4D2FBE0:"440fb789aa090000",0x4D2FBE8:"4a8b8cc9b0090000",0x4D2FC10:"0fb7b1aa090000",0x4D2FC17:"488b8cf1b0090000",0x4D2FC8E:"0fb781aa090000",0x4D2FCD1:"ff1531f87a01",0x4D2FCEF:"410fb787aa090000",0x4D2FD00:"450fb7a7a8090000",0x4D2FD18:"4969c4d8000000",0x4D2FD30:"4f896ce708",0x4D2FD49:"41ffd5",0x4D2FD5C:"41ffd5",0x4D2FD5F:"4885ed",0x4D2FDA3:"4889442408",0x4D2FDBE:"e86dd1feff",0x4D2FE21:"488b0424",0x4D2FE25:"488903",0x4D2FE36:"ff15ccf67a01",0x4D2FE3C:"4c89bbe0000000",0x4D2FE43:"48c783e800000000000000",0x4D2FE4E:"4c89a3f0000000"}
for a,e in w.items():
 raw=bytes.fromhex(e)
 if read(a,len(raw))!=raw: raise ValueError(f"witness mismatch {a:#x}")
raw=read(0x4D2FBB2,6)
if raw[:2]!=bytes.fromhex("0f84") or 0x4D2FBB2+6+struct.unpack("<i",raw[2:])[0]!=0x4D2FDA3: raise ValueError("wrong empty-root edge")
for a,e in w.items():
 altered=bytearray(bytes.fromhex(e));altered[0]^=1
 if altered==read(a,len(altered)): raise RuntimeError(f"mutation accepted {a:#x}")
print(f"Verified node #115, 730-byte FDE body, {len(w)} instruction witnesses, 1 edge and {len(w)} mutation controls.")
