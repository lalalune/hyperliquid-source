import hashlib
from pathlib import Path
b=Path("artifacts/node/115/hl-node").read_bytes()
assert hashlib.sha256(b).hexdigest()=="a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
A={94921160: 'f30f6f842428140000f30f7f8378010000', 94924217: '488d8378010000', 94924433: '488983c801000048c783d001000000000000', 94924669: '488dbc2410230000488db3c8010000488b1424e88bf5f4ff', 94201127: '4889fb488b064c8d4608488b0a488d7c24084889c64c89c2e89cdbf8ff', 93733102: '4889f5488b06488b70184c8b60204c2365084939f40f83e4'}
def valid(d): return all(d[x-0x1000:x-0x1000+len(bytes.fromhex(v))]==bytes.fromhex(v) for x,v in A.items())
assert valid(b)
for x in A:
 d=bytearray(b);d[x-0x1000]^=1
 assert not valid(d)
print("OK: six instruction spans and six corruption controls")
