import hashlib,struct
from pathlib import Path
b=Path("artifacts/node/115/hl-node").read_bytes()
assert hashlib.sha256(b).hexdigest()=="a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
A={36402470: '4889fd4c8b364c89f048f7d80f814c0400004c894424404c894c2438', 36402626: 'e8f9d00800488b8424980100004889442430488b8424a001000048894424084c8ba424a80100004989ee48c74424100000000048c7442418080000000f57c00f114424204d85e40f840403000049c1e404488b6c24084901ec0fb6c38944240448b800000000', 36402752: '4883c5104c39e50f84c6020000488b5d004c8b7d08488dbc24800100004c89f64889da4c89f9e8457a9b00488d7c24504c89f64889da4c89f9e832769b00'}
def edge(d,s,t):return s+5+struct.unpack_from("<i",d,s+1-0x1000)[0]==t
def valid(d):return all(d[x-0x1000:x-0x1000+len(bytes.fromhex(v))]==bytes.fromhex(v) for x,v in A.items()) and all(edge(d,*x) for x in [(0x22b75c2,0x23446c0),(0x22b7666,0x2c6f0b0),(0x22b7679,0x2c6ecb0)])
assert valid(b)
for x in A:
 d=bytearray(b);d[x-0x1000]^=1
 assert not valid(d)
print("PASS: #115 target digest, 3 byte spans, 3 direct calls, 3 mutations")
