import hashlib,struct
from pathlib import Path
b=Path("artifacts/node/115/hl-node").read_bytes()
assert hashlib.sha256(b).hexdigest()=="a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
A={44974643: '48bd0000000000000080', 44975765: '440fb6abf8000000440fb6a3f90000004889bc2428030000ff151d2da0034989c64488ac24e80000004488a424e90000004889ac24d0000000c68424ea00000000488dbc24d00000004889c6488b5424084c89f94531c0e81f74c5ff4c89f7e867b8fbff488bb424c00000004885f674', 41138974: '4989ce4889d34585c07474', 41139101: '4531e448b8000000000000008048ffc04839077593', 41139013: '0fb64f180fb64719488b571048895424400f10070f29442430807f1a000f84c1000000', 41139241: '4883ec084c8d155c8d03000fb6d10fb6c8488d4424384889f74889c64d89e04d89f94152415653e8bbb8b7ff'}
def edge(d,s,n,t):return s+n+struct.unpack_from("<i",d,s+n-4-0x1000)[0]==t
def valid(d):return all(d[x-0x1000:x-0x1000+len(bytes.fromhex(v))]==bytes.fromhex(v) for x,v in A.items()) and 0x60411c+struct.unpack_from("<i",d,0x60411c+11*4)[0]==0x2ae464d and all(edge(d,*x) for x in [(0x2ae46ec,5,0x273bb10),(0x273bc50,5,0x22b7510)])
assert valid(b)
for off in [x-0x1000 for x in A]+[0x60411c+11*4]:
 d=bytearray(b);d[off]^=1
 assert not valid(d)
print("OK: six instruction spans, table entry, two calls, seven corruption controls")
