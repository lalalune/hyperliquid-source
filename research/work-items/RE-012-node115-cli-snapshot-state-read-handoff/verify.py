import hashlib,struct
from pathlib import Path
b=Path("artifacts/node/115/hl-node").read_bytes()
assert hashlib.sha256(b).hexdigest()=="a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
A={44975708: '488bbbd0000000488bb3d8000000', 44975781: '4889bc2428030000ff151d2da0034989c6', 44975830: '488dbc24d00000004889c6488b5424084c89f94531c0e81f74c5ff4c89f7e867b8fbff', 90482309: '488d154cc1e200e87f3dbefea80175094889d04883c4105bc3', 90482334: '4889542408488d3d88002efb488d0daf06e6004c8d058809e600488d542408be2b000000ff15d84fe9000f0b'}
RELA=1360320
def edge(d,s,t):return s+5+struct.unpack_from("<i",d,s+1-0x1000)[0]==t
def valid(d):return all(d[x-0x1000:x-0x1000+len(bytes.fromhex(v))]==bytes.fromhex(v) for x,v in A.items()) and struct.unpack_from("<QQq",d,RELA)==(0x64e73d0,8,0x564a680) and all(edge(d,*x) for x in [(0x564a68c,0x422e410),(0x2ae46ec,0x273bb10),(0x2ae46f4,0x2a9ff60)])
assert valid(b)
for off in [x-0x1000 for x in A]+[RELA+16]:
 d=bytearray(b);d[off]^=1
 assert not valid(d)
print("OK: five instruction spans, relocation, three direct edges, six corruption controls")
