import hashlib, struct
from pathlib import Path
b=Path("artifacts/node/115/hl-node").read_bytes()
assert hashlib.sha256(b).hexdigest()=="a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
A={44974577: '4889fb0fb6871a020000488d0de2feb1fd486304814801c8ffe0', 44981840: '66c783180200000000b10131c0888b1a0200004881c4a80f00005b415c415d415e415f5dc3', 44983772: '66c783180200000000c6831a02000002488b3c24e85ba49003', 44982252: '488d3ddd1d9603ff1567b39f03488d3dd01d9603ff1562b39f03'}
def valid(d):
 return all(d[x-0x1000:x-0x1000+len(bytes.fromhex(v))]==bytes.fromhex(v) for x,v in A.items()) and [0x6040e4+struct.unpack_from("<i",d,0x6040e4+4*i)[0] for i in (1,2)]==[0x2ae5ff9,0x2ae5fec] and 0x2ae65f5+struct.unpack_from("<i",d,0x2ae65f1-0x1000)[0]==0x63f0a50
assert valid(b)
for x in list(A)+[0x6040e8+0x1000]:
 d=bytearray(b);d[x-0x1000]^=1
 assert not valid(d)
print("OK: four instruction spans, two table entries, unwind target and five mutation controls")
