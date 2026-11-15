import hashlib,struct
from pathlib import Path
b=Path("artifacts/node/115/hl-node").read_bytes()
assert hashlib.sha256(b).hexdigest()=="a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
A={44975645: '4c8db3200200004c89f7e8c468000084c07409b001b104e924180000', 44979330: '4c8db3200200004c89f7e85f5a000084c07409b001b103e9bf090000', 44981853: '888b1a0200004881c4a80f00005b415c415d415e415f5dc3', 44974577: '4889fb0fb6871a020000488d0de2feb1fd486304814801c8ffe0'}
def valid(d):
 return all(d[x-0x1000:x-0x1000+len(bytes.fromhex(v))]==bytes.fromhex(v) for x,v in A.items()) and [0x6040e4+struct.unpack_from("<i",d,0x6040e4+4*i)[0] for i in (3,4)]==[0x2ae5482,0x2ae461d] and all(x+5+struct.unpack_from("<i",d,x+1-0x1000)[0]==0x2ae5e5d for x in (0x2ae4634,0x2ae5499))
assert valid(b)
for x in list(A)+[0x6040f0+0x1000]:
 d=bytearray(b);d[x-0x1000]^=1
 assert not valid(d)
print("OK: four instruction spans, two state-table entries, two branches, five mutation controls")
