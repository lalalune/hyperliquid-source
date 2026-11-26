import hashlib,struct
from pathlib import Path
b=Path("artifacts/node/115/hl-node").read_bytes()
assert hashlib.sha256(b).hexdigest()=="a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
A={41139241: '4883ec084c8d155c8d03000fb6d10fb6c8488d4424384889f74889c64d89e04d89f94152415653e8bbb8b7ff', 36402465: '4189cd89d3', 36402715: '0fb6c389442404', 36402900: '448b7c24044489fa488b9c24f00200004889d9e834ebffff488dbc2410010000488db424c80100004489fa4889d9e819ebffff', 36403061: '4584ed7476488dbc24e8010000488db424c00000008b542404488b8c24f0020000e885eaffff'}
def edge(d,s,n,t):return s+n+struct.unpack_from("<b" if n==2 else "<i",d,s+1-0x1000)[0]==t
def valid(d):return all(d[x-0x1000:x-0x1000+len(bytes.fromhex(v))]==bytes.fromhex(v) for x,v in A.items()) and all(edge(d,*x) for x in [(0x273bc50,5,0x22b7510),(0x22b76e7,5,0x22b6220),(0x22b7702,5,0x22b6220),(0x22b7778,2,0x22b77f0),(0x22b7796,5,0x22b6220)])
assert valid(b)
for x in A:
 d=bytearray(b);d[x-0x1000]^=1
 assert not valid(d)
print("PASS: #115 digest, 5 spans, 5 calls/branches, 5 mutations")
