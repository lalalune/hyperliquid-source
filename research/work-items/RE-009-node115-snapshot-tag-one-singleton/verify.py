import hashlib,struct
from pathlib import Path
b=Path("artifacts/node/115/hl-node").read_bytes()
assert hashlib.sha256(b).hexdigest()=="a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
A={62949333: '4983fc01750e498b47084c3b7008757031d2eb2f', 62949400: '488d0c524c8b64c8104c8924244d8bafa00000004d85ed0f84820000004983fd01751e498b8f980000004c3ba198000000756c4c397118755931c0', 62949546: 'b0014c397138751f4c8923eb05c603', 46592256: '0fb64c24084883f902733eb80a00000048f724240f80f80000004801c848c7c2ffffffff4889c1480f42ca480f43c84989ce4981ee001f0afa720e4881c100e1f505480f42ca4989ce4889df4c89f6e81cb3a301'}
def edge(d,s,n,t):return s+n+struct.unpack_from("<b" if n==2 else "<i",d,s+1-0x1000)[0]==t
def valid(d):return all(d[x-0x1000:x-0x1000+len(bytes.fromhex(v))]==bytes.fromhex(v) for x,v in A.items()) and all(edge(d,*x) for x in [(0x3c087e7,2,0x3c08818),(0x3c08853,2,0x3c088b2),(0x3c088b5,2,0x3c088bc),(0x2c6f14f,5,0x46aa470)])
assert valid(b)
M=(1<<64)-1
for v,tag,want in [(0,0,100000000),(0,1,100000001),(1,0,100000010),(1,1,100000011),(M,0,M),(M,1,M)]: assert min(M,10*v+tag+100000000)==want
for x in A:
 d=bytearray(b);d[x-0x1000]^=1
 assert not valid(d)
print("PASS: #115 digest, 4 spans, 4 edges, 6 arithmetic controls, 4 mutations")
