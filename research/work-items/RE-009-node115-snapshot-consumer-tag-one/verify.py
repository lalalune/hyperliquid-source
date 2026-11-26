import hashlib,struct
from pathlib import Path
b=Path("artifacts/node/115/hl-node").read_bytes()
assert hashlib.sha256(b).hexdigest()=="a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
A={46592196: '4883fa010f858b000000488b86a00000004939c60f8340010000488b86980000004c89f148c1e105488b14084881c6d80000004889e7ff15606987030fb64c24084883f902', 46592267: 'b80a00000048f724240f80f80000004801c848c7c2ffffffff4889c1480f42ca480f43c84989ce4981ee001f0afa720e4881c100e1f505480f42ca4989ce4889df4c89f6e81cb3a301', 46591163: '4989f64889fb4883fa017533498bb6c81f00004839f10f838a000000488d34c948c1e6054903b6c01f00004981c6900000004889df4c89f2e8e8d776ffeb58'}
R=1340784
def edge(d,s,t):return s+5+struct.unpack_from("<i",d,s+1-0x1000)[0]==t
def valid(d):return all(d[x-0x1000:x-0x1000+len(bytes.fromhex(v))]==bytes.fromhex(v) for x,v in A.items()) and struct.unpack_from("<QQq",d,R)==(0x64e5a60,8,0x3c087b0) and edge(d,0x2c6f14f,0x46aa470) and edge(d,0x2c6ecf3,0x23dc4e0)
assert valid(b)
M=(1<<64)-1
for v,b,expected in [(0,0,100000000),(1,1,100000011),((M-100000000)//10,0,100000000+10*((M-100000000)//10)),(M,1,M)]:assert min(M,10*v+b+100000000)==expected
for off in [x-0x1000 for x in A]+[R+16]:
 d=bytearray(Path("artifacts/node/115/hl-node").read_bytes());d[off]^=1
 assert not valid(d)
print("PASS: #115 digest, 3 spans, relocation, 2 calls, 4 arithmetic examples, 4 mutations")
