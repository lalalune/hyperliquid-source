import hashlib,struct
from pathlib import Path
b=Path("artifacts/node/115/hl-node").read_bytes()
assert hashlib.sha256(b).hexdigest()=="a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
A={90481694: '488b1e4889d848f7d80f80610100004989ff4c8b7608488b5610488d7c24204c89f6ff156218ea00807c2420010f8456010000', 90481745: '0f104424210f104c24310f298c24300100000f29842420010000488d7c2420488db42420010000e87343f6fb4c8b642428837c2420010f8451010000', 90482062: '488d3d02032efb488d155c0ae600be16000000ff15c951e900', 90482087: '0f104424280f298424a0000000488d3df2022efb488d0dde07e6004c8d05470ae600488d9424a0000000be1a000000'}
RELA=1415568
def target(d,s,n,t):return s+n+struct.unpack_from("<i",d,s+n-4-0x1000)[0]==t
def valid(d):return all(d[x-0x1000:x-0x1000+len(bytes.fromhex(v))]==bytes.fromhex(v) for x,v in A.items()) and struct.unpack_from("<QQq",d,RELA)==(0x64ebca8,8,0x5bb89f0) and all(target(d,*x) for x in [(0x564a427,6,0x564a58e),(0x564a44b,6,0x564a5a7),(0x564a478,5,0x15ae7f0),(0x564a487,6,0x564a5de)])
assert valid(b)
for off in [x-0x1000 for x in A]+[RELA+16]:
 d=bytearray(b);d[off]^=1
 assert not valid(d)
print("OK: four spans, one relocation, four branch/call targets, five mutation controls")
