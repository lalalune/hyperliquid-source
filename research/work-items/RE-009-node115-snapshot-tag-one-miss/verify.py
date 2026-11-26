import hashlib,struct
from pathlib import Path
b=Path("artifacts/node/115/hl-node").read_bytes()
assert hashlib.sha256(b).hexdigest()=="a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
A={46592206: '488b86a00000004939c60f8340010000488b86980000004c89f148c1e105488b14084881c6d80000004889e7ff', 46592256: '0fb64c24084883f902733e', 46592329: '4889df4c89f6e81cb3a301', 62949307: '4889fb488914244c8b66104d85e40f84860000004989d64989f74983fc01750e498b47084c3b7008757031d2eb2f', 62949461: 'b002eb63', 62949564: '8843084889d84883c4085b415c415d415e415f5dc3'}
def edge(d,s,n,t):return s+n+struct.unpack_from("<b" if n==2 else "<i",d,s+n-(1 if n==2 else 4)-0x1000)[0]==t
def valid(d):return all(d[x-0x1000:x-0x1000+len(bytes.fromhex(v))]==bytes.fromhex(v) for x,v in A.items()) and all(edge(d,*x) for x in [(0x3c087c9,6,0x3c08855),(0x3c087e3,2,0x3c08855),(0x3c08857,2,0x3c088bc),(0x2c6f109,2,0x2c6f149),(0x2c6f14f,5,0x46aa470)])
assert valid(b)
for x in A:
 d=bytearray(b);d[x-0x1000]^=1
 assert not valid(d)
print("PASS: #115 digest, 6 spans, 5 branches/calls, 6 mutations")
