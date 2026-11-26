import hashlib,struct,subprocess
from pathlib import Path
b=Path("artifacts/node/115/hl-node").read_bytes()
assert hashlib.sha256(b).hexdigest()=="a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
A={40751018: '4c8d4b384c8d4318488d7c2408488d742470488d5424204c89f9e8b7915cff', 30040465: '4989d4488b2e440fb7bd2a0400004983ff0b7238', 30040541: '488b56104c8d4201488d0452488d1cc5080000004801eb4d39f8767b498b44241048894310410f1004240f1103', 30040692: '488d45084c894424304f8d044048897c24504a8d3cc04d89e54989cc4989ee4c89fd4829d548c1e5034889542418488d146d000000004801ea48897424104889deff15ad928304410f1045000f1103498b451048894310', 30040847: '488b442418488d04c0498db4c610010000488b442430488d04c0498d3cc64881c710010000488d14ed000000004801ea4c89f5ff1520928304488b542418488b7c2450488b742410', 30040919: '41ffc7488d04d2488b8c241001000048898cc5500100000f288424d00000000f288c24e00000000f289424f00000000f289c24000100000f119cc5400100000f1194c5300100000f118cc5200100000f1184c510010000664489bd2a040000'}
def valid(d):
 return all(d[x-0x1000:x-0x1000+len(bytes.fromhex(v))]==bytes.fromhex(v) for x,v in A.items()) and 0x26dcfc9+struct.unpack_from("<i",d,0x26dcfc5-0x1000)[0]==0x1ca6180 and 0x1ca62bb+struct.unpack_from("<i",d,0x1ca62b7-0x1000)[0]==0x64df568 and 0x1ca6348+struct.unpack_from("<i",d,0x1ca6344-0x1000)[0]==0x64df568
assert valid(b)
for x in A:
 d=bytearray(b);d[x-0x1000]^=1;assert not valid(d)
r=subprocess.check_output(["llvm-readelf","-r","artifacts/node/115/hl-node"],text=True)
assert any("00000000064df568" in x and "R_X86_64_GLOB_DAT" in x and "memmove@GLIBC_2.2.5" in x for x in r.splitlines())
for n,i,k,v in [(0,0,0,0),(1,0,24,72),(10,5,120,360),(10,10,0,0)]:assert ((n-i)*24,(n-i)*72)==(k,v)
print("PASS: digest, 6 spans, call/relocation targets, 6 mutations, 4 arithmetic controls")
