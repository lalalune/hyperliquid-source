import hashlib,struct,subprocess
from pathlib import Path
b=Path("artifacts/node/115/hl-node").read_bytes()
assert hashlib.sha256(b).hexdigest()=="a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
A={36402773: '488dbc24800100004c89f64889da4c89f9e8457a9b00', 36403257: '488b84249001000048898424f00000000f108424800100000f298424e0000000488d7c2450488d742410488d9424e0000000488d8c2400020000e838b9b000', 46592345: '48b94b598638d6c56d344c89f048f7e14989d449c1ec0b4c3ba6d00700000f83b40000004c8baec80700004969ec1005000066c7042456014889e7e87716870141bf010000004d3b642d50754c', 46592422: '4969c4102700004929c64901ed4d3b75107339498b450849c1e6054e8b6430104d85e474274e8b7430084c89e7ff15a70287034885c0747e4989c74889c74c89f64c89e2ff1518038703eb03', 46592498: '4531e44c89234c897b084c896310'}
def valid(d):
 return all(d[x-0x1000:x-0x1000+len(bytes.fromhex(v))]==bytes.fromhex(v) for x,v in A.items()) and 0x2c6f1f0+struct.unpack_from("<i",d,0x2c6f1ec-0x1000)[0]==0x64df508 and 0x22b766b+struct.unpack_from("<i",d,0x22b7667-0x1000)[0]==0x2c6f0b0
assert valid(b)
for x in A:
 d=bytearray(b);d[x-0x1000]^=1;assert not valid(d)
r=subprocess.check_output(["llvm-readelf","-r","artifacts/node/115/hl-node"],text=True)
assert any("00000000064df508" in x and "R_X86_64_GLOB_DAT" in x and "memcpy@GLIBC_2.14" in x for x in r.splitlines())
print("PASS: digest, 5 spans, consumer call, memcpy relocation and 5 mutations")
