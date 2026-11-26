import hashlib,struct,subprocess
from pathlib import Path
b=Path("artifacts/node/115/hl-node").read_bytes()
assert hashlib.sha256(b).hexdigest()=="a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
A={36403289: '488d7c2450488d742410488d9424e0000000488d8c2400020000e838b9b000', 47985938: '498b042448894424784d8b6c24084d8b7c2410488b55084885d20f8482010000488b45104889842488000000488d420848895424700fb78a2a04000048898c24200100008d0ccd00000000', 47986013: '4c8d244948c7c3ffffffff0f1f8400000000004d85e4744b488d6818488b7008488b50104d89fe4929d6490f42d74c89efff15bcc57103489885c04c0f45f04d85f60f98c00f9fc128c148ffc34983c4e84889e880f90174ba0fb6c185c0743f', 47986112: '488b9c2420010000488b542470488b8424880000004883e801488bac24800000000f82cf0000004889842488000000488b94da30040000e942ffffff', 47986246: '488d04db498d04c64805100100004c8b742408488b484049894e400f10000f1048100f1050200f105830410f115e30410f115620410f114e10410f11060f284424100f284c24200f285424300f285c24400f11000f1148100f1150200f115830488b4c245048894840'}
def valid(d):
 return all(d[x-0x1000:x-0x1000+len(bytes.fromhex(v))]==bytes.fromhex(v) for x,v in A.items()) and 0x2dc3594+struct.unpack_from("<i",d,0x2dc3590-0x1000)[0]==0x64dfb50
assert valid(b)
for x in A:
 d=bytearray(b);d[x-0x1000]^=1;assert not valid(d)
r=subprocess.check_output(["llvm-readelf","-r","artifacts/node/115/hl-node"],text=True)
assert any("00000000064dfb50" in x and "R_X86_64_GLOB_DAT" in x and "memcmp@GLIBC_2.2.5" in x for x in r.splitlines())
def compare(x,y):
 for a,c in zip(x,y):
  if a!=c:return (a>c)-(a<c)
 return (len(x)>len(y))-(len(x)<len(y))
for x,y,z in [(b"",b"",0),(b"a",b"a",0),(b"a",b"ab",-1),(b"ab",b"a",1),(b"b",b"a",1),(b"a",b"b",-1)]:assert compare(x,y)==z
print("PASS: digest, 5 spans, memcmp relocation, 5 mutations, 6 model controls")
