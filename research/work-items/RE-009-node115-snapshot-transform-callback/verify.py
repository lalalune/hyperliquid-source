import hashlib,struct,subprocess
from pathlib import Path
b=Path("artifacts/node/115/hl-node").read_bytes()
assert hashlib.sha256(b).hexdigest()=="a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
A={41139245: '4c8d155c8d0300', 41139275: '4152415653e8bbb8b7ff', 36402448: '554157415641554154534881eca8020000', 36402908: '488b9c24f00200004889d9e834ebffff', 36397617: '4989ff8854240f48894c2410', 36397728: '4c89e641bc01000000488d7c2470ff542410', 36397866: '488dbc24480100004c89e6ff542410', 41372048: '534889fbbaa8000000ff1569abd6034889d85bc3'}
def valid(d):
 return all(d[x-0x1000:x-0x1000+len(bytes.fromhex(v))]==bytes.fromhex(v) for x,v in A.items()) and 0x273bc34+struct.unpack_from("<i",d,0x273bc30-0x1000)[0]==0x2774990 and 0x277499f+struct.unpack_from("<i",d,0x277499b-0x1000)[0]==0x64df508
assert valid(b)
for x in A:
 d=bytearray(b);d[x-0x1000]^=1; assert not valid(d)
r=subprocess.check_output(["llvm-readelf","-r","artifacts/node/115/hl-node"],text=True)
assert any("00000000064df508" in x and "R_X86_64_GLOB_DAT" in x and "memcpy@GLIBC_2.14" in x for x in r.splitlines())
assert 6*8+0x2a8+0x18==0x2f0
print("PASS: digest, 8 spans, 2 RIP targets, memcpy relocation, 8 mutations, stack offset")
