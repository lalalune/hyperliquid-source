import hashlib,struct
from pathlib import Path
b=Path("artifacts/node/115/hl-node").read_bytes()
assert hashlib.sha256(b).hexdigest()=="a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
A={44975494: '488d83c0000000488b004889c14883e902ba0c000000480f43d14c8dbba8000000488d0d6efbb1fd486314914801caffe2'}
T=[44975543, 44979233, 44977852, 44978388, 44975921, 44979378, 44981011, 44978822, 44981429, 44977699, 44981269, 44975693, 44976155, 44979565]
def valid(d): return all(d[x-0x1000:x-0x1000+len(bytes.fromhex(v))]==bytes.fromhex(v) for x,v in A.items()) and [0x60411c+struct.unpack_from("<i",d,0x60411c+4*i)[0] for i in range(14)]==T
assert valid(b)
for tag in range(16):
 i=12 if tag<2 else tag-2
 assert 0<=i<len(T) and (0x60411c+struct.unpack_from("<i",b,0x60411c+4*i)[0])==T[i]
for off in [0x2ae4586-0x1000]+[0x60411c+4*i for i in range(14)]:
 d=bytearray(b);d[off]^=1
 assert not valid(d)
print("OK: instruction span, 14 table entries, 16 tag projections, 15 mutation controls")
