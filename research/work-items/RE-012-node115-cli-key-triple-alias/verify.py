import hashlib,struct
from pathlib import Path
b=Path("artifacts/node/115/hl-node").read_bytes()
assert hashlib.sha256(b).hexdigest()=="a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
A={44975331: '488b8c241806000048898bb80000000f108424080600000f1183a8000000', 44975520: '4c8dbba8000000488d0d6efbb1fd486314914801caffe2', 44978968: '498b47104889442460410f10070f29442450488dbc24d0000000488d742450ff159b20a003'}
RELA=1360344
def valid(d):
 return all(d[x-0x1000:x-0x1000+len(bytes.fromhex(v))]==bytes.fromhex(v) for x,v in A.items()) and 0x60411c+struct.unpack_from("<i",d,0x60411c+7*4)[0]==0x2ae5286 and struct.unpack_from("<QQq",d,RELA)==(0x64e73d8,8,0x564a410)
assert valid(b)
for off in [x-0x1000 for x in A]+[0x60411c+7*4,RELA+16]:
 d=bytearray(b);d[off]^=1
 assert not valid(d)
print("OK: three spans, tag-9 entry, relocation and five mutation controls")
