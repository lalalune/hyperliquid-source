import hashlib,struct
from pathlib import Path
b=Path("artifacts/node/115/hl-node").read_bytes()
assert hashlib.sha256(b).hexdigest()=="a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
A={90492493: '488d7c2420488d742408ff1553eee900837c2420100f8488000000', 90492562: '0f104424200f104c24300f105424400f105c24500f115b300f1153200f114b100f1103', 44974951: '488dbc24d00000004c8dac24800300004c89eeff154830a003', 44974986: '488b8c24d0000000', 44975154: '4883f9100f84161c0000488d830a02000048894b10', 44975432: '0f1043100f104b200f1053300f105b400f119bf00000000f1193e00000000f118bd00000000f1183c0', 44975494: '488d83c0000000488b004889c14883e902ba0c000000480f43d14c8dbba8000000488d0d6efbb1fd486314914801caffe2'}
def valid(d): return all(d[x-0x1000:x-0x1000+len(bytes.fromhex(v))]==bytes.fromhex(v) for x,v in A.items()) and [0x60411c+struct.unpack_from("<i",d,0x60411c+i*4)[0] for i in (0,1)]==[0x2ae45b7,0x2ae5421]
assert valid(b)
for x in list(A)+[0x60411c+0x1000]:
 d=bytearray(b);d[x-0x1000]^=1
 assert not valid(d)
print("OK: seven instruction spans, two table entries and eight corruption controls")
