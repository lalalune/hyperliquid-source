import hashlib,struct
from pathlib import Path
b=Path("artifacts/node/115/hl-node").read_bytes()
assert hashlib.sha256(b).hexdigest()=="a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
A={44975655: 'e8c468000084c07409b001b104e9241800004c89f7e8cf97fdffc6830802000000e9bd170000', 44979340: 'e85f5a000084c07409b001b103e9bf0900004c89f7e86a89fdffc6830902000000e958090000', 44981770: '48c783100200000000000048c7830a0200000000000080bb05020000007420488bb3a8', 44981833: 'c683050200000066c783180200000000b10131c0888b1a0200004881c4a80f00005b415c415d415e415f5dc3', 44964457: '4084ed7544e9d3020000', 44965190: '488dbc24a85a0000e8bd90fbff488b442420488b7c2428ff5018488dbc2490000000e823bdfdffe929060000'}
def edge(d,s,t):return s+5+struct.unpack_from("<i",d,s+1-0x1000)[0]==t
def valid(d):return all(d[x-0x1000:x-0x1000+len(bytes.fromhex(v))]==bytes.fromhex(v) for x,v in A.items()) and all(edge(d,*x) for x in [(0x2ae4648,0x2ae5e0a),(0x2ae54ad,0x2ae5e0a),(0x2ae1d4e,0x2a9ae10),(0x2ae1d68,0x2abda90)])
assert valid(b)
for x in A:
 d=bytearray(b);d[x-0x1000]^=1
 assert not valid(d)
print("OK: six instruction spans, four direct edges and six mutation controls")
