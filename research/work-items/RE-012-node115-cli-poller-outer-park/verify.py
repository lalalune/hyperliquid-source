import hashlib,struct
from pathlib import Path
b=Path("artifacts/node/115/hl-node").read_bytes()
assert hashlib.sha256(b).hexdigest()=="a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
A={44964417: '4c89e74c89eee89427000089c580', 44964457: '4084ed7544e9d3020000', 44964521: '4084ed0f849402000064803c25f0fbff', 44964544: '488b384883c710e8c4c02103e90fffffff', 44964561: '4c89ff31f6e825d81f034885c075e0', 44964320: '48c7c0d0eeffff640fb6584883fb01742f83fb02743c48'}
def edge(d,src,dst): return src+5+struct.unpack_from("<i",d,src+1-0x1000)[0]==dst
def valid(d): return all(d[x-0x1000:x-0x1000+len(bytes.fromhex(v))]==bytes.fromhex(v) for x,v in A.items()) and all(edge(d,*x) for x in [(0x2ae1a47,0x2ae41e0),(0x2ae1ac7,0x5cfdb90),(0x2ae1acc,0x2ae19e0),(0x2ae1ad6,0x5cdf300)])
assert valid(b)
for x in A:
 d=bytearray(b);d[x-0x1000]^=1
 assert not valid(d)
print("OK: six instruction spans, four direct edges, six mutation controls")
