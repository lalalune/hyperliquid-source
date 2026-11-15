import hashlib,struct
from pathlib import Path
b=Path("artifacts/node/115/hl-node").read_bytes()
assert hashlib.sha256(b).hexdigest()=="a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
A={93733262: '498b442428488b5d084839d8753531c9b001', 93733329: '4c892424488b75004c8b66184c01e04839d80f95c0743a', 93733356: '4d8b7d3031c9b001f0410fb04d280f857c0200004d29e74939df488b4c24', 93733389: '48ff4508488b04244889410848c70103000000eba0', 93733500: '4c897d084929df48c701020000004c897908', 94201189: '488b44241048c7030100000048c743080100000048894310'}
def valid(d):
 return all(d[x-0x1000:x-0x1000+len(bytes.fromhex(v))]==bytes.fromhex(v) for x,v in A.items()) and 0x937a10+struct.unpack_from("<i",d,0x937a18)[0]==0x59d6565
assert valid(b)
for x in list(A)+[0x937a18+0x1000]:
 d=bytearray(b);d[x-0x1000]^=1
 assert not valid(d)
print("OK: six instruction spans, dispatch entry, seven corruption controls")
