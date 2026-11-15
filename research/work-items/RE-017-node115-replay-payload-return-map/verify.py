import hashlib, struct
from pathlib import Path

p=Path("artifacts/node/115/hl-node")
b=p.read_bytes()
assert hashlib.sha256(b).hexdigest()=="a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
ANCHORS = {94924669: '488dbc2410230000488db3c8010000488b1424e88bf5f4ff4c8ba424102300004983fc02', 94924908: '488b8c2418230000488b842420230000', 94201120: '4156534883ec184889fb488b064c8d4608488b0a488d7c24084889c64c89c2e89cdbf8ff488b442408488d0dc014f6fa486304814801c8ffe0', 94201218: '4c8b74241041837e08017537498b4e10498b46184885c97433f048ff010f8e800000004885c07406f048ff007e7531d2eb2448c7030100000048c7430800000000eb48ba0100000031c9eb0af048ff007e5131d231c948891348894b0848894310'}

def valid(data):
    if any(data[a-0x1000:a-0x1000+len(bytes.fromhex(h))] != bytes.fromhex(h) for a,h in ANCHORS.items()): return False
    return [0x937a10+struct.unpack_from("<i",data,0x937a10+4*i)[0] for i in range(4)] == [0x59d6559,0x59d65b4,0x59d6565,0x59d6582]
assert valid(b)
for a in list(ANCHORS)+[0x937a10+0x1000]:
    changed=bytearray(b); changed[a-0x1000] ^= 1
    assert not valid(changed)
print("OK: four instruction anchors, four dispatch entries, five corruption controls")
