import hashlib,struct
from pathlib import Path
b=Path("artifacts/node/115/hl-node").read_bytes()
assert hashlib.sha256(b).hexdigest()=="a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
A={46592196: '4883fa010f858b000000488b86a00000004939c60f8340010000', 46592345: '48b94b598638d6c56d344c89f048f7e14989d449c1ec0b4c3ba6d00700000f83b40000004c8baec80700004969ec10050000', 46592409: '41bf010000004d3b642d50754c4969c4102700004929c64901ed4d3b75107339498b450849c1e6054e8b6430104d85e474274e8b7430084c89e7ff15a70287034885c0747e4989c74889c74c89f64c89e2ff1518038703eb034531e44c89234c897b084c8963104889d84883c4785b415c41', 46591163: '4989f64889fb4883fa017533498bb6c8', 46591226: '4889cf4c89f64989cce898f4afff4989c748b94b598638d6c56d344c89e048f7e148c1ea0b493b96d007000073494c69e2100500004d03a6c8070000'}
def edge(d,s,t):return s+5+struct.unpack_from("<i",d,s+1-0x1000)[0]==t
def valid(d):return all(d[x-0x1000:x-0x1000+len(bytes.fromhex(v))]==bytes.fromhex(v) for x,v in A.items()) and edge(d,0x2c6ed03,0x276e1a0)
assert valid(b)
m=0x346dc5d63886594b
assert 10000*m==(1<<75)+432 and 432*((1<<64)-1)<(1<<75)
for n in (0,1,9999,10000,10001,(1<<64)-1):assert (n*m>>75)==n//10000
for x in A:
 d=bytearray(b);d[x-0x1000]^=1
 assert not valid(d)
print("PASS: #115 target digest, 5 spans, 1 direct call, 6 arithmetic examples, 5 mutations")
