"""Read-only independent byte-preimage/decimal-value check; no target execution."""
from pathlib import Path
import gzip,hashlib,json,struct
root=Path(__file__).resolve().parents[3]
p=root/'research/work-items/RE-004-three-digit-parser-rust-94'
sha=lambda raw:hashlib.sha256(raw).hexdigest()
def require(ok,message):
    if not ok:raise ValueError(message)
data=(root/'artifacts/node/94/hl-node').read_bytes()
require(sha(data)=='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f','target SHA')
require(data[:6]==b'\x7fELF\x02\x01','ELF64 LE')
phoff=struct.unpack_from('<Q',data,32)[0];entsize,num=struct.unpack_from('<HH',data,54)
require(entsize==56,'program header size')
segments=[struct.unpack_from('<IIQQQQQQ',data,phoff+i*56) for i in range(num)]
def read(va,n):
    matches=[s for s in segments if s[0]==1 and s[3]<=va and va+n<=s[3]+s[5]]
    require(len(matches)==1,'unique file backed PT_LOAD')
    s=matches[0];offset=s[2]+va-s[3];return data[offset:offset+n]
body=read(0x1683670,85)
require(sha(body)=='90c7bd6c996890a0c04b23ee47ff7aa6bdb911997e320fdb6989e741a090abca','full body')
require(body[0:6]==bytes.fromhex('4883fe037530'),'full64 length compare and closed branch')
require(body[6:13]==bytes.fromhex('0fb60f0fb64701') and body[15:19]==bytes.fromhex('0fb65702'),'all three load operands precede digit decisions')
require(body[13:15]==bytes.fromhex('04d0') and body[19:22]==bytes.fromhex('80c2d0'),'two byte biases')
require(body[22:29]==bytes.fromhex('8d71c64080fef7'),'leading byte bias/threshold')
require(body[33:35]==bytes.fromhex('3c0a') and body[39:42]==bytes.fromhex('80fa0a'),'last two thresholds')
# Enumerate each mathematical byte preimage from the actual immediate bytes.
# No register/flag instruction interpreter is used.
a_set={v for v in range(256) if (v+body[24])%256>=body[28]}
b_set={v for v in range(256) if (v+body[14])%256<body[34]}
c_set={v for v in range(256) if (v+body[21])%256<body[41]}
require(a_set==set(range(49,58)) and b_set==c_set==set(range(48,58)),'exact byte preimages')
require(len(a_set)*len(b_set)*len(c_set)==900,'accepted language size')
inputs=gzip.decompress((p/'inputs.bin.gz').read_bytes());expected=gzip.decompress((p/'expected.bin.gz').read_bytes())
require(len(inputs)%24==0 and len(expected)==len(inputs)//24*16,'fixture framing')
actual=bytearray();counts={'length_rejections':0,'safe_refusals':0,'invalid_triples':0,'valid_triples':0};accepted=set()
for row in struct.iter_unpack('<3Q',inputs):
    length,available,packed=row;require(available<=4 and packed<2**32,'fixture descriptor')
    status,value=0,0
    if length!=3:counts['length_rejections']+=1
    elif available<3:status=1;counts['safe_refusals']+=1
    else:
        triple=packed.to_bytes(4,'little')[:3]
        if triple[0] in a_set and triple[1] in b_set and triple[2] in c_set:
            # Python's decimal conversion supplies values independently of
            # the frozen string dictionary and Rust's explicit weighted sum.
            value=int(triple.decode('ascii'),10);counts['valid_triples']+=1;accepted.add(triple)
        else:counts['invalid_triples']+=1
    actual.extend(struct.pack('<2Q',status,value))
require(actual==expected,'all frozen status/full-RAX outputs')
require(len(accepted)==900,'all accepted words observed')
source=root/'src/node94-three-digit-parser/lib.rs';proof=p/'PROOF.md';caller=read(0x1682220,0x1682735-0x1682220)
require(len(caller)==1301 and sha(caller)=='a1a34984f457e4413ab96820190afa549708a6c14a7eb9ca0715a5d65a7b078b','full caller raw bytes')
edge=read(0x1682606,5);require(edge[0]==0xe8 and 0x168260b+int.from_bytes(edge[1:],'little',signed=True)==0x1683670,'direct edge')
result={'result':'PASS','cases':len(inputs)//24,'coverage':counts,'byte_preimages':[sorted(s) for s in (a_set,b_set,c_set)],'distinct_accepted_words':len(accepted),'source_sha256':sha(source.read_bytes()),'proof_sha256':sha(proof.read_bytes()),'oracle_sha256':sha((p/'oracle.py').read_bytes()),'inputs_sha256':sha(inputs),'expected_sha256':sha(expected),'independent_output_sha256':sha(actual),'manual_segment_mapping':True,'leaf_bytes':85,'caller_bytes':1301,'captured_execution':False,'instruction_emulation':False,'native_execution':False,'review':'Full source, proof, raw parser instructions and input-only driver reviewed; no blocker.'}
print(json.dumps(result,indent=2))
