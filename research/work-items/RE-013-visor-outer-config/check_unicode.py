"""Finite Unicode arithmetic checks supporting a manual static proof, no native evaluator."""
from pathlib import Path
import json,hashlib,datetime
def standard_formula(cp):
    if cp<0x80:return bytes([cp])
    if cp<0x800:return bytes([0xc0|(cp>>6),0x80|(cp&63)])
    if cp<0x10000:return bytes([0xe0|(cp>>12),0x80|((cp>>6)&63),0x80|(cp&63)])
    return bytes([0xf0|(cp>>18),0x80|((cp>>12)&63),0x80|((cp>>6)&63),0x80|(cp&63)])
for unit in range(65536):
    low=(unit&0xfc00)==0xdc00
    high=((unit+0x2400)&65535)>=0xfc00
    second=((unit+0x2000)&65535)>=0xfc00
    if low!=(0xdc00<=unit<=0xdfff) or high!=(0xd800<=unit<=0xdbff) or second!=(0xdc00<=unit<=0xdfff):
        raise ValueError('Declared surrogate partition differs from independent ranges')
scalar_digest=hashlib.sha256();scalar_count=0
for cp in range(0x110000):
    if 0xd800<=cp<=0xdfff:continue
    expected=chr(cp).encode('utf-8');observed=standard_formula(cp)
    if observed!=expected:raise ValueError('Scalar encoding formula differs from Python Unicode codec')
    scalar_digest.update(cp.to_bytes(4,'little')+observed);scalar_count+=1
pair_digest=hashlib.sha256();pair_count=0
for high in range(0xd800,0xdc00):
    hpart=((high+0x2800)&65535)<<10
    for low in range(0xdc00,0xe000):
        lowpart=(low+0x2400)&65535
        cp=0x10000+hpart+lowpart
        # A closed mathematical packed-byte expression from the manual proof.
        # No register state, captured opcode, branch or execution trace is used.
        packed=((cp>>18)|((cp>>4)&0xff00)|(((hpart|lowpart)<<10)&0xff0000)|((low<<24)&0xffffffff))
        observed=((packed&0x3f3f3fff)|0x808080f0).to_bytes(4,'little')
        expected=chr(0x10000+((high-0xd800)*1024)+(low-0xdc00)).encode('utf-8')
        if observed!=expected:raise ValueError('Packed surrogate-pair formula differs from independent codec')
        pair_digest.update(high.to_bytes(2,'little')+low.to_bytes(2,'little')+observed);pair_count+=1
result={
 'state':'unicode-arithmetic-proof-support-unqualified',
 'surrogateGuardInputs':65536,'scalarChecks':scalar_count,'pairChecks':pair_count,
 'scalarDigest':scalar_digest.hexdigest(),'pairDigest':pair_digest.hexdigest(),
 'scope':'Independent scalar/range/codec comparisons for declared mathematical formulas and the manual packed-byte relation. This program never interprets captured instructions or native state.',
 'limits':['Native input/cursor/read/write/literal/capacity/call bindings and manual proof are separate obligations. No target runtime comparison, ABI, heap/unwind safety or full task gate is established.'],
 'capturedExecution':False,'instructionEvaluation':False,'semanticQualification':False,
}
dest=Path(__import__('sys').argv[1])
if dest.exists():raise ValueError('Preserve existing formula audit')
dest.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n')
print(json.dumps({k:result[k] for k in ['surrogateGuardInputs','scalarChecks','pairChecks','semanticQualification']}))
