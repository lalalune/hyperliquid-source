"""Check an abstract value relation against pre-frozen mathematical records.

This is not a native instruction/register/branch evaluator. It consumes only
synthetic field inputs and never reads or runs the captured node.
"""
from pathlib import Path
import gzip,hashlib,json,struct,sys
B=Path(__file__).resolve().parent
SOURCE=B/'expectations.jsonl.gz'
META=B/'FROZEN.json'
ports=[4001,4002,4003,4004,3998,3999]
def address(i,wrong=None):
    d=i['selector'];b=bytes.fromhex(i['packedHex'])
    q=int.from_bytes(b,'little');host=(q>>8)&0xffffffff
    local=bool(q&1) if wrong!='flag-any' else bool(b[0])
    index=host&255
    offset=1000*index if local else (1000*index if wrong=='remote-offset' else 0)
    if offset>65535:return {'kind':'credited-multiply-panic-no-request'}
    p=ports[d]+offset
    if p>65535:return {'kind':'credited-add-panic-no-request'}
    ip=0x0100007f if local and wrong!='local-server-ip' else host
    ipraw=struct.pack('<I',ip)
    if wrong=='reverse-ip':ipraw=ipraw[::-1]
    frame=struct.pack('<H',2)+struct.pack('<H' if wrong=='little-port' else '>H',p)+ipraw+bytes(8)
    return {'kind':'request','domain':2,'type':0x80801,'protocol':0,'addrlen':16,'frameHex':frame.hex()}
def outcome(i,wrong=None):
    fd,cr,err=i['socketReturn'],i['connectReturn'],i['errno']
    if fd<0:
        return {'tag':1,'errorWord':((err&0xffffffff)<<32)|2,'connectRequests':0,
                'closeRequests':1 if wrong=='close-socket-error' else 0}
    accepted=cr>=0 or (err==115 and wrong!='reject-115')
    if wrong=='accept-114':accepted=cr>=0 or err==114
    if accepted:return {'tag':0,'fd':fd,'connectRequests':1,'closeRequests':1 if wrong=='close-success' else 0}
    return {'tag':1,'errorWord':((err&0xffffffff)<<32)|2,'connectRequests':1,
            'closeRequests':0 if wrong=='leak-failure' else 1,'closeFd':fd}
meta=json.loads(META.read_bytes());raw=SOURCE.read_bytes()
if hashlib.sha256(raw).hexdigest()!=meta['compressedSha256']:raise ValueError('Frozen compressed identity')
data=gzip.decompress(raw)
if hashlib.sha256(data).hexdigest()!=meta['uncompressedSha256']:raise ValueError('Frozen value identity')
rows=[json.loads(l) for l in data.splitlines()]
if len(rows)!=meta['cases']:raise ValueError('Frozen denominator')
mutants={k:0 for k in ['flag-any','remote-offset','local-server-ip','reverse-ip','little-port',
                       'close-socket-error','reject-115','accept-114','close-success','leak-failure']}
counts={'address':0,'result':0}
for r in rows:
    fun=address if r['family']=='address' else outcome
    if fun(r['input'])!=r['expected']:raise ValueError('Independent relation differs '+r['id'])
    counts[r['family']]+=1
    wrongs=list(mutants)[:5] if r['family']=='address' else list(mutants)[5:]
    for w in wrongs:mutants[w]+=fun(r['input'],w)!=r['expected']
if any(v==0 for v in mutants.values()):raise ValueError('Neutral wrong relation')
# Exhaustive16bit byte-order identity has an independent arithmetic expression.
for p in range(65536):
    if struct.pack('>H',p)!=bytes([p//256,p%256]):raise ValueError('Port byte order')
result={'state':'abstract-field-relation-check-unqualified','frozenSha256':meta['compressedSha256'],
 'cases':counts,'wrongRules':mutants,'allU16PortEncodings':65536,
 'capturedExecution':False,'instructionEvaluation':False,'networkOperations':0,'nativeEquivalence':False,
 'limits':'Value/call-request model supports the addressed conditional manual proof only; neither OS calls nor captured CPU code run. No Rust/nativeABI or whole async equivalence.'}
out=B/sys.argv[1]
if out.exists():raise ValueError('Preserve prior check')
out.write_text(json.dumps(result,sort_keys=True,indent=2)+'\n',encoding='utf-8',newline='\n')
print(json.dumps(result,sort_keys=True))
