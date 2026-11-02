"""Aggregate-field specification checked against independently prefrozen values.

No captured instructions, registers or hash digest are evaluated.
"""
from pathlib import Path
import gzip,hashlib,json,struct,sys
B=Path(__file__).resolve().parent
SOURCE=B/'expectations.jsonl.gz'
META=B/'FROZEN.json'

def key(i,wrong=None):
    a=i['address']&0xffffffff;p=i['port']&0xffff;d=i['direction']&255
    packed=a|(p<<32)|(d<<48)
    requests=[struct.pack('<Q',d),struct.pack('<I',a),struct.pack('>H' if wrong=='hash-big-port' else '<H',p)]
    if wrong=='hash-packed-key':requests=[struct.pack('<Q',packed)]
    if wrong=='hash-address-first':requests=requests[1:2]+requests[:1]+requests[2:]
    if wrong=='hash-one-byte-selector':requests[0]=bytes([d])
    return {'packedKeyHex':struct.pack('<Q',packed).hex(),'hashUpdateHex':[x.hex() for x in requests],
            'hashUpdateWidths':[len(x) for x in requests]}

def candidate(i,wrong=None):
    q=bytes.fromhex(i['queryHex']);e=bytes.fromhex(i['entryHex'])
    qword=int.from_bytes(q,'little');eword=int.from_bytes(e,'little')
    masks={'ignore-address':0x00ffffff00000000,'ignore-port':0x00ff0000ffffffff,
           'ignore-selector':0x0000ffffffffffff,'compare-padding':0xffffffffffffffff}
    mask=masks.get(wrong,0x00ffffffffffffff)
    match=(qword&mask)==(eword&mask)
    if wrong=='fingerprint-only':match=True
    return {'eligibleExactKey':i['control']==i['fingerprint'] and match}

def clone(i,wrong=None):
    before=i['counts'];after=list(before);n=0;failed=False
    for index in range(3):
        value=before[index]+1
        if wrong!='no-wrap':value&=0xffffffffffffffff
        after[index]=value;n+=1
        if value==0 or value&(1<<63):
            failed=True
            if wrong!='increment-after-abort':break
    return {'countsAfter':after,'increments':n,'outputWritten':not failed or wrong=='output-on-abort','aborted':failed}

def handle(i,wrong=None):
    traffic=i['pool']=='traffic';hit=i['hit']
    resources=list(i['existingResources'] if hit else i['freshResources'])
    sizes=[] if hit else ([24,24,40] if traffic else [24,24,24])
    if wrong=='small-traffic-tail' and traffic and not hit:sizes[-1]=24
    stamp=traffic and not hit
    if wrong=='timestamp-on-hit' and traffic and hit:stamp=True
    if wrong=='timestamp-on-lz4' and not traffic:stamp=True
    cells=[]
    if not hit:
        for index,resource in enumerate(resources):
            cell={'resource':resource,'header0':1,'header1':0 if wrong=='zero-second-header' else 1,'data0':0}
            if traffic and index==2:cell.update(clockPair=list(i['clockPair']))
            cells.append(cell)
    result={'resources':resources,'allocationSizes':sizes,'timestampRequests':int(stamp),'initialCells':cells}
    if not traffic:
        use_cached=hit and wrong!='rebuild-cached-tail'
        result['returnedPort']=i['cachedPort'] if use_cached else i['port']
        result['returnedDirection']=i['cachedDirection'] if use_cached else i['direction']
    return result

def constructor(i,wrong=None):
    address=i['address'];port=i['port'];h=i['handles']
    requests=[[pool,d,address,port] for pool in ['traffic','lz4'] for d in [0,1]]
    if wrong=='one-registry':requests=[['traffic',x[1],x[2],x[3]] for x in requests]
    regions=[{'offset':0,'hex':i['registrationHex']}]
    layout=[('lz40',0x20),('lz41',0x40),('traffic0',0x60),('traffic1',0x78)]
    for label,offset in layout:
        selected=label
        if wrong=='swap-directions':selected=label[:-1]+str(1-int(label[-1]))
        values=h[selected]
        raw=struct.pack('<QQQ',*values[:3])
        if label.startswith('lz4'):raw+=struct.pack('<HB',*values[3:])
        if wrong=='wrong-placement' and label=='traffic0':offset=0x58
        regions.append({'offset':offset,'hex':raw.hex()})
    regions.append({'offset':0x90,'hex':struct.pack('<H',port).hex()})
    undefined=[[0x3b,5],[0x5b,5],[0x92,6]]
    if wrong=='claim-padding-zero':undefined=[]
    if wrong=='drop-registration':regions=regions[1:]
    return {'requests':requests,'definedRegions':regions,'undefinedWithin152':undefined}

functions={'key-request':key,'candidate-key':candidate,'clone-projection':clone,
           'handle-fields':handle,'constructor-fields':constructor}
wrongs={'key-request':['hash-big-port','hash-packed-key','hash-address-first','hash-one-byte-selector'],
 'candidate-key':['ignore-address','ignore-port','ignore-selector','compare-padding','fingerprint-only'],
 'clone-projection':['no-wrap','increment-after-abort','output-on-abort'],
 'handle-fields':['small-traffic-tail','timestamp-on-hit','timestamp-on-lz4','zero-second-header','rebuild-cached-tail'],
 'constructor-fields':['one-registry','swap-directions','wrong-placement','claim-padding-zero','drop-registration']}
meta=json.loads(META.read_bytes());raw=SOURCE.read_bytes()
if hashlib.sha256(raw).hexdigest()!=meta['compressedSha256']:raise ValueError('Frozen compressed identity')
data=gzip.decompress(raw)
if hashlib.sha256(data).hexdigest()!=meta['uncompressedSha256']:raise ValueError('Frozen values differ')
rows=[json.loads(x) for x in data.splitlines()]
if len(rows)!=meta['cases']:raise ValueError('Frozen denominator differs')
counts={k:0 for k in functions};mutants={w:0 for ws in wrongs.values() for w in ws}
for r in rows:
    f=r['family'];fun=functions[f]
    if fun(r['input'])!=r['expected']:raise ValueError('Independent relation differs '+r['id'])
    counts[f]+=1
    for wrong in wrongs[f]:mutants[wrong]+=fun(r['input'],wrong)!=r['expected']
if counts!=meta['families'] or any(x==0 for x in mutants.values()):raise ValueError('Incomplete or neutral wrong rules')
receipt={'state':'stream-stat-abstract-relation-check-unqualified','cases':counts,'wrongRules':mutants,
 'frozenSha256':meta['compressedSha256'],'capturedExecution':False,'instructionEvaluation':False,
 'networkOperations':0,'nativeEquivalence':False,'hashOutputsInvented':False,
 'scope':'Key/update request, candidate equality, clone/header and defined constructor fields under manual premises. Synthetic fields are not live memory/allocator/ABI or hash digest output.'}
out=B/sys.argv[1]
if out.exists():raise ValueError('Preserve prior check')
out.write_text(json.dumps(receipt,sort_keys=True,indent=2)+'\n',encoding='utf-8',newline='\n')
print(json.dumps(receipt,sort_keys=True))
