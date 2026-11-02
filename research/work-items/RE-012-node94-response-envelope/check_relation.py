"""Partial protocol mathematics and conditional response-envelope specification.

No captured instructions, registers or executable code are evaluated.
"""
from pathlib import Path
import gzip,hashlib,json,struct,sys
B=Path(__file__).resolve().parent
SOURCE=B/'expectations.jsonl.gz'
META=B/'FROZEN.json'
def cell(offset,value,size=8):return {'offset':offset,'hex':struct.pack({1:'<B',2:'<H',4:'<I',8:'<Q'}[size],value).hex()}
def reference(offset,va):return {'offset':offset,'ref':'image+'+hex(va),'width':8}
def construct(i,wrong=None):
    a=i['flag'];limit=3000000000 if a else 1000
    if wrong=='readlimit-small':limit=1000
    if wrong=='only-one-enables-large':limit=3000000000 if a==1 else 1000
    if wrong=='length-as-limit':limit=i['length']
    return {'readLimit':limit,'diagnosticFlag':a,'decodeState':{'mode':0 if wrong=='mode-zero' else 1,
      'limit':limit,'pointer':i['pointer'],'remaining':i['length'],
      'charge':i['length'] if wrong=='initial-charge-length' else 0}}
def wrap(i,wrong=None):
    n=i['length'];t=i['resultTag'];r=i['remaining'];c=construct(i,wrong)
    if t!=8 and r>n and wrong!='skip-underflow':
        return {'constructor':c,'diagnosticConsumed':None,'route':'wrapper-underflow',
          'wrapperCells':[],'releaseRequests':[],'outerCells':[]}
    consumed=0 if t==8 else (n-r)&((1<<64)-1)
    if wrong=='error-cursor-as-diagnostic' and t==8:consumed=(n-r)&((1<<64)-1)
    if wrong=='charge-as-consumption' and t!=8:consumed=i.get('logicalCharge',4)
    cells=i['responseCells'];release=[[i['pointer'],i['capacity'],0]] if i['capacity'] else []
    if wrong=='skip-error-release' and t==8:release=[]
    route='caller-error-conversion' if t==8 else 'return'
    if wrong=='reject-suffix' and t!=8 and r:route='caller-error-conversion'
    if wrong=='zero-inactive':cells=cells+[cell(112,0)]
    outer=[]
    if route=='return':
        outer=[dict(x,offset=x['offset']+(8 if wrong=='shift-response' else 0)) for x in cells]
        shift=112 if wrong=='stream-at-112' else 120
        outer += [cell(shift,0)]+[dict(x,offset=x['offset']+shift) for x in i['streamCells']]
    return {'constructor':c,'diagnosticConsumed':consumed,'route':route,'wrapperCells':cells,
            'releaseRequests':release,'outerCells':outer}
def integer(raw,pos,width):
    n=len(raw)-pos
    if not n:return None,pos,{'kind':0,'needed':1}
    marker=raw[pos];fast=n>width
    if marker<251:return marker,pos+1,None
    accepted={251:2,252:4}
    if width==8:accepted[253]=8
    if marker not in accepted:
        return None,pos+(0 if fast else 1),{'kind':3,'expected':2 if width==4 or fast else 3,
                                               'found':{253:3,254:4,255:12}[marker]}
    size=accepted[marker];total=size+1
    if n<total:return None,pos+1,{'kind':0,'needed':total-n}
    return int.from_bytes(raw[pos+1:pos+total],'little'),pos+total,None
def error_cells(e):
    k=e['kind'];out=[cell(0,8),cell(8,k,1)]
    if k==0:out.append(cell(16,e['needed']))
    if k==3:out += [cell(9,e['expected'],1),cell(10,e['found'],1)]
    if k==5:out += [cell(12,e['value'],4),reference(16,0x3e63d4),cell(24,18),reference(32,0x203580)]
    return out
class OutsideSelectedDomain(ValueError):pass
def simple(i,wrong=None):
    raw=bytes.fromhex(i['dataHex']);value,pos,error=integer(raw,0,4);charge=4
    if error:tag=8;cells=error_cells(error)
    elif value==0:raise OutsideSelectedDomain('Vector/hash selector0 is outside this byte model')
    elif value>5:tag=8;cells=error_cells({'kind':5,'value':value})
    elif value>=2:
        tag=value+2;cells=[cell(0,tag)]
        if wrong=='reject-unit-response':tag=8;cells=error_cells({'kind':5,'value':value})
    else:
        vals=[]
        for _ in range(3):
            charge+=8;v,pos,error=integer(raw,pos,8)
            if error:break
            vals.append(v)
        if error:tag=8;cells=error_cells(error)
        else:
            tag=3;order=vals if wrong=='triplet-source-order' else [vals[1],vals[2],vals[0]]
            cells=[cell(0,3)]+[cell(8*(j+1),v) for j,v in enumerate(order)]
    envelope_input={'flag':i['flag'],'length':len(raw),'capacity':i['capacity'],'pointer':i['pointer'],
      'resultTag':tag,'remaining':len(raw)-pos,'responseCells':cells,'streamCells':i['streamCells'],'logicalCharge':charge}
    return {'logicalCharge':charge,'innerConsumed':pos,'remainingHex':raw[pos:].hex(),
      'decoderCells':cells,'envelope':wrap(envelope_input,wrong)}
functions={'constructor':construct,'envelope':wrap,'simple-response':simple}
constructor_wrongs=['readlimit-small','only-one-enables-large','length-as-limit','mode-zero','initial-charge-length']
envelope_wrongs=['error-cursor-as-diagnostic','charge-as-consumption','skip-error-release','skip-underflow',
 'reject-suffix','zero-inactive','shift-response','stream-at-112']
wrongs={'constructor':constructor_wrongs,'envelope':envelope_wrongs,
 'simple-response':['triplet-source-order','reject-unit-response']}
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
# This is a model scope guard, not another successful target comparison.
try:simple({'flag':0,'dataHex':'00','capacity':1,'pointer':1,'streamCells':[]})
except OutsideSelectedDomain:pass
else:raise ValueError('Opaque selector0 silently invented')
receipt={'state':'response-abstract-relation-check-unqualified','cases':counts,'wrongRules':mutants,
 'frozenSha256':meta['compressedSha256'],'selector0ByteModelExcluded':True,
 'capturedExecution':False,'instructionEvaluation':False,'networkOperations':0,'nativeEquivalence':False,
 'scope':'Actual constructor, conditional defined result, diagnostic consumption and selected simple reply composition; scalar/schema facts credited. No original ABI/validity, full selector0 parsing or actual I/O claim.'}
out=B/sys.argv[1]
if out.exists():raise ValueError('Preserve prior check')
out.write_text(json.dumps(receipt,sort_keys=True,indent=2)+'\n',encoding='utf-8',newline='\n')
print(json.dumps(receipt,sort_keys=True))
