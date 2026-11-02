"""Independent selected-protocol parser, not a captured instruction evaluator."""
from pathlib import Path
import gzip,hashlib,json,struct,sys
B=Path(__file__).resolve().parent
SOURCE=B/'expectations.jsonl.gz'
META=B/'FROZEN.json'
U=(1<<64)-1
def cell(o,v,n=8):return {'offset':o,'hex':struct.pack('<B' if n==1 else '<Q',v).hex()}
def errors(e):
    k=e['kind'];out=[cell(0,1),cell(8,k,1)]
    if k==0:out.append(cell(16,e['needed']))
    if k==3:out.extend([cell(9,e['expected'],1),cell(10,e['found'],1)])
    return out
def read_integer(data,pos,wrong=None):
    available=len(data)-pos
    if not available:return None,pos,{'kind':0,'needed':1}
    marker=data[pos]
    if marker<251:return marker,pos+1,None
    widths={251:2,252:4,253:8}
    if marker not in widths:
        fast=available>8
        consumed=0 if fast else 1
        if wrong=='consume-fast-rejected-marker':consumed=1
        expected=2 if fast else 3
        if wrong=='always-fast-error-kind':expected=2
        return None,pos+consumed,{'kind':3,'expected':expected,'found':4 if marker==254 else 12}
    width=widths[marker]
    if available<=width:
        consumed=available if wrong=='consume-short-extension' else 1
        return None,pos+consumed,{'kind':0,'needed':width+1-available}
    value=int.from_bytes(data[pos+1:pos+1+width],'little')
    return value,pos+1+width,None
def relation(family,inp,wrong=None):
    data=bytes.fromhex(inp['dataHex']);c=inp['charge'];limit=inp['limit'];pos=0;stores=[];words=[]
    def finish(e=None):
        count=c;trace=stores[:]
        if e and wrong=='rollback-charge-on-error':count=inp['charge'];trace=[]
        if e:out=errors(e)
        else:
            order=words[:]
            if wrong=='reverse-four-word-order':
                order=[v for j in range(0,len(order),4) for v in reversed(order[j:j+4])]
            if wrong=='swap-paired-blocks' and family=='paired-value':order=order[4:]+order[:4]
            if wrong=='truncate-first-high-bits':order[0]&=255
            out=[cell(0,0)]+[cell(8+8*j,v) for j,v in enumerate(order)]
            if family=='paired-value':out.append(cell(72,last,1))
            if wrong=='require-whole-input' and pos<len(data):out=errors({'kind':2})
        return {'charge':count,'stores':trace,'consumed':pos,'remainingHex':data[pos:].hex(),'cells':out}
    def charge(amount):
        nonlocal c
        if c>U-amount:return False
        c+=amount;stores.append(c)
        return c<=limit
    blocks=1 if family=='four-word' else 2
    for block in range(blocks):
        if wrong=='empty-before-charge' and pos==len(data):return finish({'kind':0,'needed':1})
        if wrong!='eight-per-word-charge' and not charge(32):return finish({'kind':2})
        for _ in range(4):
            if wrong=='eight-per-word-charge' and not charge(8):return finish({'kind':2})
            if wrong=='raw-eight-byte-words':
                n=len(data)-pos
                if n<8:return finish({'kind':0,'needed':8-n})
                value=int.from_bytes(data[pos:pos+8],'little');pos+=8;e=None
            else:value,pos,e=read_integer(data,pos,wrong)
            if e:return finish(e)
            words.append(value)
    if family=='paired-value':
        if wrong=='byte-input-before-charge' and pos==len(data):return finish({'kind':0,'needed':1})
        if wrong!='omit-final-byte-charge' and not charge(1):return finish({'kind':2})
        if pos==len(data):return finish({'kind':0,'needed':1})
        last=data[pos];pos+=1
        if wrong=='validate-final-byte-as-bool' and last>1:return finish({'kind':2})
    return finish()
wrong_rules=['eight-per-word-charge','raw-eight-byte-words','rollback-charge-on-error',
    'consume-short-extension','always-fast-error-kind','consume-fast-rejected-marker',
    'reverse-four-word-order','swap-paired-blocks','truncate-first-high-bits',
    'require-whole-input','empty-before-charge','byte-input-before-charge',
    'omit-final-byte-charge','validate-final-byte-as-bool']
meta=json.loads(META.read_bytes());compressed=SOURCE.read_bytes()
if hashlib.sha256(compressed).hexdigest()!=meta['compressedSha256']:raise ValueError('Frozen compressed identity')
raw=gzip.decompress(compressed)
if hashlib.sha256(raw).hexdigest()!=meta['uncompressedSha256']:raise ValueError('Frozen plain identity')
rows=[json.loads(line) for line in raw.splitlines()]
if len(rows)!=meta['cases']:raise ValueError('Frozen count')
counts={};mismatches={w:0 for w in wrong_rules}
for j,row in enumerate(rows):
    if row['id']!=str(j):raise ValueError('Frozen row ordering')
    f=row['family'];i=row['input'];expected=row['expected']
    if relation(f,i)!=expected:raise ValueError('Mathematical relation mismatch '+str(j))
    counts[f]=counts.get(f,0)+1
    for w in wrong_rules:
        if relation(f,i,w)!=expected:mismatches[w]+=1
if counts!=meta['families'] or not all(mismatches.values()):raise ValueError('Ineffective control or denominator')
result={'state':'greeting-value-mathematical-relation-unqualified','cases':counts,
    'frozenSha256':meta['compressedSha256'],'wrongRules':mismatches,
    'capturedExecution':False,'instructionEvaluation':False,'nativeEquivalence':False,
    'networkOperations':0,'modeDomain':'QWORD exactly1',
    'scope':'Four-word and paired-value charge/cursor/active-cell composition; generic scalar grammar is credited context. No raw other-mode, source type, native ABI or full map/connection claim.'}
out=Path(sys.argv[1])
if out.exists():raise ValueError('Preserve prior relation receipt')
out.write_text(json.dumps(result,sort_keys=True,indent=2)+'\n',encoding='utf-8',newline='\n')
print(json.dumps(result,sort_keys=True))
