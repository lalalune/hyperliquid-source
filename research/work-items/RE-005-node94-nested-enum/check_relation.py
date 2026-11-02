"""Independent whole-caller protocol/map parser; never a CPU interpreter.

No oracle imports or constructors are used. The map parser reuses credited
MIT1779/1853 mathematics; the actual u32 selector, outer fields, third-arm
limit and whole-caller state/ownership projection are composed here.
"""
from pathlib import Path
import gzip,hashlib,json,sys
B=Path(__file__).resolve().parent
SOURCE=B/'expectations.jsonl.gz'
META=B/'FROZEN.json'
U=(1<<64)-1

def cell(offset,value,width=8):return {'offset':offset,'hex':value.to_bytes(width,'little').hex()}

class DecodeError(Exception):
    def __init__(self,kind,**fields):self.record={'kind':kind,**fields}

class State:
    def __init__(self,inp,wrong):
        if inp['mode']!=1 or inp['limit']!=1000 or not 0<=inp['charge']<=1000:raise ValueError('Selected domain')
        self.data=bytes.fromhex(inp['dataHex']);self.pos=0;self.c=inp['charge'];self.stores=[];self.wrong=wrong
    def charge(self,n):
        if self.c+n>U:raise DecodeError(2)
        self.c+=n;self.stores.append(self.c)
        if self.c>1000:raise DecodeError(2)
    def raw(self,n):
        available=len(self.data)-self.pos
        if available<n:
            if (n==20 and self.wrong=='consume-short-key') or (n==32 and self.wrong=='consume-short-fixed32'):
                self.pos+=available
            raise DecodeError(0,needed=n-available)
        out=self.data[self.pos:self.pos+n];self.pos+=n;return out
    def integer(self,bits=64,family='map'):
        available=len(self.data)-self.pos
        if not available:raise DecodeError(0,needed=1)
        marker=self.data[self.pos]
        if marker<=250:self.pos+=1;return marker
        allowed={251:2,252:4}
        if bits==64 or self.wrong=='u32-accept-FD-as-u64':allowed[253]=8
        payload=allowed.get(marker)
        if payload is None:
            threshold=8 if bits==64 or self.wrong=='u32-fast-threshold8' else 4
            fast=available>threshold
            if not fast or self.wrong=='consume-fast-bad-marker':self.pos+=1
            expected=2 if family=='selector' else 5 if family=='record' else 2 if fast else 3
            if family=='selector' and self.wrong=='u32-use-map-slow-expected3' and not fast:expected=3
            if family=='record' and self.wrong=='record-use-map-expected':expected=2 if fast else 3
            if family=='map' and self.wrong=='always-fast-error-type':expected=2
            raise DecodeError(3,expected=expected,found={253:3,254:4,255:12}[marker])
        self.pos+=1
        if len(self.data)-self.pos<payload:raise DecodeError(0,needed=payload-(len(self.data)-self.pos))
        value=int.from_bytes(self.raw(payload),'little')
        if self.wrong=='reject-nonminimal-width' and (value<251 or payload==4 and value<65536 or payload==8 and value<1<<32):
            raise DecodeError(3,expected=2,found=3)
        return value
    def paired(self):
        values=[]
        for _ in range(2):
            self.charge(32)
            for _ in range(4):values.append(self.integer())
        self.charge(1);return values,self.raw(1)[0]

def relation(inp,wrong=None):
    s=State(inp,wrong);leaves=[[],[]];allocated=[False,False]
    allocations=[];releases=[];comparisons=[];movements=[];first_done=False;prefix=None;failure=None;tag=None
    def keyorder(key):
        if wrong=='signed-key-order':return bytes(b^128 for b in key)
        if wrong=='little-endian-key-order':return int.from_bytes(key,'little')
        return key
    def release(j):
        if allocated[j]:releases.append({'symbol':'map'+str(j),'bytes':1024,'flags':0})
    def decode_map(j):
        symbol='map'+str(j);leaf=leaves[j]
        if j==1 and wrong=='reset-second-counter':s.c=inp['charge']+36
        s.charge(8);attempts=s.integer();product=attempts*(85 if wrong=='reserve85' else 96);total=s.c+product
        if product>U or total>U:
            if wrong=='store-reservation-overflow':s.c=total&U;s.stores.append(s.c)
            raise DecodeError(2)
        if wrong=='test-reservation-limit-before-store' and total>1000:raise DecodeError(2)
        s.c=total
        if not(wrong=='omit-empty-reservation-store' and not attempts):s.stores.append(total)
        if total>1000:raise DecodeError(2)
        try:
            for _ in range(attempts):
                refund=0 if wrong=='omit-refund' else 85 if wrong=='refund85' else 96
                if s.c<refund:raise DecodeError(2)
                s.c-=refund;s.stores.append(s.c)
                if wrong=='allocate-before-whole-entry' and not allocated[j]:
                    allocated[j]=True;allocations.append({'symbol':symbol,'bytes':1024})
                s.charge(20);key=s.raw(20);words,last=s.paired();index=0
                while index<len(leaf):
                    existing=leaf[index][0]
                    comparisons.append({'map':symbol,'leftKeyHex':key.hex(),'rightKeyHex':existing.hex(),'bytes':20})
                    if keyorder(key)<=keyorder(existing):break
                    index+=1
                duplicate=index<len(leaf) and key==leaf[index][0]
                if duplicate:
                    if wrong!='first-duplicate-value-wins':leaf[index]=(key,words,last)
                    if wrong=='stop-on-first-duplicate':break
                else:
                    if not allocated[j]:allocated[j]=True;allocations.append({'symbol':symbol,'bytes':1024})
                    elif index<len(leaf):
                        count=len(leaf)-index;stride=65 if wrong=='move65-byte-values' else 72
                        movements.extend([
                          {'symbol':symbol,'sourceOffset':800+20*index,'destinationOffset':800+20*(index+1),'bytes':20*count},
                          {'symbol':symbol,'sourceOffset':8+stride*index,'destinationOffset':8+stride*(index+1),'bytes':stride*count}])
                    leaf.insert(index,(key,words,last))
        except DecodeError:
            release(j)
            raise
    try:
        if wrong!='omit-selector-charge':s.charge(4)
        tag=s.integer(32,'selector')
        if tag>2:raise DecodeError(5,tag=tag)
        if wrong=='reset-child-counter':s.c=0
        if tag in (0,1):
            if wrong!='omit-fixed32-charge':s.charge(32)
            prefix=s.raw(32);decode_map(0)
            if tag==1:
                first_done=True;decode_map(1)
        else:
            for _ in range(2):s.charge(8);s.integer(64,'record')
            if wrong=='allocate-unreachable-tag2-box':allocations.append({'symbol':'box','bytes':0x1830})
            if wrong!='read-tag2-array-before-charge':s.charge(2048)
            s.raw(2048)
            raise ValueError('Selected tag2 success is unreachable')
    except DecodeError as e:
        failure=e.record
        if first_done and wrong!='omit-first-map-cleanup':release(0)
    maps=[]
    if failure is not None:
        kind=failure['kind'];out=[cell(0,8 if wrong=='outer-error8' else 3),cell(8,kind,1)]
        if kind==0:out.append(cell(16,failure['needed']))
        if kind==3:out.extend([cell(9,failure['expected'],1),cell(10,failure['found'],1)])
        if kind==5:
            out.extend([cell(12,failure['tag'],4),{'offset':16,'symbol':'literal:GreetingHash@3e635f'},
                        cell(24,12),{'offset':32,'symbol':'range:0..2@209410'}])
            if wrong=='unknown-tag-use-range-as-literal':out[3]['symbol']='range:0..2@209410'
            if wrong=='unknown-tag-length11':out[4]=cell(24,11)
            if wrong=='unknown-tag-truncate-u8':out[2]=cell(12,failure['tag']&255,4)
        if wrong=='rollback-error-charge':s.c=inp['charge'];s.stores=[]
        if wrong=='rollback-error-input':s.pos=0
        if wrong=='first-free-before-second':releases.sort(key=lambda x:x['symbol'])
        if wrong=='return-partial-maps':maps=[list(leaf) for leaf in leaves]
    else:
        out=[cell(0,0 if wrong=='tag1-retain-child-success0' else tag),
             {'offset':8,'hex':(prefix[::-1] if wrong=='reverse-fixed32-output' else prefix).hex()}]
        for j in range(tag+1):
            k=1-j if tag==1 and wrong=='swap-map-fields' else j;selected=leaves[k];offset=40+24*j
            out.append({'offset':offset,'symbol':'map'+str(k)} if allocated[k] else cell(offset,0))
            if allocated[k] or wrong=='initialize-empty-height':out.append(cell(offset+8,0))
            out.append(cell(offset+16,len(selected)))
            maps.append([{'keyHex':key.hex(),'words':words,'byte':last} for key,words,last in selected])
        if wrong=='release-success-maps':
            for j in reversed(range(tag+1)):release(j)
        if wrong=='share-map-keyspace' and tag==1:
            merged={x['keyHex']:x for group in maps for x in group};maps=[list(merged.values())]*2
    return {'charge':s.c,'stores':s.stores,'consumed':s.pos,'remainingHex':s.data[s.pos:].hex(),
      'cells':out,'maps':maps,'allocationRequests':allocations,'releaseRequests':releases,
      'comparisons':comparisons,'movements':movements}

wrong_rules=['reserve85','store-reservation-overflow','test-reservation-limit-before-store',
 'omit-empty-reservation-store','omit-refund','refund85','first-duplicate-value-wins',
 'signed-key-order','little-endian-key-order','move65-byte-values','allocate-before-whole-entry',
 'initialize-empty-height','rollback-error-charge','consume-short-key','consume-fast-bad-marker',
 'always-fast-error-type','stop-on-first-duplicate','reset-second-counter','omit-fixed32-charge',
 'consume-short-fixed32','reverse-fixed32-output','omit-first-map-cleanup','first-free-before-second',
 'return-partial-maps','rollback-error-input','swap-map-fields','release-success-maps','share-map-keyspace',
 'omit-selector-charge','reset-child-counter','u32-accept-FD-as-u64','u32-fast-threshold8',
 'u32-use-map-slow-expected3','record-use-map-expected','reject-nonminimal-width','outer-error8',
 'tag1-retain-child-success0','unknown-tag-use-range-as-literal','unknown-tag-length11','unknown-tag-truncate-u8',
 'allocate-unreachable-tag2-box','read-tag2-array-before-charge']

if __name__=='__main__':
    meta=json.loads(META.read_bytes());compressed=SOURCE.read_bytes()
    if hashlib.sha256(compressed).hexdigest()!=meta['compressedSha256']:raise ValueError('Frozen compressed identity')
    raw=gzip.decompress(compressed)
    if hashlib.sha256(raw).hexdigest()!=meta['uncompressedSha256']:raise ValueError('Frozen plain identity')
    frozen=[json.loads(line) for line in raw.splitlines()]
    if len(frozen)!=meta['cases']:raise ValueError('Frozen count')
    mismatches={w:0 for w in wrong_rules};counts={}
    for j,row in enumerate(frozen):
        if row['id']!=str(j):raise ValueError('Frozen ordering')
        inp=row['input'];expected=row['expected'];observed=relation(inp)
        if observed!=expected:raise ValueError('Enum mathematics mismatch '+str(j)+' '+json.dumps({'input':inp,'expected':expected,'observed':observed}))
        counts[row['category']]=counts.get(row['category'],0)+1
        for wrong in wrong_rules:
            try:different=relation(inp,wrong)!=expected
            except ValueError:different=True
            if different:mismatches[wrong]+=1
    if counts!=meta['categories'] or not all(mismatches.values()):raise ValueError('Ineffective control or denominator '+json.dumps(mismatches))
    result={'state':'actual-nested-enum-mathematical-relation-unqualified','cases':len(frozen),'categories':counts,
      'frozenSha256':meta['compressedSha256'],'wrongRules':mismatches,'capturedExecution':False,
      'instructionEvaluation':False,'nativeEquivalence':False,'networkOperations':0,
      'domain':'Stable mode1/L1000/C at actual255eba0 entry0..1000, valid disjoint input/output/state/stack/heap and ordinary preserving helpers.',
      'scope':'Actual u32 selector/errors/unknown diagnostics, tag0/1 layout and shared reservation bounds, ordered child cleanup, tag2 leading words/array charge and box exclusion. Credited schema/children; no CPU execution/nativeABI/whole greeting/component gate.'}
    out=Path(sys.argv[1])
    if out.exists():raise ValueError('Preserve relation receipt')
    out.write_text(json.dumps(result,sort_keys=True,indent=2)+'\n',encoding='utf-8',newline='\n')
    print(json.dumps(result,sort_keys=True))
