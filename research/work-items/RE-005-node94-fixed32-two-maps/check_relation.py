"""Independent bounded protocol/map parser, never an instruction evaluator."""
from pathlib import Path
import gzip,hashlib,json,struct,sys
B=Path(__file__).resolve().parent
SOURCE=B/'expectations.jsonl.gz'
META=B/'FROZEN.json'
U=(1<<64)-1

def cell(o,v,n=8):return {'offset':o,'hex':struct.pack('<B' if n==1 else '<Q',v).hex()}
def error_cells(e,wrong):
    kind=e['kind'];out=[cell(0,kind,1)]
    if kind==0:out.append(cell(8,e['needed']))
    if kind==3:out.extend([cell(1,e['expected'],1),cell(2,e['found'],1)])
    if wrong=='retain-paired-outer-error-tag':out=[cell(0,1)]+[dict(c,offset=c['offset']+8) for c in out]
    return out

class DecodeError(Exception):
    def __init__(self,kind,**fields):self.record={'kind':kind,**fields}

class State:
    def __init__(self,inp,wrong):
        if inp['mode']!=1 or inp['limit']!=1000 or not 0<=inp['charge']<=1000:raise ValueError('Selected domain')
        self.data=bytes.fromhex(inp['dataHex']);self.pos=0
        self.c=inp['charge'];self.stores=[];self.wrong=wrong
    def charge(self,n):
        if self.c+n>U:raise DecodeError(2)
        self.c+=n;self.stores.append(self.c)
        if self.c>1000:raise DecodeError(2)
    def raw(self,n):
        remaining=len(self.data)-self.pos
        if remaining<n:
            if self.wrong=='consume-short-key' and n==20:self.pos+=remaining
            raise DecodeError(0,needed=n-remaining)
        out=self.data[self.pos:self.pos+n];self.pos+=n;return out
    def integer(self):
        available=len(self.data)-self.pos
        if not available:raise DecodeError(0,needed=1)
        marker=self.data[self.pos]
        if marker<=250:self.pos+=1;return marker
        payload={251:2,252:4,253:8}.get(marker)
        if payload is None:
            fast=available>=9
            if not fast or self.wrong=='consume-fast-bad-marker':self.pos+=1
            expected=2 if fast or self.wrong=='always-fast-error-type' else 3
            raise DecodeError(3,expected=expected,found=4 if marker==254 else 12)
        self.pos+=1
        if len(self.data)-self.pos<payload:raise DecodeError(0,needed=payload-(len(self.data)-self.pos))
        value=int.from_bytes(self.raw(payload),'little');return value
    def paired(self):
        out=[]
        for _ in range(2):
            self.charge(32)
            for _ in range(4):out.append(self.integer())
        self.charge(1);last=self.raw(1)[0]
        return out,last

def relation(inp,wrong=None):
    s=State(inp,wrong);leaves=[[],[]];allocated=[False,False];calls=[];drops=[]
    allocations=[];releases=[];comparisons=[];movements=[];first_done=False;prefix=None;failure=None
    def keyorder(k):
        if wrong=='signed-key-order':return bytes(b^128 for b in k)
        if wrong=='little-endian-key-order':return int.from_bytes(k,'little')
        return k
    def release(j):
        drops.append('map'+str(j))
        if allocated[j]:releases.append({'symbol':'map'+str(j),'bytes':1024,'flags':0})
    def decode_map(j):
        symbol='map'+str(j);calls.append(symbol);leaf=leaves[j]
        if j==1 and wrong=='reset-second-counter':s.c=inp['charge']+32
        s.charge(8);attempts=s.integer()
        unit=85 if wrong=='reserve85' else 96
        product=attempts*unit;total=s.c+product
        if product>U or total>U:
            if wrong=='store-reservation-overflow':s.c=total&U;s.stores.append(s.c)
            raise DecodeError(2)
        if wrong=='test-reservation-limit-before-store' and total>1000:raise DecodeError(2)
        s.c=total
        if not(wrong=='omit-empty-reservation-store' and attempts==0):s.stores.append(total)
        if total>1000:raise DecodeError(2)
        try:
            for _ in range(attempts):
                refund=0 if wrong=='omit-refund' else 85 if wrong=='refund85' else 96
                if s.c<refund:raise DecodeError(2)
                s.c-=refund;s.stores.append(s.c)
                if wrong=='allocate-before-whole-entry' and not allocated[j]:
                    allocated[j]=True;allocations.append({'symbol':symbol,'bytes':1024})
                s.charge(20);key=s.raw(20);words,last=s.paired()
                index=0
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
        calls.append('fixed32')
        if wrong!='omit-fixed32-charge':s.charge(32)
        if wrong=='consume-short-fixed32' and len(s.data)<32:
            n=32-len(s.data);s.pos=len(s.data);raise DecodeError(0,needed=n)
        prefix=s.raw(32)
        decode_map(0);first_done=True
        decode_map(1)
    except DecodeError as e:
        failure=e.record
        if first_done and wrong!='omit-first-map-cleanup':release(0)
    maps=[]
    if failure:
        # Map errors are already flattened; the caller adds its outer QWORD.
        out=[cell(0,1)]+[dict(c,offset=c['offset']+8) for c in error_cells(failure,None)]
        if wrong=='retain-map-success-tag':out[0]=cell(0,18)
        if wrong=='rollback-error-charge':s.c=inp['charge'];s.stores=[]
        if wrong=='rollback-error-input':s.pos=0
        if wrong=='first-free-before-second':
            releases.sort(key=lambda x:x['symbol']);drops.sort()
        if wrong=='return-partial-maps':maps=[list(leaf) for leaf in leaves]
    else:
        out=[cell(0,0),{'offset':8,'hex':(prefix[::-1] if wrong=='reverse-fixed32-output' else prefix).hex()}]
        for j,leaf in enumerate(leaves):
            k=1-j if wrong=='swap-map-fields' else j;selected=leaves[k];o=40+24*j
            out.append({'offset':o,'symbol':'map'+str(k)} if allocated[k] else cell(o,0))
            if allocated[k] or wrong=='initialize-empty-height':out.append(cell(o+8,0))
            out.append(cell(o+16,len(selected)))
            maps.append([{'keyHex':key.hex(),'words':words,'byte':last} for key,words,last in selected])
        if wrong=='release-success-maps':
            release(1);release(0)
        if wrong=='share-map-keyspace':
            merged={x['keyHex']:x for group in maps for x in group};maps=[list(merged.values())]*2
    return {'charge':s.c,'stores':s.stores,'consumed':s.pos,'remainingHex':s.data[s.pos:].hex(),
      'cells':out,'maps':maps,'calls':calls,'dropCalls':drops,'allocationRequests':allocations,
      'releaseRequests':releases,'comparisons':comparisons,'movements':movements}

wrong_rules=['reserve85','store-reservation-overflow','test-reservation-limit-before-store',
 'omit-empty-reservation-store','omit-refund','refund85','first-duplicate-value-wins',
 'signed-key-order','little-endian-key-order','move65-byte-values','allocate-before-whole-entry',
 'initialize-empty-height','rollback-error-charge','consume-short-key','consume-fast-bad-marker',
 'always-fast-error-type','stop-on-first-duplicate','reset-second-counter','omit-fixed32-charge',
 'consume-short-fixed32','reverse-fixed32-output','omit-first-map-cleanup','first-free-before-second',
 'return-partial-maps','retain-map-success-tag','rollback-error-input','swap-map-fields',
 'release-success-maps','share-map-keyspace']

if __name__=='__main__':
    meta=json.loads(META.read_bytes());compressed=SOURCE.read_bytes()
    if hashlib.sha256(compressed).hexdigest()!=meta['compressedSha256']:raise ValueError('Frozen compressed identity')
    raw=gzip.decompress(compressed)
    if hashlib.sha256(raw).hexdigest()!=meta['uncompressedSha256']:raise ValueError('Frozen plain identity')
    rows=[json.loads(line) for line in raw.splitlines()]
    if len(rows)!=meta['cases']:raise ValueError('Frozen count')
    mismatches={w:0 for w in wrong_rules};counts={}
    for j,row in enumerate(rows):
        if row['id']!=str(j):raise ValueError('Frozen ordering')
        inp=row['input'];expected=row['expected'];observed=relation(inp)
        if observed!=expected:raise ValueError('Nested-map mathematics mismatch '+str(j)+' '+json.dumps({'input':inp,'expected':expected,'observed':observed}))
        counts[row['category']]=counts.get(row['category'],0)+1
        for w in wrong_rules:
            if relation(inp,w)!=expected:mismatches[w]+=1
    if counts!=meta['categories'] or not all(mismatches.values()):raise ValueError('Ineffective control or denominator '+json.dumps(mismatches))
    result={'state':'nested-map-mathematical-relation-unqualified','cases':len(rows),'categories':counts,
      'frozenSha256':meta['compressedSha256'],'wrongRules':mismatches,'capturedExecution':False,
      'instructionEvaluation':False,'nativeEquivalence':False,'networkOperations':0,
      'domain':'QWORDmode1/C at entry0..1000/L1000, valid stable disjoint input/output/state/stack/heap and ordinary preserving helpers.',
      'scope':'Fixed32/ordered two-map composition, original-attempt accounting, joint admission, active output, partial cursor/errors and chronological allocation/drop/release request mathematics. Primitives and clone contexts credited; no allocator/full trees/nativeABI/whole greeting/component gate.'}
    out=Path(sys.argv[1])
    if out.exists():raise ValueError('Preserve relation receipt')
    out.write_text(json.dumps(result,sort_keys=True,indent=2)+'\n',encoding='utf-8',newline='\n')
    print(json.dumps(result,sort_keys=True))

