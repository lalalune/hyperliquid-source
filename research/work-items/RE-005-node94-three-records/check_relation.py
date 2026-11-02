"""Independent protocol/field aggregate parser, never a CPU interpreter."""
from pathlib import Path
import gzip,hashlib,json,struct,sys
B=Path(__file__).resolve().parent;U=(1<<64)-1
SOURCE=B/'expectations.jsonl.gz'
META=B/'FROZEN.json'
def cell(offset,value,width=8):return {'offset':offset,'hex':struct.pack('<B' if width==1 else '<Q',value).hex()}
class Failure(Exception):
    def __init__(self,kind,**fields):self.fields={'kind':kind,**fields}
class Reader:
    def __init__(self,inp,wrong):
        if inp['mode']!=1:raise ValueError('Selected mode')
        self.data=bytes.fromhex(inp['dataHex']);self.pos=0
        self.c=inp['charge'];self.limit=inp['limit'];self.stores=[];self.wrong=wrong
    def charge(self,n):
        total=self.c+n
        if total>U:
            if self.wrong=='overflow-store-wrap':self.c=total&U;self.stores.append(self.c)
            raise Failure(2)
        if self.wrong=='limit-before-store' and total>self.limit:raise Failure(2)
        self.c=total;self.stores.append(total)
        if self.c>self.limit:raise Failure(2)
    def take(self,n,array=False):
        left=len(self.data)-self.pos
        if left<n:
            if array and self.wrong=='partial-array-consume':self.pos+=left
            raise Failure(0,needed=n-left)
        value=self.data[self.pos:self.pos+n];self.pos+=n;return value
    def word(self):
        self.charge(4 if self.wrong=='scalar-charge4' else 8)
        if self.wrong=='scalar-fixed8-wire':return int.from_bytes(self.take(8),'little')
        available=len(self.data)-self.pos
        if not available:raise Failure(0,needed=1)
        marker=self.data[self.pos]
        if marker<251:self.pos+=1;return marker
        width={251:2,252:4,253:8}.get(marker)
        if width is None:
            fast=available>8
            if not fast or self.wrong=='consume-fast-marker':self.pos+=1
            expected=(2 if fast else 3) if self.wrong=='u64-type-error-codes' else 5
            raise Failure(3,expected=expected,found=4 if marker==254 else 12)
        self.pos+=1
        return int.from_bytes(self.take(width),'little')
    def array(self):
        if self.wrong=='array-input-before-charge' and len(self.data)-self.pos<2048:raise Failure(0,needed=2048-(len(self.data)-self.pos))
        if self.wrong!='omit-array-charge':self.charge(2016 if self.wrong=='array-charge2016' else 2048)
        return self.take(2016 if self.wrong=='array-truncate2016' else 2048,array=True)
def relation(inp,wrong=None):
    r=Reader(inp,wrong);records=[];failure=None
    try:
        for _ in range(2 if wrong=='skip-third-record' else 3):
            a=r.word();b=r.word();array=r.array();records.append((a,b,array))
        if wrong=='require-whole-input' and r.pos!=len(r.data):raise Failure(2)
    except Failure as e:failure=e.fields
    if failure:
        if wrong=='rollback-charge':r.c=inp['charge'];r.stores=[]
        if wrong=='rollback-input':r.pos=0
        kind=failure['kind'];cells=[cell(0,1),cell(8,kind,1)]
        if kind==0:cells.append(cell(16,failure['needed']))
        if kind==3:cells.extend([cell(9,failure['expected'],1),cell(10,failure['found'],1)])
    else:
        cells=[cell(0,0)]
        if wrong=='reverse-records':records.reverse()
        arrays=[row[2] for row in records]
        if wrong=='swap-arrays':arrays=arrays[1:]+arrays[:1]
        for j,((a,b,_),array) in enumerate(zip(records,arrays)):
            if wrong=='swap-word-pairs':a,b=b,a
            if wrong=='truncate-word32':a&=(1<<32)-1;b&=(1<<32)-1
            base=8+j*2064
            if wrong=='words-before-array':cells.extend([cell(base,a),cell(base+8,b),{'offset':base+16,'hex':array.hex()}])
            else:cells.extend([{'offset':base,'hex':array.hex()},cell(base+2048,a),cell(base+2056,b)])
    return {'charge':r.c,'stores':r.stores,'consumed':r.pos,'remainingHex':r.data[r.pos:].hex(),'cells':cells}
wrong_rules=['scalar-charge4','scalar-fixed8-wire','array-charge2016','array-input-before-charge',
 'partial-array-consume','array-truncate2016','words-before-array','reverse-records','swap-word-pairs','swap-arrays',
 'truncate-word32','rollback-charge','rollback-input','consume-fast-marker','u64-type-error-codes',
 'skip-third-record','require-whole-input','limit-before-store','overflow-store-wrap','omit-array-charge']
if __name__=='__main__':
    meta=json.loads(META.read_bytes());compressed=SOURCE.read_bytes()
    if hashlib.sha256(compressed).hexdigest()!=meta['compressedSha256']:raise ValueError('Frozen compressed identity')
    raw=gzip.decompress(compressed)
    if hashlib.sha256(raw).hexdigest()!=meta['uncompressedSha256']:raise ValueError('Frozen plain identity')
    rows=[json.loads(line) for line in raw.splitlines()]
    if len(rows)!=meta['cases']:raise ValueError('Frozen count')
    counts={};mismatches={w:0 for w in wrong_rules}
    for j,row in enumerate(rows):
        if row['id']!=str(j):raise ValueError('Frozen order')
        inp=row['input'];expected=row['expected'];observed=relation(inp)
        if observed!=expected:raise ValueError('Mathematical record mismatch '+str(j))
        counts[row['category']]=counts.get(row['category'],0)+1
        for w in wrong_rules:
            if relation(inp,w)!=expected:mismatches[w]+=1
    if counts!=meta['categories'] or not all(mismatches.values()):raise ValueError('Ineffective control '+json.dumps(mismatches))
    receipt={'state':'three-record-mathematical-relation-unqualified','cases':len(rows),'categories':counts,
      'wrongRules':mismatches,'frozenSha256':meta['compressedSha256'],'capturedExecution':False,
      'instructionEvaluation':False,'nativeEquivalence':False,'networkOperations':0,
      'scope':'Mode1 word/array/three-record active output, ordered charge and partial cursor mathematics. Primitive contexts credited; native ABI/full caller/greeting/connection/gates excluded.'}
    out=Path(sys.argv[1])
    if out.exists():raise ValueError('Preserve receipt')
    out.write_text(json.dumps(receipt,sort_keys=True,indent=2)+'\n',encoding='utf-8',newline='\n')
    print(json.dumps(receipt,sort_keys=True))
