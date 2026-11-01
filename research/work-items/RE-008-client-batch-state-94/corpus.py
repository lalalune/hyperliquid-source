#!/usr/bin/env python3
"""Pre-Rust value/state expectations. Never evaluates captured instructions.

Admission scalar rules are independently written from the credited baseline
contract; byte/control-flow proof is in PROOF.md. Fixture authentication is an
explicit deterministic test boundary, not target signature or preimage evidence.
"""
from __future__ import annotations
import argparse,ast,copy,gzip,hashlib,json,struct
from functools import lru_cache
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
MAX64=(1<<64)-1

def need(ok,why):
    if not ok:raise ValueError(why)

def sha(raw):return hashlib.sha256(raw).hexdigest()

def keccak_provider():
    raw=(ROOT/'tools/action_signable.py').read_bytes()
    need(sha(raw)==json.loads((HERE/'dependencies.json').read_text())['tools/action_signable.py'],'credited pure Keccak hash')
    tree=ast.parse(raw)
    fs=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='keccak256']
    cs=[n.value for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='KECCAK_RC' for t in n.targets)]
    need(len(fs)==len(cs)==1,'one pure helper and constant')
    space={'MASK':MAX64,'KECCAK_RATE':136,'KECCAK_DELIM':1,'KECCAK_RC':ast.literal_eval(cs[0]),'__builtins__':{'range':range,'len':len,'int':int,'bytes':bytes,'bytearray':bytearray}}
    exec(compile(ast.fix_missing_locations(ast.Module(body=fs,type_ignores=[])),'credited-pure-keccak','exec'),space)
    fn=space['keccak256'];need(fn(b'').hex()=='c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470','known hash')
    return lru_cache(maxsize=20000)(fn)

K=keccak_provider()
def u8(x):return bytes([x])
def u32(x):return struct.pack('<I',x)
def u64(x):return struct.pack('<Q',x)
def raw(x,n=None):
    b=bytes.fromhex(x);need(n is None or len(b)==n,'fixed bytes');return b

def vec(xs,fn):return u32(len(xs))+b''.join(fn(x) for x in xs)
def qscalar(q):return u64(q['hf'][0])+u64(q['hf'][1])+u64(q['round'])+raw(q['hash'],32)
def qbytes(q):return qscalar(q)+vec(q['votes'],lambda v:raw(v['signer'],20)+raw(v['signature'],72))
def tbytes(t):return u64(t['round'])+vec(t['votes'],lambda v:qbytes(v['qc'])+u64(v['round'])+raw(v['signer'],20)+raw(v['signature'],72))
def bunsigned(b):
    return u64(b['round'])+raw(b['proposer'],20)+b''.join(u32(x) for x in b['time'])+vec(b['hashes'],lambda h:raw(h,32))+qbytes(b['qc'])+(b'\0' if b['tc'] is None else b'\1'+tbytes(b['tc']))
def bbytes(b):return bunsigned(b)+raw(b['signature'],72)
def ibytes(i):
    return bbytes(i['block'])+vec(i['tx'],lambda t:raw(t['hash'],32)+u32(len(raw(t['bytes'])))+raw(t['bytes']))+b''.join(u32(x) for x in i['time'])+(b'\0' if i['proof'] is None else b'\1'+bbytes(i['proof']['child'])+qbytes(i['proof']['qc']))
def hbytes(h):return u64(h['base'])+u64(h['hf'][0])+u64(h['hf'][1])+u64(h['until'])+vec(h['snapshots'],lambda s:u64(s['round'])+vec(s['stakes'],lambda v:raw(v['address'],20)+u64(v['weight'])))
def input_frame(c):
    result=b'CB1'+u8(c['mode'])+hbytes(c['history'])
    if c['mode']==0:return result+u64(c['start'])+vec(c['items'],ibytes)
    return result+u64(c['last'])+u64(c['confirmed'])+vec(c['pending'],ibytes)+u64(c['close_after'])+vec(c['items'],ibytes)

# A deterministic test-only boundary; these are not network signatures.
def fixture_signature(domain,message,signer):return (raw(signer,20)+K(domain+message+raw(signer,20))+bytes(20)).hex()
def recover(domain,message,signature):
    s=raw(signature,72);who=s[:20].hex()
    return who if fixture_signature(domain,message,who)==signature else None

def block_digest(b):return K(b'fixture-block-v1'+bunsigned(b))
def sign_block(b):b['signature']=fixture_signature(b'fixture-block-sign-v1',bunsigned(b),b['proposer']);return b

def local(tag,payload=b''):return ('L',tag,payload)
def admission(tag,payload=b''):return ('A',tag,payload)
def fatal(tag):return ('F',tag,b'')
def outer(tag,payload=b''):return ('O',tag,payload)
def status_bytes(s):return b'\0' if s is None else u8({'L':1,'A':2,'F':3,'O':4}[s[0]])+u8(s[1])+u32(len(s[2]))+s[2]
def trace_event(trace,code,round_value,message):trace.append((code,round_value,K(message)))

def selected(h,r):
    bound=h['base'] if r<min(MAX64,h['base']+2000) else max(h['base'],(r-200)&MAX64)
    candidates=[s for s in h['snapshots'] if s['round']<=bound]
    return max(candidates,key=lambda s:s['round'])['stakes'] if candidates else None

def weights(stakes):return {s['address']:s['weight'] for s in stakes}
def quorum(stakes,signers):
    w=weights(stakes);total=sum(w.values());signed=sum(w.get(a,0) for a in set(signers))
    return None if max(total,signed)>MAX64 else 3*signed>2*total

def check_qc(h,q,trace):
    stakes=selected(h,q['round']);passed=False
    if stakes is None:held=admission(0x28,u64(q['round']))
    else:
        held=None;w=weights(stakes)
        for v in q['votes']:
            if v['signer'] not in w:held=admission(2);break
            message=qscalar(q)+raw(v['signature'],72)
            trace_event(trace,2,q['round'],message)
            if recover(b'fixture-qc-v1',qscalar(q),v['signature'])!=v['signer']:held=admission(2);break
        if held is None:
            reached=quorum(stakes,[v['signer'] for v in q['votes']])
            if reached is None:return fatal(0)
            passed=reached;held=None if reached else admission(9)
    if q['hf']!=h['hf']:
        if q['hf'][0]>h['hf'][0] and passed:return fatal(1)
        return admission(0,b''.join(u64(x) for x in q['hf']+h['hf']))
    if q['round']<h['hf'][1]:return admission(7)
    if q['round']==h['hf'][1]:return None if q['hash']=='00'*32 and not q['votes'] else admission(8)
    return held

def check_timeout(h,v,trace,with_qc):
    stakes=selected(h,v['round'])
    if stakes is None:return admission(0x28,u64(v['round']))
    if with_qc:
        error=check_qc(h,v['qc'],trace)
        if error:return error
    if v['signer'] not in weights(stakes):return admission(1)
    message=qscalar(v['qc'])+u64(v['round'])
    trace_event(trace,3,v['round'],message+raw(v['signature'],72))
    return None if recover(b'fixture-timeout-v1',message,v['signature'])==v['signer'] else admission(1)

def check_tc(h,t,trace):
    stakes=selected(h,t['round'])
    if stakes is None:return admission(0x28,u64(t['round']))
    if not t['votes']:return admission(11)
    for v in t['votes']:
        if v['round']!=t['round']:return admission(15,u64(v['round'])+u64(t['round']))
    chosen=max(enumerate(t['votes']),key=lambda pair:(pair[1]['qc']['round'],pair[0]))[1]
    error=check_timeout(h,chosen,trace,True)
    if error:return error
    for v in t['votes']:
        error=check_timeout(h,v,trace,False)
        if error:return error
    reached=quorum(stakes,[v['signer'] for v in t['votes']])
    return fatal(0) if reached is None else None if reached else admission(10)

def check_block(h,b,trace):
    stakes=selected(h,b['round'])
    if stakes is None:return admission(0x28,u64(b['round']))
    eligible=sorted(weights(stakes))
    trace_event(trace,1,b['round'],u64(b['round'])+vec(eligible,lambda a:raw(a,20)))
    if not eligible:return admission(255) # explicit fixture-boundary failure, no target tag assigned
    expected=eligible[0]
    if b['proposer']!=expected:return admission(12,raw(b['proposer'],20)+raw(expected,20))
    error=check_qc(h,b['qc'],trace)
    if error:return error
    if b['qc']['round']>=b['round']:return admission(4)
    if b['tc'] is not None:
        if b['tc']['round']!=((b['round']-1)&MAX64):return admission(5)
        error=check_tc(h,b['tc'],trace)
        if error:return error
    if b['proposer'] not in weights(stakes):return admission(1)
    trace_event(trace,4,b['round'],bbytes(b))
    return None if recover(b'fixture-block-sign-v1',bunsigned(b),b['signature'])==b['proposer'] else admission(1)

def digest_call(b,trace):
    trace_event(trace,5,b['round'],bunsigned(b));return block_digest(b)

def batch(h,items,start,trace):
    if not items:return local(20)
    previous=None;round_value=start
    for index,item in enumerate(items):
        b=item['block']
        if item['proof'] is not None and index+1!=len(items):return local(26)
        if b['qc']['round']!=round_value:return local(21,u64(b['qc']['round'])+u64(round_value))
        if previous is not None and raw(b['qc']['hash'],32)!=previous:return local(22,raw(b['qc']['hash'],32)+previous)
        error=check_block(h,b,trace)
        if error:return error
        for tx in item['tx']:
            if K(raw(tx['bytes']))!=raw(tx['hash'],32):return local(23,raw(tx['hash'],32))
        if [t['hash'] for t in item['tx']]!=b['hashes']:return local(24)
        if item['time']!=b['time']:return local(25)
        round_value=b['round'];previous=digest_call(b,trace)
    item=items[-1];b=item['block'];proof=item['proof']
    if proof is None:return local(27)
    last=digest_call(b,trace);child=proof['child']
    error=check_block(h,child,trace)
    if error:return error
    error=check_qc(h,proof['qc'],trace)
    if error:return error
    if raw(child['qc']['hash'],32)!=last:return local(29)
    child_hash=digest_call(child,trace)
    if raw(proof['qc']['hash'],32)!=child_hash:
        digest_call(child,trace) # lazy getter excluded from API; second digest preserved
        return local(30)
    if child['round']!=min(MAX64,b['round']+1):return local(31)
    return None

def trace_bytes(trace):return vec(trace,lambda e:u8(e[0])+u64(e[1])+e[2])
def fingerprint(item):return K(ibytes(item))
def observation(last,confirmed,pending):return u64(last)+u64(confirmed)+vec(pending,fingerprint)

def expected(c):
    trace=[]
    if c['mode']==0:
        result=batch(c['history'],c['items'],c['start'],trace)
        return status_bytes(result)+trace_bytes(trace),dict(status=None if result is None else [result[0],result[1],result[2].hex()],trace_count=len(trace))
    pending=copy.deepcopy(c['pending']);last=c['last'];confirmed=c['confirmed'];sent=[];events=[];steps=[];statuses=[]
    for item in c['items']:
        b=item['block']
        if b['qc']['round']!=last:result=outer(44,u64(b['qc']['round']))
        else:
            last=b['round'];pending.append(item)
            if item['proof'] is None:result=None if len(pending)<=100 else outer(42,b'Too many unconfirmed blocks')
            else:
                result=batch(c['history'],pending,confirmed,trace)
                if result is None:
                    confirmed=last;drained=pending;pending=[]
                    for queued in drained:
                        accepted=len(sent)<c['close_after'];events.append(u8(int(accepted))+u64(last)+u64(confirmed)+u64(len(pending))+fingerprint(queued))
                        if not accepted:result=outer(53);break
                        sent.append(queued)
        steps.append(status_bytes(result)+observation(last,confirmed,pending)+vec(sent,fingerprint))
        statuses.append(None if result is None else [result[0],result[1],result[2].hex()])
    return vec(steps,lambda x:x)+vec(events,lambda x:x)+trace_bytes(trace),dict(statuses=statuses,last=last,confirmed=confirmed,pending=len(pending),sent=len(sent),trace_count=len(trace),sink_attempts=len(events))

# Case construction uses semantic names only in metadata; client IDs are opaque.
def address(n):return bytes([n])*20
A=address(1).hex()
def history():return dict(base=0,hf=[1,0],until=MAX64,snapshots=[dict(round=0,stakes=[dict(address=A,weight=10)])])
def qc(r,hash_value=None):
    q=dict(hf=[1,0],round=r,hash=('00'*32 if r==0 else '11'*32) if hash_value is None else hash_value,votes=[])
    if r!=0:q['votes']=[dict(signer=A,signature=fixture_signature(b'fixture-qc-v1',qscalar(q),A))]
    return q

def resign_q(q):
    for v in q['votes']:v['signature']=fixture_signature(b'fixture-qc-v1',qscalar(q),v['signer'])
    return q

def block(r,parent,hash_value=None,txs=()):
    b=dict(round=r,proposer=A,time=[0,123,456],hashes=[K(t).hex() for t in txs],qc=qc(parent,hash_value),tc=None,signature='00'*72)
    return sign_block(b)

def item(b,txs=(),proof=False):
    i=dict(block=b,tx=[dict(hash=K(t).hex(),bytes=t.hex()) for t in txs],time=list(b['time']),proof=None)
    if proof:
        child=block(min(MAX64,b['round']+1),b['round'],block_digest(b).hex())
        i['proof']=dict(child=child,qc=qc(child['round'],block_digest(child).hex()))
    return i

def chain(n=2,start=0,gap=1,txs=()):
    result=[];parent=start;prev=None
    for i in range(n):
        b=block(parent+gap,parent,prev,txs);result.append(item(b,txs,proof=i==n-1));parent=b['round'];prev=block_digest(b).hex()
    return result

def case(name,items=None,start=0,h=None,mode=0,**kw):
    c=dict(name=name,mode=mode,history=history() if h is None else h,items=chain(1) if items is None else items)
    if mode==0:c['start']=start
    else:
        c.update(last=0,confirmed=0,pending=[],close_after=MAX64);c.update(kw)
    return c

def cases():
    out=[]
    def add(c):out.append(c)
    add(case('empty',[]));add(case('single-success'));add(case('ordered-chain',chain(3)))
    add(case('gapped-rounds',chain(3,gap=4)))
    x=chain(1);x[0]['proof']=None;add(case('missing-proof',x))
    x=chain(2);x[0]['proof']=copy.deepcopy(x[-1]['proof']);add(case('earlier-proof',x))
    x=chain(2);x[0]['proof']=copy.deepcopy(x[-1]['proof']);x[0]['block']['qc']['round']=7;add(case('proof-before-round',x))
    x=chain(1);x[0]['block']['qc']['round']=3;add(case('qc-round',x))
    for byte in range(32):
        x=chain(2);h=bytearray(raw(x[1]['block']['qc']['hash']));h[byte]^=1;x[1]['block']['qc']['hash']=h.hex();add(case(f'parent-hash-byte-{byte}',x))
    # Non-genesis first parent hash has no local anchor; actual QC remains valid.
    add(case('first-parent-unconstrained',chain(1,start=5),start=5))
    for n in [0,1,3,4,31,32,135,136,137,271,272,273,4096]:
        tx=bytes((i*37+11)%256 for i in range(n));add(case(f'tx-length-{n}',chain(1,txs=[tx])))
    for byte in range(32):
        x=chain(1,txs=[b'alpha']);h=bytearray(raw(x[0]['tx'][0]['hash']));h[byte]^=1;x[0]['tx'][0]['hash']=h.hex();add(case(f'tx-hash-byte-{byte}',x))
    x=chain(1,txs=[b'a',b'b']);x[0]['block']['hashes']=[];sign_block(x[0]['block']);x[0]['tx'][1]['bytes']='cc';add(case('all-tx-hashes-before-count',x))
    x=chain(1,txs=[b'a']);x[0]['block']['hashes']=[];sign_block(x[0]['block']);add(case('tx-count',x))
    x=chain(1,txs=[b'a',b'b']);x[0]['block']['hashes'].reverse();sign_block(x[0]['block']);add(case('tx-order',x))
    add(case('repeat-tx',chain(1,txs=[b'a',b'a',b'b'])))
    for word in range(3):
        for bit in [0,7,15,31]:
            x=chain(1);x[0]['time'][word]^=1<<bit;add(case(f'time-word-{word}-bit-{bit}',x))
    x=chain(1);x[0]['block']['time']=[MAX64&0xffffffff]*3;sign_block(x[0]['block']);x[0]=item(x[0]['block'],proof=True);add(case('all-time-bits-valid-raw',x))
    # Frozen timed-signature stub makes omission/replacement of signed time visible.
    for word in range(3):
        x=chain(1);x[0]['block']['time'][word]^=1;x[0]['time']=list(x[0]['block']['time']);add(case(f'timed-auth-required-{word}',x))
    for label,where in [('block',0),('child',1),('proof-qc',2)]:
        x=chain(1)
        if where==0:x[0]['block']['signature']='00'*72
        elif where==1:x[0]['proof']['child']['signature']='00'*72
        else:x[0]['proof']['qc']['votes'][0]['signature']='00'*72
        add(case(label+'-signature-failure',x))
    for byte in range(32):
        x=chain(1);q=x[0]['proof']['child']['qc'];h=bytearray(raw(q['hash']));h[byte]^=1;q['hash']=h.hex();resign_q(q);sign_block(x[0]['proof']['child']);add(case(f'child-link-byte-{byte}',x))
        x=chain(1);q=x[0]['proof']['qc'];h=bytearray(raw(q['hash']));h[byte]^=1;q['hash']=h.hex();resign_q(q);add(case(f'proof-link-byte-{byte}',x))
    x=chain(1);child=x[0]['proof']['child'];child['round']+=2;sign_block(child);x[0]['proof']['qc']=qc(child['round'],block_digest(child).hex());add(case('child-round-not-consecutive',x))
    # Saturating local comparison is reached by an otherwise valid child QC below MAX.
    b=block(MAX64,MAX64-2);x=item(b,proof=False);child=block(MAX64,MAX64-1,block_digest(b).hex());x['proof']=dict(child=child,qc=qc(MAX64,block_digest(child).hex()));add(case('saturating-child-round', [x],start=MAX64-2))
    # Important precedence pairs and actual admission dependence.
    for kind in ['missing-stake','proposer','qc-hardfork','qc-no-quorum','qc-genesis','bad-qc-round','empty-tc','bad-tc-round','single-timeout-signature']:
        x=chain(1);h=history();b=x[0]['block']
        if kind=='missing-stake':h['snapshots']=[]
        elif kind=='proposer':b['proposer']=address(2).hex()
        elif kind=='qc-hardfork':b['qc']['hf'][0]=0
        elif kind=='qc-no-quorum':b['qc']=qc(1);b['qc']['votes']=[];b['round']=2
        elif kind=='qc-genesis':b['qc']['hash']='ff'*32
        elif kind=='bad-qc-round':b['round']=0
        else:
            b['round']=2;b['qc']=qc(1)
            b['tc']=dict(round=1 if kind!='bad-tc-round' else 0,votes=[])
            if kind=='single-timeout-signature':b['tc']['votes']=[dict(qc=qc(0),round=1,signer=A,signature='00'*72)]
        sign_block(b);c=case(kind,x,h=h,start=b['qc']['round']);add(c)
    # A single valid TC child closes tie/parallel ambiguity for this fixture domain.
    b=block(2,1);v=dict(qc=qc(0),round=1,signer=A,signature='00'*72);v['signature']=fixture_signature(b'fixture-timeout-v1',qscalar(v['qc'])+u64(1),A);b['tc']=dict(round=1,votes=[v]);sign_block(b);add(case('single-timeout-success',[item(b,proof=True)],start=1))
    x=chain(1);x[0]['block']['signature']='00'*72;x[0]['tx']=[dict(hash='00'*32,bytes='01')];add(case('block-before-tx',x))
    x=chain(1);x[0]['proof']['child']['signature']='00'*72;x[0]['proof']['qc']['votes'][0]['signature']='00'*72;add(case('child-before-proof-qc',x))
    x=chain(1);x[0]['proof']['child']['qc']['hash']='ee'*32;resign_q(x[0]['proof']['child']['qc']);sign_block(x[0]['proof']['child']);x[0]['proof']['qc']['votes'][0]['signature']='00'*72;add(case('proof-qc-before-child-link',x))
    # Direct buffer histories, including retention after each error class.
    add(case('buffer-success',mode=1))
    add(case('buffer-round-reject',chain(1,start=9),mode=1))
    for n in [99,100,101,102]:
        xs=chain(n)
        for i in xs:i['proof']=None
        add(case(f'unconfirmed-count-{n}',xs,mode=1))
    add(case('proof-flush-above-100',chain(101),mode=1))
    for close in [0,1,2,3]:add(case(f'closed-after-{close}',chain(3),mode=1,close_after=close))
    empty=history();empty['snapshots']=[]
    a=item(block(1,0),proof=True);b=item(block(2,1),proof=True)
    add(case('empty-stake-two-call-counterexample',[a,b],mode=1,h=empty))
    x=chain(1);x[0]['block']['signature']='00'*72;x.append(item(block(2,1),proof=True));add(case('signature-error-retained-proof',x,mode=1))
    xs=chain(2);xs[1]['time'][0]=1;xs.append(item(block(3,2),proof=True));add(case('time-error-retained-proof',xs,mode=1))
    # Retry after a closed flush starts from the advanced confirmed round.
    xs=chain(2);last=xs[-1]['block'];next_item=item(block(3,2,block_digest(last).hex()),proof=True);xs.append(next_item);add(case('closed-flush-followed-by-next',xs,mode=1,close_after=1))
    # Deterministic combinations vary order/row counts/time/high rounds, not a test farm.
    for n in [1,2,4]:
        for gap in [1,7]:
            for txs in [[],[b'x'],[b'x',b'y',b'x']]:add(case(f'composition-{n}-{gap}-{len(txs)}',chain(n,gap=gap,txs=txs)))
    return out

def generate():
    all_cases=cases();case_lines=[];inputs=[];outputs=[];meta=[]
    for index,c in enumerate(all_cases):
        identifier=f'C{index:06d}';frame=input_frame(c);answer,summary=expected(c)
        case_lines.append(json.dumps(dict(id=identifier,**c),separators=(',',':')))
        inputs.append(identifier+'\t'+frame.hex());outputs.append(identifier+'\t'+answer.hex())
        meta.append(dict(id=identifier,name=c['name'],input_bytes=len(frame),expected_bytes=len(answer),summary=summary))
    # The named witness is a protocol-independent check on the model itself.
    witness=next(x for x in meta if x['name']=='empty-stake-two-call-counterexample')['summary']
    need(witness['statuses']==[['A',40,u64(1).hex()],['L',26,'']] and witness['last']==2 and witness['confirmed']==0 and witness['pending']==2 and witness['trace_count']==0,'empty-stake witness')
    need(len(set(c['name'] for c in all_cases))==len(all_cases),'unique semantic cases')
    return {'cases.jsonl.gz':gzip.compress(('\n'.join(case_lines)+'\n').encode(),mtime=0),'inputs.tsv.gz':gzip.compress(('\n'.join(inputs)+'\n').encode(),mtime=0),'expected.tsv.gz':gzip.compress(('\n'.join(outputs)+'\n').encode(),mtime=0),'case-index.json':(json.dumps(dict(count=len(all_cases),cases=meta),separators=(',',':'))+'\n').encode()}

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--out',type=Path,required=True);a=ap.parse_args();need(not a.out.exists(),'new output only');outputs=generate();a.out.mkdir(parents=True)
    for n,b in outputs.items():(a.out/n).write_bytes(b)
    print(json.dumps(dict(cases=len(cases()),files=len(outputs))))
if __name__=='__main__':main()
