#!/usr/bin/env python3
"""Pre-Rust mathematical expectations from proved values, not target instructions."""
from __future__ import annotations
import argparse
import ast
import copy
import gzip
import hashlib
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
MAX64 = (1 << 64) - 1
PREFIX = b'Hyperliquid Consensus Payload'
BOUNDARIES = [0,1,249,250,251,252,65534,65535,65536,65537,(1<<32)-1,1<<32,(1<<32)+1,MAX64]


def need(condition, why):
    if not condition:
        raise ValueError(why)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def keccak_provider():
    # Only the credited pure mathematical helper is extracted. The module's
    # captured instruction evaluators and imports are never loaded.
    path = ROOT/'tools/action_signable.py'
    raw = path.read_bytes()
    wanted = json.loads((HERE/'dependencies.json').read_text())['tools/action_signable.py']
    need(sha(raw) == wanted, 'pure Keccak dependency')
    tree = ast.parse(raw)
    functions = [x for x in tree.body if isinstance(x,ast.FunctionDef) and x.name=='keccak256']
    constants = [x.value for x in tree.body if isinstance(x,ast.Assign)
                 and any(isinstance(t,ast.Name) and t.id=='KECCAK_RC' for t in x.targets)]
    need(len(functions)==len(constants)==1, 'pure Keccak selection')
    space = {'MASK':MAX64,'KECCAK_RATE':136,'KECCAK_DELIM':1,
             'KECCAK_RC':ast.literal_eval(constants[0]),
             '__builtins__':{'range':range,'len':len,'int':int,'bytes':bytes,'bytearray':bytearray}}
    module = ast.fix_missing_locations(ast.Module(body=functions,type_ignores=[]))
    exec(compile(module,'credited-pure-keccak','exec'),space)
    fn = space['keccak256']
    need(fn(b'').hex()=='c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470','Keccak known answer')
    return fn


def v(x):
    need(isinstance(x,int) and 0<=x<=MAX64,'u64 input')
    if x<251:
        return bytes([x])
    width = 2 if x<1<<16 else 4 if x<1<<32 else 8
    return bytes([{2:251,4:252,8:253}[width]])+x.to_bytes(width,'little')


def vl(x):
    need(0<=x<=MAX64,'length scalar')
    return 1 if x<=250 else 1+(2 if x.bit_length()<=16 else 4 if x.bit_length()<=32 else 8)


def fixed(text,n):
    raw=bytes.fromhex(text)
    need(len(raw)==n,'fixed width')
    return raw


def leap(y):
    return y%4==0 and (y%100!=0 or y%400==0)


CYCLE=[0]
for year in range(400):
    CYCLE.append(CYCLE[-1]+365+leap(year))
EPOCH=4*CYCLE[-1]+CYCLE[370]


def split_date(date):
    need(-(1<<31)<=date<1<<31,'i32 packed date')
    return date//8192,((date & 0xffffffff)>>4)&511


def timestamp(time):
    # Independent cycle-prefix equation; production is planned to use a
    # closed signed-floor day formula, not this table.
    date,seconds,nanoseconds=time
    need(0<=seconds<1<<32 and 0<=nanoseconds<1<<32,'two u32 time words')
    year,ordinal=split_date(date)
    cycle,residue=divmod(year,400)
    days=cycle*CYCLE[-1]+CYCLE[residue]+ordinal-1-EPOCH
    return days*86400+seconds


def zigzag(x):
    return x*2 if x>=0 else -x*2-1


def time_bytes(time):
    return v(zigzag(timestamp(time)))+v(time[2])


def signature_bytes(text):
    raw=fixed(text,72)
    return b''.join(v(int.from_bytes(raw[i:i+8],'little')) for i in range(0,64,8))+raw[64:65]


def signature_length(text):
    raw=fixed(text,72)
    return 1+sum(vl(int.from_bytes(raw[i:i+8],'little')) for i in range(0,64,8))


def qc_bytes(q):
    return (v(q['version'])+v(q['start'])+v(q['round'])+fixed(q['hash'],32)+v(len(q['votes']))
            +b''.join(fixed(row['signer'],20)+signature_bytes(row['signature']) for row in q['votes']))


def qc_length(q):
    return (vl(q['version'])+vl(q['start'])+vl(q['round'])+32+vl(len(q['votes']))
            +sum(20+signature_length(row['signature']) for row in q['votes']))


def timeout_bytes(t):
    return signature_bytes(t['signature'])+fixed(t['signer'],20)+v(t['round'])+qc_bytes(t['qc'])


def timeout_length(t):
    return signature_length(t['signature'])+20+vl(t['round'])+qc_length(t['qc'])


def expected(c):
    tc=c['tc']
    tail=b'\0' if tc is None else b'\1'+v(tc['round'])+v(len(tc['votes']))+b''.join(timeout_bytes(t) for t in tc['votes'])
    return (PREFIX+b'\0'+fixed(c['proposer'],20)+v(c['round'])+v(len(c['hashes']))
            +b''.join(fixed(x,32) for x in c['hashes'])+time_bytes(c['time'])+qc_bytes(c['qc'])+tail)


def size(c):
    tc=c['tc']
    tail=1 if tc is None else 1+vl(tc['round'])+vl(len(tc['votes']))+sum(timeout_length(t) for t in tc['votes'])
    return (50+vl(c['round'])+vl(len(c['hashes']))+32*len(c['hashes'])
            +vl(zigzag(timestamp(c['time'])))+vl(c['time'][2])+qc_length(c['qc'])+tail)


def packed(year,ordinal,flags=0):
    need(-262144<=year<=262143 and 0<=ordinal<=511 and 0<=flags<=15,'raw packed fields')
    x=((year & ((1<<19)-1))<<13)|(ordinal<<4)|flags
    return x if x<1<<31 else x-(1<<32)


def addr(i):
    return i.to_bytes(20,'big').hex()


def sig(limbs=None,last=0,padding=0):
    limbs=[0]*8 if limbs is None else limbs
    return (b''.join(x.to_bytes(8,'little') for x in limbs)+bytes([last])+bytes([padding])*7).hex()


def qc(n=0):
    return dict(version=0,start=0,round=0,hash=bytes(range(32)).hex(),
                votes=[dict(signer=addr(i+1),signature=sig()) for i in range(n)])


def timeout(n=0,i=1):
    return dict(signer=addr(0x1000+i),round=0,qc=qc(n),signature=sig(last=i%256))


def block():
    return dict(proposer=addr(0x123456),round=0,hashes=[],time=[packed(1970,1),0,0],
                qc=qc(),tc=None,signature=sig())


def time_for_seconds(t):
    # Small signed-second witnesses around scalar-width thresholds. Keep
    # canonical day/seconds values, deriving the year via a cycle prefix.
    day,seconds=divmod(t,86400)
    total=day+EPOCH
    cycle,within=divmod(total,146097)
    residue=next(i for i in range(400) if CYCLE[i]<=within<CYCLE[i+1])
    year=400*cycle+residue
    return [packed(year,within-CYCLE[residue]+1),seconds,0]


def input_frame(c):
    """Own fixed-width test input only; this is not the native wire format."""
    out=bytearray(fixed(c['proposer'],20))
    def word(x):
        out.extend(struct.pack('<Q',x))
    def count(n):
        need(n<1<<32,'finite driver count');out.extend(struct.pack('<I',n))
    def put_qc(q):
        for k in ('version','start','round'):word(q[k])
        out.extend(fixed(q['hash'],32));count(len(q['votes']))
        for row in q['votes']:
            out.extend(fixed(row['signer'],20));out.extend(fixed(row['signature'],72))
    word(c['round'])
    out.extend(struct.pack('<iII',*c['time']))
    count(len(c['hashes']))
    for h in c['hashes']:out.extend(fixed(h,32))
    put_qc(c['qc'])
    out.append(c['tc'] is not None)
    if c['tc'] is not None:
        word(c['tc']['round']);count(len(c['tc']['votes']))
        for row in c['tc']['votes']:
            out.extend(fixed(row['signer'],20));word(row['round'])
            out.extend(fixed(row['signature'],72));put_qc(row['qc'])
    out.extend(fixed(c['signature'],72))
    return bytes(out)


def certificates():
    need(CYCLE[-1]==146097 and EPOCH==719528,'cycle/epoch')
    mult=0x51eb851f
    for x in range(262146):
        need((x*mult)>>39==x//400,'reciprocal400')
    for x in range(262143):
        need((x*mult)>>37==x//100,'reciprocal100')
    minimum_day=10**20;maximum_day=-10**20
    extrema={k:[10**20,-10**20] for k in ('d','k','1461d','compensation','day')}
    for year in range(-262144,262144):
        k=0 if year>0 else (1-year)//400+1
        d=year-1+400*k
        for name,value in [('d',d),('k',k),('1461d',1461*d),('compensation',-146097*k)]:
            extrema[name][0]=min(extrema[name][0],value);extrema[name][1]=max(extrema[name][1],value)
        for ordinal in (0,511):
            observed=ordinal-146097*k+(1461*d)//4-d//100+(d//100)//4-719163
            earlier=year-1
            closed=365*earlier+earlier//4-earlier//100+earlier//400+ordinal-719163
            cyc,residue=divmod(year,400)
            independent=cyc*146097+CYCLE[residue]+ordinal-1-EPOCH
            need(observed==closed==independent,'all-year day identities')
            extrema['day'][0]=min(extrema['day'][0],observed);extrema['day'][1]=max(extrema['day'][1],observed)
            # Every ordered32-bit additive intermediate fits, even for raw ordinal0/511.
            parts=[ordinal,-146097*k,-(d//100),(1461*d)//4,(d//100)//4,-719163]
            running=0
            for x in parts:
                running+=x
                need(-(1<<31)<=running<1<<31,'native32-bit additive range')
    seconds=[extrema['day'][0]*86400,extrema['day'][1]*86400+(1<<32)-1]
    need(-(1<<63)<=seconds[0]<=seconds[1]<(1<<63),'signed64 seconds')
    need(max(zigzag(seconds[0]),zigzag(seconds[1]))<=MAX64,'zigzag u64')
    return dict(year_count=524288,ordinal_endpoints=[0,511],reciprocal400_count=262146,
                reciprocal100_count=262143,cycle_days=146097,epoch_serial=EPOCH,
                extrema=extrema,timestamp_seconds_extrema=seconds,
                claim='Independent integer equations only; no native instruction evaluation.')


def cases():
    result=[]
    def add(name,c):
        x=copy.deepcopy(c);x['name']=name;result.append(x)
    add('minimal-absent',block())
    for key in ('round','version','start','qc_round'):
        for value in BOUNDARIES:
            c=block()
            if key=='round':c['round']=value
            else:c['qc'][{'version':'version','start':'start','qc_round':'round'}[key]]=value
            add(key+'-'+str(value),c)
    for count in (0,1,2,3,4,249,250,251,252):
        c=block();c['hashes']=[(i.to_bytes(8,'little')*4).hex() for i in range(count)]
        add('transaction-count-'+str(count),c)
        if count in (2,3):c['hashes'].reverse();add('transaction-reverse-'+str(count),c)
    for count in (0,1,2,3,250,251):
        c=block();c['qc']=qc(count);add('QC-count-'+str(count),c)
    for limb in range(8):
        for value in BOUNDARIES:
            c=block();c['qc']=qc(1);limbs=[0]*8;limbs[limb]=value
            c['qc']['votes'][0]['signature']=sig(limbs,last=255)
            add('QC-limb-'+str(limb)+'-'+str(value),c)
    for final in (0,1,2,27,28,127,128,255):
        c=block();c['qc']=qc(1);c['qc']['votes'][0]['signature']=sig(last=final)
        add('QC-final-'+str(final),c)
    for padding in (0,1,255):
        c=block();c['qc']=qc(1);c['qc']['votes'][0]['signature']=sig(padding=padding)
        c['signature']=sig([MAX64]*8,last=255,padding=padding)
        add('inactive-signature-padding-'+str(padding),c)
    years=(-262144,-262143,-401,-400,-399,-100,-1,0,1,4,100,400,1582,1900,1969,1970,2000,2038,2100,262142,262143)
    for yi,year in enumerate(years):
        for oi,ordinal in enumerate((0,1,59,60,365,366,511)):
            for si,seconds in enumerate((0,86399,86400,(1<<32)-1)):
                c=block();nano=(0,1,999999999,(1<<32)-1)[(yi+oi+si)%4]
                c['time']=[packed(year,ordinal,(yi+oi)%16),seconds,nano]
                add('time-'+str(year)+'-'+str(ordinal)+'-'+str(seconds),c)
    for year in (-262144,-400,-1,0,1,1970,262143):
        for flags in range(16):
            c=block();c['time']=[packed(year,1,flags),0,0]
            add('inactive-date-flags-'+str(year)+'-'+str(flags),c)
    for t in (0,-1,1,-125,125,-126,126,-32767,32767,-32768,32768,-(1<<31),(1<<31)-1,1<<31):
        c=block();c['time']=time_for_seconds(t);need(timestamp(c['time'])==t,'timestamp witness')
        add('zigzag-threshold-'+str(t),c)
    for nano in (0,1,249,250,251,65535,65536,(1<<32)-1):
        c=block();c['time'][2]=nano;add('nanoseconds-'+str(nano),c)
    for count in (0,1,2,3,250,251):
        c=block();c['tc']=dict(round=251,votes=[timeout(i=i+1) for i in range(count)])
        add('TC-count-'+str(count),c)
    for key in ('certificate_round','timeout_round','version','start','qc_round'):
        for value in BOUNDARIES:
            c=block();c['tc']=dict(round=0,votes=[timeout(1)])
            if key=='certificate_round':c['tc']['round']=value
            elif key=='timeout_round':c['tc']['votes'][0]['round']=value
            else:c['tc']['votes'][0]['qc'][{'version':'version','start':'start','qc_round':'round'}[key]]=value
            add('TC-'+key+'-'+str(value),c)
    for limb in range(8):
        for value in BOUNDARIES:
            c=block();c['tc']=dict(round=0,votes=[timeout()])
            limbs=[0]*8;limbs[limb]=value;c['tc']['votes'][0]['signature']=sig(limbs,last=28)
            add('timeout-outer-limb-'+str(limb)+'-'+str(value),c)
    for count in (0,1,2,250,251):
        c=block();c['tc']=dict(round=MAX64,votes=[timeout(count),timeout(1,2)])
        add('nested-QC-count-'+str(count),c)
    for reverse in (False,True):
        c=block();c['qc']=qc(3);c['tc']=dict(round=42,votes=[timeout(2,1),timeout(1,2)])
        for i,row in enumerate(c['qc']['votes']):row['signature']=sig([i+251]*8,last=i)
        if reverse:
            c['qc']['votes'].reverse();c['tc']['votes'].reverse()
            for row in c['tc']['votes']:row['qc']['votes'].reverse()
        add('nested-order-'+str(reverse),c)
    for which in ('block','timeout','nestedQC'):
        for byte in (0,1,63,64,65,71):
            c=block();c['tc']=dict(round=2,votes=[timeout(1)]);c['qc']=qc(1)
            obj=c if which=='block' else c['tc']['votes'][0] if which=='timeout' else c['tc']['votes'][0]['qc']['votes'][0]
            raw=bytearray(fixed(obj['signature'],72));raw[byte]^=0xff;obj['signature']=raw.hex()
            add('active-inactive-'+which+'-'+str(byte),c)
    # Fill exact rate-adjacent lengths using scalar width increments and raw32
    # transaction hashes. This searches mathematical values, not the target.
    found={}
    wanted={135,136,137,271,272,273,407,408,409}
    choices=(0,251,65536,1<<32)
    for n in range(11):
        for a in choices:
            for b in choices:
                for cv in choices:
                    for dv in choices:
                        for nano in (0,251,65536):
                            for votes in (0,1):
                                c=block();c['hashes']=['5a'*32]*n;c['round']=a;c['qc']=qc(votes)
                                c['qc'].update(version=b,start=cv,round=dv);c['time'][2]=nano
                                length=size(c)
                                if length in wanted and length not in found:found[length]=c
    need(set(found)==wanted,'all requested rate-boundary lengths')
    for length in sorted(found):add('rate-length-'+str(length),found[length])
    need(len({c['name'] for c in result})==len(result),'unique fixture names')
    return result


def generate():
    cert=certificates();h=keccak_provider();entries=cases()
    outputs=[];case_lines=[];lengths=[];times=[]
    for index,c in enumerate(entries):
        preimage=expected(c);need(len(preimage)==size(c),'independent size equation')
        need(len(preimage)<1<<63,'finite fixture total length')
        case_id=f'C{index:06d}'
        outputs.append('\t'.join([case_id,input_frame(c).hex(),str(len(preimage)),preimage.hex(),h(preimage).hex()]))
        case_lines.append(json.dumps(dict(c,case_id=case_id),separators=(',',':'),sort_keys=True))
        lengths.append(len(preimage));times.append(timestamp(c['time']))
    # Human-checkable minimal witness: all scalar widths1 and absentTC.
    zero=entries[0]
    # Round,count,seconds,nanos,three QC words precede hash: build independently.
    minimal=PREFIX+b'\0'+fixed(zero['proposer'],20)+bytes(7)+fixed(zero['qc']['hash'],32)+bytes(2)
    need(expected(zero)==minimal and len(minimal)==91,'minimal byte witness')
    record=dict(target_sha256='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f',
                cases=len(entries),min_preimage_bytes=min(lengths),max_preimage_bytes=max(lengths),
                rate_boundary_lengths=sorted({n for n in lengths if n in (135,136,137,271,272,273,407,408,409)}),
                domains='raw i32 packed date and two u32 time words; finite stable typed vectors/signature projections',
                pure_arithmetic_only=True,captured_execution=False,corpus_sha256=sha(Path(__file__).read_bytes()),
                certificate=cert,keccak_credit='baseline tools/action_signable.py pure helper; native permutation identity conditional')
    return {'cases.jsonl.gz':gzip.compress(('\n'.join(case_lines)+'\n').encode(),mtime=0),
            'vectors.tsv.gz':gzip.compress(('\n'.join(outputs)+'\n').encode(),mtime=0),
            'corpus.json':(json.dumps(record,sort_keys=True,separators=(',',':'))+'\n').encode()}


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--out',type=Path,required=True);a=ap.parse_args()
    need(not a.out.exists(),'fresh output required');outputs=generate();a.out.mkdir(parents=True)
    for name,data in outputs.items():(a.out/name).write_bytes(data)
    print((a.out/'corpus.json').read_text())


if __name__=='__main__':
    main()
