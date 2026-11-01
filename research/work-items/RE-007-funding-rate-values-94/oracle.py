#!/usr/bin/env python3
"""Independent rational value oracle, written before production.

No target decoder, register/PC model, host floating operations or candidate import.
Finite rounding locates adjacent representable encodings by binary search and
compares exact rational distances. This is not the planned production algorithm.
"""
import argparse
from collections import Counter
from fractions import Fraction
from functools import lru_cache
import gzip
import hashlib
import json
from pathlib import Path

SIGN=1<<63
INF=0x7ff0000000000000
MAX=INF-1
QUIET=1<<51
INDEFINITE=0xfff8000000000000
INTEREST=0x3f1a36e2eb1c432d
ONE=0x3ff0000000000000
CAP=0x3fd47ae147ae147b
EIGHTH=0x3fc0000000000000

def require(ok,message):
    if not ok: raise ValueError(message)

def magnitude(bits):return bits & (SIGN-1)
def nan(bits):return magnitude(bits)>INF
def finite(bits):return magnitude(bits)<INF

@lru_cache(maxsize=100000)
def rational(bits):
    require(finite(bits),'rational finite input')
    frac=bits & ((1<<52)-1);exponent=(bits>>52)&2047
    integer=frac if exponent==0 else frac+(1<<52)
    power=-1074 if exponent==0 else exponent-1075
    value=Fraction(integer*(1<<power),1) if power>=0 else Fraction(integer,1<<-power)
    return -value if bits&SIGN else value

@lru_cache(maxsize=50000)
def rounded(value):
    """Exact nearest-even encoding of a nonzero finite mathematical rational."""
    require(value!=0,'zero sign supplied by operation')
    sign=SIGN if value<0 else 0
    x=abs(value)
    # Midpoint from largest finite to the virtual next magnitude2**1024.
    if x>=Fraction((1<<1024)-(1<<970)):return sign|INF
    if x>=rational(MAX):return sign|MAX
    low,high=0,MAX
    while high-low>1:
        mid=(low+high)//2
        if rational(mid)<=x:low=mid
        else:high=mid
    left=x-rational(low);right=rational(high)-x
    chosen=low if left<right or (left==right and low%2==0) else high
    return sign|chosen

def nan_result(a,b):
    if nan(a):return a|QUIET
    if nan(b):return b|QUIET
    return None

def add(a,b):
    chosen=nan_result(a,b)
    if chosen is not None:return chosen
    if magnitude(a)==INF or magnitude(b)==INF:
        if magnitude(a)==magnitude(b)==INF and (a^b)&SIGN:return INDEFINITE
        return a if magnitude(a)==INF else b
    value=rational(a)+rational(b)
    if value==0:return SIGN if a==b==SIGN else 0
    return rounded(value)

def sub(a,b):
    # SUBSD does not invert the sign of an already selected second-source NaN.
    chosen=nan_result(a,b)
    return chosen if chosen is not None else add(a,b^SIGN)

def mul(a,b):
    chosen=nan_result(a,b)
    if chosen is not None:return chosen
    sign=(a^b)&SIGN
    if magnitude(a)==INF or magnitude(b)==INF:
        return INDEFINITE if magnitude(a)==0 or magnitude(b)==0 else sign|INF
    if magnitude(a)==0 or magnitude(b)==0:return sign
    return rounded(rational(a)*rational(b))

def div(a,b):
    chosen=nan_result(a,b)
    if chosen is not None:return chosen
    aa,bb=magnitude(a),magnitude(b);sign=(a^b)&SIGN
    if (aa==bb==INF) or (aa==bb==0):return INDEFINITE
    if aa==INF or bb==0:return sign|INF
    if aa==0 or bb==INF:return sign
    return rounded(rational(a)/rational(b))

def min_second(a,b):
    require(finite(a) and finite(b),'only finite native clamp operands')
    return a if rational(a)<rational(b) else b

def max_second(a,b):
    require(finite(a) and finite(b),'only finite native clamp operands')
    return a if rational(a)>rational(b) else b

def rate(samples,interest,multiplier,clamp):
    if samples is None or not samples:return None
    require(len(samples)<1<<60,'ordinary vector length')
    summed=SIGN
    for sample in samples:summed=add(summed,sample)
    mean=div(summed,rounded(Fraction(len(samples))))
    gap=sub(INTEREST if interest is None else interest,mean)
    if finite(gap) and finite(clamp):
        low=min_second(clamp,clamp^SIGN)
        high=max_second(clamp^SIGN,clamp)
        gap=min_second(high,max_second(low,gap))
    value=mul(add(mean,gap),ONE if multiplier is None else multiplier)
    if finite(value):value=min_second(CAP,max_second(CAP|SIGN,value))
    return mul(value,EIGHTH)

def math_checks():
    checks=[]
    def check(name,actual,wanted):
        require(actual==wanted,name);checks.append(name)
    check('positive half-subnormal ties to even zero',rounded(Fraction(1,1<<1075)),0)
    check('negative half-subnormal keeps sign',rounded(-Fraction(1,1<<1075)),SIGN)
    check('odd lower subnormal midpoint rounds up',rounded(Fraction(3,1<<1075)),2)
    check('even lower subnormal midpoint rounds down',rounded(Fraction(5,1<<1075)),2)
    check('overflow midpoint chooses infinity',rounded(Fraction((1<<1024)-(1<<970))),INF)
    check('immediately below overflow midpoint stays finite',rounded(Fraction((1<<1024)-(1<<970)-1)),MAX)
    check('normal/subnormal midpoint chooses even minimum normal',rounded((rational(0x000fffffffffffff)+rational(0x0010000000000000))/2),0x0010000000000000)
    check('negative zeros add to negative zero',add(SIGN,SIGN),SIGN)
    check('exact cancellation is positive zero',add(ONE,ONE|SIGN),0)
    check('second-source subtraction NaN keeps sign',sub(ONE,0xfff0000000000123),0xfff8000000000123)
    check('first signaling NaN beats second quiet payload',add(0x7ff0000000000123,0xfff8000000000456),0x7ff8000000000123)
    check('first quiet NaN beats second signaling payload',mul(0xfff8000000000456,0x7ff0000000000123),0xfff8000000000456)
    check('opposite infinities create indefinite',add(INF,INF|SIGN),INDEFINITE)
    check('infinity times negative zero creates indefinite',mul(INF,SIGN),INDEFINITE)
    check('positive zero clamp retains negative corrected zero',rate([SIGN],INTEREST|SIGN,ONE,0),SIGN)
    check('negative zero clamp changes that corrected zero',rate([SIGN],INTEREST|SIGN,ONE,SIGN),0)
    check('absence maps separately from active negative zero',rate(None,None,None,0),None)
    return {'count':len(checks),'checks':checks,'kind':'Independent exact mathematics, not target execution or broad generic-float API tests.'}

def cases():
    result=[];seen=set()
    def put(category,samples,interest=None,multiplier=None,clamp=0):
        samples=None if samples is None else tuple(samples)
        key=(samples,interest,multiplier,clamp)
        if key not in seen:seen.add(key);result.append((category,*key))
    values=[0,SIGN,1,SIGN|1,2,SIGN|2,4,SIGN|4,12,SIGN|12,0x000fffffffffffff,0x0010000000000000,
            0x0010000000000001,ONE,ONE|SIGN,INTEREST,INTEREST|SIGN,CAP-1,CAP,CAP+1,
            CAP|SIGN,(CAP|SIGN)+1,0x4340000000000000,0xc340000000000000,MAX,MAX|SIGN,
            INF,INF|SIGN,0x7ff0000000000001,0xfff0000000000001,0x7ff8000000000001,
            0xfff8000000000456,0x7fffffffffffffff,0xffffffffffffffff]
    configs=[(None,None,0),(None,None,SIGN),(0,ONE,0),(INTEREST|SIGN,ONE,0),
             (INTEREST|SIGN,ONE,SIGN),(ONE,ONE,INTEREST),(ONE|SIGN,ONE,INTEREST|SIGN),
             (0,0,0),(0,SIGN,0),(0,INF,0),(0,INF|SIGN,0),(0,ONE,INF),
             (0,ONE,0xfff0000000000007),(0x7ff0000000000123,ONE,0),
             (0,0xfff8000000000456,0),(0,0x2000000000000000,0)]
    for interest,multiplier,clamp in configs:
        put('missing',None,interest,multiplier,clamp);put('present-empty',[],interest,multiplier,clamp)
        for value in values:put('single-class', [value],interest,multiplier,clamp)
    for a in values:
        for b in values:
            put('ordered-two-samples',[a,b],0,ONE,0)
    for count in [1,2,3,4,7,8,9,15,16,17,31,32,33,63,64,65]:
        for value in [0,SIGN,1,SIGN|1,4,12,INTEREST,INTEREST|SIGN,MAX,INF,0x7ff0000000000123]:
            put('bulk-and-tail',[value]*count,INTEREST|SIGN,ONE,0)
        for pos in sorted({0,count//2,count-1}):
            for value in [1,0x7ff0000000000123,0xfff8000000000456,INF]:
                seq=[0]*count;seq[pos]=value;put('position-sensitive',seq,0,ONE,0)
    for seq in [[0x4340000000000000,ONE,0xc340000000000000],
                [0x4340000000000000,0xc340000000000000,ONE],
                [INF,INF|SIGN,0xfff8000000000456],
                [0xfff8000000000456,INF,INF|SIGN],
                [MAX,MAX,MAX|SIGN],[MAX,MAX|SIGN,MAX]]:
        for config in configs:put('order-or-exception-priority',seq,*config)
    for value in values:
        for context in [None,0,SIGN,INTEREST,INTEREST|SIGN,INF,0x7ff0000000000123]:
            put('optional-interest',[value],context,ONE,INTEREST)
            put('optional-multiplier',[value],0,context,0)
            put('raw-clamp',[value],INTEREST|SIGN,ONE,0 if context is None else context)
    # Deterministic bit-pattern inputs; no random library/platform generator.
    state=0x5e2d91b74c6a083f
    def word():
        nonlocal state
        state=(state*6364136223846793005+1442695040888963407)&((1<<64)-1)
        return state
    for i in range(512):
        seq=[word() for _ in range(1+i%19)]
        put('deterministic-raw-patterns',seq,word(),word(),word())
    return result

def generate(out):
    require(not out.exists(),'fresh corpus directory')
    checks=math_checks();input_lines=[];expected_lines=[];provenance=[];counts=Counter()
    for i,(category,samples,interest,multiplier,clamp) in enumerate(cases()):
        identifier=f'{i:016x}'
        optional=lambda value:'-' if value is None else f'{value:016x}'
        sample_fields=['-'] if samples is None else [str(len(samples)),*(f'{b:016x}' for b in samples)]
        input_lines.append('\t'.join([identifier,optional(interest),optional(multiplier),f'{clamp:016x}',*sample_fields])+'\n')
        value=rate(samples,interest,multiplier,clamp)
        expected_lines.append(f'{identifier}\t{optional(value)}\t{0 if value is None else value:016x}\n')
        provenance.append(f'{identifier}\t{category}\n');counts[category]+=1
    raw={'inputs.tsv.gz':''.join(input_lines).encode(),'expected.tsv.gz':''.join(expected_lines).encode(),'provenance.tsv.gz':''.join(provenance).encode()}
    out.mkdir(parents=True)
    files={}
    for name,content in raw.items():
        compressed=gzip.compress(content,mtime=0);(out/name).write_bytes(compressed)
        files[name]={'raw_sha256':hashlib.sha256(content).hexdigest(),'stored_sha256':hashlib.sha256(compressed).hexdigest(),'raw_bytes':len(content),'stored_bytes':len(compressed)}
    metadata={'cases':len(input_lines),'categories':dict(sorted(counts.items())),'math_controls':checks,'files':files,'scope':'Exact rational Intel-SSE value specification; no native execution. Written before production; corpus will freeze before the separate root gate.'}
    (out/'summary.json').write_text(json.dumps(metadata,indent=2)+'\n')
    return metadata

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--out',type=Path,required=True)
    args=parser.parse_args();print(json.dumps(generate(args.out),indent=2))
