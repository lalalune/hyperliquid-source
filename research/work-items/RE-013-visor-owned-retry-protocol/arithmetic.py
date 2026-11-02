#!/usr/bin/env python3
"""Independent exact-rational duration dependency and integer sleep certificates.

This is a value specification, not a captured-instruction interpreter.
No production source, native decoder or expected corpus is imported.
"""
import argparse
from fractions import Fraction
import json
from pathlib import Path

BILLION = 10**9
U64_MAX = (1<<64)-1
CHUNK_MAX = (1<<63)-1
OVERFLOW_MIDPOINT = Fraction((1<<1024)-(1<<970))
DEFAULT_BITS = (0x3f50624dd2f1a9fc,0x3fa999999999999a,0x3ff0000000000000)
FIXED_BITS = (0x3ff0000000000000,0x4008000000000000,0x4024000000000000)


def require(ok,message):
    if not ok:
        raise ValueError(message)


def exact_positive(bits):
    require(0<=bits<1<<64,"raw binary64 width")
    sign=bits>>63
    exponent=(bits>>52)&2047
    fraction=bits&((1<<52)-1)
    if sign or exponent==2047:
        return None
    if exponent==0:
        return Fraction(fraction,1<<1074)
    significand=(1<<52)+fraction
    power=exponent-1075
    return Fraction(significand<<power) if power>=0 else Fraction(significand,1<<-power)


def nearest_even(value):
    q,r=divmod(value.numerator,value.denominator)
    return q+int(2*r>value.denominator or (2*r==value.denominator and q%2==1))


def duration_total(bits):
    value=exact_positive(bits)
    if value is None:
        return 0
    if value < 1<<64:
        return nearest_even(value*BILLION)
    # On this admitted fallback domain, finite rounded products saturate to
    # u64::MAX; only the binary64 overflow midpoint distinguishes zero.
    if value*1_000_000>=OVERFLOW_MIDPOINT:
        return 0
    return (U64_MAX//1_000_000)*BILLION+(U64_MAX%1_000_000)*1000


def pair(total):
    require(total>=0,"nonnegative total")
    return divmod(total,BILLION)


def request(total):
    seconds,nanos=pair(total)
    require(seconds<=U64_MAX,"canonical seconds width")
    return min(seconds,CHUNK_MAX),nanos


def valid_remainder(q,n,r,rn):
    return 0<=r<=CHUNK_MAX and 0<=rn<BILLION and (r,rn)<=(q,n)


def certificates():
    defaults=[list(pair(duration_total(b))) for b in DEFAULT_BITS]
    fixed=[list(pair(duration_total(b))) for b in FIXED_BITS]
    require(defaults==[[0,1_000_000],[0,50_000_000],[1,0]],"default literals")
    require(fixed==[[1,0],[3,0],[10,0]],"actual caller literals")
    # A monotone exact-RN projection below 2^64 has its maximum at this
    # greatest representable input; all fallback outcomes are zero or plateau.
    largest_small=0x43efffffffffffff
    maximum=pair(duration_total(largest_small))
    require(maximum==((1<<64)-2048,0),"maximum below discontinuity")
    require(pair(duration_total(0x43f0000000000000))[0]<CHUNK_MAX,"fallback plateau")
    # Derive, rather than import, the scaled-product overflow boundary.
    lo=0x43f0000000000000;hi=0x7fefffffffffffff
    while lo<hi:
        mid=(lo+hi)//2
        if exact_positive(mid)*1_000_000>=OVERFLOW_MIDPOINT:hi=mid
        else:lo=mid+1
    require(lo==0x7eb0c6f7a0b5ed8d,"credited overflow-boundary derivation")
    require(duration_total(lo-1)>0 and duration_total(lo)==0,"overflow neighbors")
    boundaries=(0,1,CHUNK_MAX-1,CHUNK_MAX,CHUNK_MAX+1,2*CHUNK_MAX,U64_MAX)
    nano_values=(0,1,BILLION-1)
    checked=0
    for seconds in boundaries:
        for nanos in nano_values:
            total=seconds*BILLION+nanos
            q,n=request(total)
            require(0<=q<=seconds and q<=CHUNK_MAX,"unsigned chunk bounds")
            retained=seconds-q
            require(total-(q*BILLION+n)==retained*BILLION,"completion recurrence")
            r_values={0,q}
            if q:r_values.add(q-1)
            for r in sorted(r_values):
                for rn in nano_values:
                    admitted=valid_remainder(q,n,r,rn)
                    if not admitted:continue
                    require(retained+r<=seconds<=U64_MAX,"add-back bound")
                    lhs=(retained+r)*BILLION+rn
                    rhs=total-(q*BILLION+n)+(r*BILLION+rn)
                    require(lhs==rhs<=total,"total recurrence")
                    checked+=1
    # Two exact halfway inputs distinguish even-down and odd-up.
    ties=[]
    for bits in (0x3f50000000000000,0x3f68000000000000):
        scaled=exact_positive(bits)*BILLION
        q,r=divmod(scaled.numerator,scaled.denominator)
        require(2*r==scaled.denominator,"exact half witness")
        ties.append(dict(bits=f"{bits:016x}",floor=q,rounded=nearest_even(scaled),floor_parity=q%2))
    require([x["floor_parity"] for x in ties]==[0,1],"both tie parities")
    # Explicit invalid-callback counterexamples prevent a universal claim.
    overflow_add=(U64_MAX-CHUNK_MAX)+(CHUNK_MAX+1)
    require(overflow_add==1<<64 and not valid_remainder(CHUNK_MAX,0,CHUNK_MAX+1,0),"invalid overflow witness")
    require(not valid_remainder(0,1,0,-1),"negative nanos witness")
    return dict(status="PASS exact value certificates only",
                default_pairs=defaults,fixed_pairs=fixed,
                maximum_converter_seconds=maximum[0],maximum_noninterrupted_chunks=2,
                derived_first_scaled_overflow=f"{lo:016x}",finite_valid_addback_checks=checked,
                halfway_witnesses=ties,
                universal_argument="For q=min(S,INT64_MAX),0<=q<=S and0<=r<=q imply0<=(S-q)+r<=S<=u64_MAX. Exact total-nanosecond recurrence follows by distributivity; finite tests are illustrative certificates, not exhaustion of the domain.",
                invalid_counterexamples=[dict(kind="oversized remainder",sum_before_wrap=str(overflow_add),wrapped=0),dict(kind="negative nanos",native_nonpositive_branch_can_advance=True,source_policy="InvalidRemainder")],
                limits=["Original duration proof is credited, not re-proved by finite vectors.",
                        "No captured instructions, host floating point, real sleep or command execution.",
                        "Finite interruption termination is a premise; equal remainder can make no progress."])


def main():
    p=argparse.ArgumentParser();p.add_argument("--out",type=Path,required=True);a=p.parse_args()
    require(not a.out.exists(),"fresh output")
    result=certificates()
    a.out.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    print(json.dumps({k:result[k] for k in ("status","finite_valid_addback_checks","derived_first_scaled_overflow")}))


if __name__=="__main__":
    main()
