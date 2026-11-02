#!/usr/bin/env python3
"""Finite arithmetic/sequence certificates for the manual proof, not an evaluator."""
import bisect
import json
import math
import random
import struct
import corpus as c


def check():
    result={}
    # A positive reciprocal error below one divisor-unit proves floor division
    # for every nonnegative numerator through the stated maximum. Signed
    # high-product + sign correction then gives truncation toward zero.
    reciprocal=[]
    for name,m,d,k,bound in [
        ('nanoseconds',0x112e0be826d694b3,10**9,90,1<<63),
        ('seconds',0x1845c8a0ce512957,86400,77,1<<63),
        ('year',0x51eb851f,400,39,262144),
        ('cycle-day',0x396b06bd,146097,47,252850)]:
        error=m*d-(1<<k)
        c.need(0 < error and bound*error < 1<<k,'reciprocal bound '+name)
        reciprocal.append(dict(name=name,multiplier=hex(m),divisor=d,shift=k,
                               magnitude_bound=bound,error=error,strict_margin=(1<<k)-bound*error))
    result['reciprocal_bounds']=reciprocal
    # Native cycle approximation followed by at most one predecessor correction.
    # This is an exhaustive finite integer identity, not a captured row interpreter.
    for day in range(146097):
        hi=day*0x6719f361>>32
        approx=(((day-hi)>>1)+hi)>>8
        c.need(approx==day//365,'365 quotient identity')
        prefix_leaps=c.PREFIX[approx]-365*approx
        remain=day-365*approx-prefix_leaps
        year=approx if remain>=0 else approx-1
        ordinal=day-c.PREFIX[year]+1
        c.need(year==bisect.bisect_right(c.PREFIX,day)-1 and 1<=ordinal<=365+c.leap(year),'calendar partition')
    result['calendar_partition_days']=146097
    # Year-start chronology and packed canonical order, covering every admitted year.
    for year in range(c.MIN_YEAR,c.MAX_YEAR+1):
        closed=365*year+(year+3)//4-(year+99)//100+(year+399)//400
        c.need(c.year_start(year)==closed,'independent cycle/closed year relation')
        last=c.timestamp(year,365+c.leap(year))[0]
        if year<c.MAX_YEAR:c.need(last<c.timestamp(year+1)[0],'signed packed chronology')
    result['canonical_years']=c.MAX_YEAR-c.MIN_YEAR+1
    # Symbolic token sequence identities cover every admissible local insertion
    # gap. Payload identity is preserved by reference, not reconstructed values.
    nonsplit=0
    for n in range(11):
        for i in range(n+1):
            keys=[object() for _ in range(n)];x=object();actual=keys[:i]+[x]+keys[i:]
            c.need(actual[:i]==keys[:i] and actual[i] is x and actual[i+1:]==keys[i:],'shift identity')
            nonsplit+=1
    splits=[]
    for i in range(12):
        keys=[object() for _ in range(11)];x=object()
        pivot=4 if i<5 else 5 if i in (5,6) else 6
        right=i>pivot
        j=i-pivot-1 if right else i
        left,rightkeys=keys[:pivot],keys[pivot+1:]
        if right:rightkeys=rightkeys[:j]+[x]+rightkeys[j:]
        else:left=left[:j]+[x]+left[j:]
        c.need(left+[keys[pivot]]+rightkeys==keys[:i]+[x]+keys[i:],'split inorder identity')
        c.need(5<=len(left)<=6 and 5<=len(rightkeys)<=6,'split occupancy')
        # Internal split partitions all old edges; insertion adds one right edge
        # immediately after the replaced/split child. Parent/index repair assigns
        # exactly the array position to every affected child.
        old_edges=[object() for _ in range(12)];new_edge=object()
        el,er=old_edges[:pivot+1],old_edges[pivot+1:]
        target=er if right else el;target.insert(j+1,new_edge)
        c.need(el+er==old_edges[:i+1]+[new_edge]+old_edges[i+1:],'edge conservation')
        c.need(len(el)==len(left)+1 and len(er)==len(rightkeys)+1,'edge/key arity')
        for part in (el,er):c.need([index for index,_ in enumerate(part)]==list(range(len(part))),'parent index repair')
        splits.append(dict(gap=i,pivot=pivot,side='right' if right else 'left',index=j,
                           left_count=len(left),right_count=len(rightkeys)))
    result.update(nonfull_gaps=nonsplit,full_node_splits=splits)
    # Independent host IEEE arithmetic checks examples only; the integer
    # definition and PROOF supply the all-bit class argument.
    rng=random.Random(1133)
    bits=[rng.getrandbits(64) for _ in range(10000)]
    bits += [s['delay'] for case in c.cases() for s in case['steps'] if s['delay'] is not None]
    for b in bits:
        x=struct.unpack('<d',b.to_bytes(8,'little'))[0]*1e9
        expect=0 if not math.isfinite(x) else min(c.LIMIT,max(-(1<<63),math.trunc(x)))
        c.need(c.delay_ns(b)==expect,'independent host product example')
    result['host_float_examples']=len(bits)
    result['scope']='Mathematical identities and finite host examples; no captured execution/emulation and no corpus-based universal proof.'
    return result


if __name__=='__main__':print(json.dumps(check(),separators=(',',':')))
