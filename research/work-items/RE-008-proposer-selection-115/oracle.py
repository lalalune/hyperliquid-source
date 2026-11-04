#!/usr/bin/env python3
"""Node115 mathematical oracle, frozen before node115 Rust adaptation; no captured instruction interpretation.

Binary64 operations are rounded from integer ratios, including a single exact
multiply-add. History uses maximization, set transforms use mathematical sets,
and replacement uses ranked tuples rather than the target's tree/sort machinery.
"""
from fractions import Fraction
import gzip
import hashlib
import json
from pathlib import Path
import random

HERE = Path(__file__).resolve().parent
U64 = (1 << 64) - 1
MISSING = 0x28
EMPTY = 0x0f
SELECTED = 0x2e


def rn(value):
    """Positive finite rational -> binary64 RN-even bits (normal result or zero)."""
    value = Fraction(value)
    if not value:
        return 0
    a, b = value.numerator, value.denominator
    if a < 0:
        raise ValueError('oracle domain is nonnegative arithmetic')
    exponent = a.bit_length() - b.bit_length()
    if Fraction(2) ** exponent > value:
        exponent -= 1
    shift = 52 - exponent
    dividend, divisor = (a << shift, b) if shift >= 0 else (a, b << -shift)
    q, r = divmod(dividend, divisor)
    q += 2 * r > divisor or (2 * r == divisor and q % 2 == 1)
    if q == 1 << 53:
        q >>= 1
        exponent += 1
    if not (-1022 <= exponent <= 1023):
        raise ValueError('unexpected arithmetic exponent')
    return ((exponent + 1023) << 52) | (q - (1 << 52))


def rational(bits):
    if bits == 0:
        return Fraction(0)
    e = (bits >> 52) & 2047
    if bits >> 63 or not 0 < e < 2047:
        raise ValueError('not a positive normal')
    return Fraction((1 << 52) + (bits & ((1 << 52) - 1))) * Fraction(2) ** (e - 1075)


def event(i, n, w, j):
    inverse = rn(1 / rational(rn(w)))
    product = rn(rational(rn(i)) * rational(inverse))
    base = rn(rational(product) / rational(rn(n)))
    point = rn(rational(inverse) * rational(rn(j)) + rational(base))
    return inverse, base, point


def history(base, rounds, query):
    threshold = min(U64, base + 2000)
    key = base if query < threshold else max(base, (query - 200) % (1 << 64))
    matches = [(r, i) for i, r in enumerate(rounds) if r <= key]
    return key, max(matches)[1] if matches else -1


def prepare(blocked, extra, rows):
    members = set(blocked) | set(extra)
    kept = [(k, w) for k, w in rows if k not in set(blocked)]
    total = min(U64, sum(w for _, w in kept))
    threshold = max(0, total - 1000) // len(members) if members else 0
    adjusted = [(k, max(0, w - threshold) if k in members else min(U64, 3 * w))
                for k, w in kept]
    fallback = sorted([(min(U64, 3 * w), k) for k, w in adjusted if k in members], reverse=True)
    return total, threshold, adjusted, fallback, members


def ordered(events):
    def key(e):
        bits, tag, payload = e
        # Float sign partition implements mathematical IEEE total-order coding,
        # independently of the source's f64::total_cmp.
        rank = U64 - bits if bits & (1 << 63) else bits + (1 << 63)
        return rank, tag, payload if tag else ''
    return sorted(events, key=key)


def schedule(blocked, extra, rows, round_, initial):
    prep = prepare(blocked, extra, rows)
    if prep is None:
        return 'OVERFLOW'
    _, _, adjusted, fallback, members = prep
    events = ordered([(event(i, len(adjusted), w, j)[2], int(k not in members), k if k not in members else '-')
                      for i, (k, w) in enumerate(adjusted) for j in range(w)])
    result = []
    counts = dict((k, c) for c, k in fallback)
    active = [k for _, k in fallback]
    for _, tag, key in events:
        if tag:
            result.append(key)
        elif active:
            # The order is frozen during the three removals; it is ranked again
            # only after the complete batch. One/two entries wrap in that batch.
            chosen = [active[t % len(active)] for t in range(3)]
            for k in chosen:
                counts[k] = max(0, counts[k] - 1)
            result.extend(chosen)
            active = sorted((k for k in active if counts[k]), key=lambda k: (counts[k], k), reverse=True)
    image = bytearray.fromhex(initial)
    if not result:
        image[0] = EMPTY
    else:
        image[0] = SELECTED
        image[1:21] = bytes.fromhex(result[round_ % len(result)])
    fields = [image.hex(), str(len(events))]
    for bits, tag, key in events:
        fields.extend((f'{bits:016x}', str(tag), key))
    fields.append(str(len(result)))
    fields.extend(result)
    return ' '.join(fields)


def values(tokens, count, width=1):
    return [tuple(next(tokens) for _ in range(width)) if width > 1 else next(tokens) for _ in range(count)]


def parse_rows(tokens):
    return [(k, int(w)) for k, w in values(tokens, int(next(tokens)), 2)]


def evaluate(line):
    t = iter(line.split())
    command = next(t)
    if command == 'H':
        base, query, count = (int(next(t)) for _ in range(3))
        q, i = history(base, [int(x) for x in values(t, count)], query)
        answer = f'H {q} {i}'
    elif command == 'E':
        answer = 'E ' + ' '.join(f'{x:016x}' for x in event(*(int(next(t)) for _ in range(4))))
    elif command == 'Q':
        entries = [(int(b, 16), int(tag), k) for b, tag, k in values(t, int(next(t)), 3)]
        answer = 'Q ' + ' '.join(f'{b:016x} {tag} {k if tag else "-"}' for b, tag, k in ordered(entries))
    elif command in ('P', 'S'):
        blocked = values(t, int(next(t)))
        extra = values(t, int(next(t)))
        rows = parse_rows(t)
        if command == 'S':
            answer = 'S ' + schedule(blocked, extra, rows, int(next(t)), next(t))
        else:
            p = prepare(blocked, extra, rows)
            if p is None:
                answer = 'P OVERFLOW'
            else:
                total, threshold, adjusted, fallback, _ = p
                answer = ' '.join(['P', str(total), str(threshold), str(len(adjusted))]
                     + [s for k, w in adjusted for s in (k, str(w))]
                     + [str(len(fallback))] + [s for w, k in fallback for s in (str(w), k)])
    elif command == 'G':
        stake_base, execution, base, query, counter, count = (int(next(t)) for _ in range(6))
        q, index = history(base, [int(x) for x in values(t,count)], query)
        limit = min(U64, max(stake_base + 2000, execution + 201))
        warning = int(query >= limit)
        answer = f'G {limit} {q} {index} {(counter+warning)%(1<<64)} {warning}'
    elif command == 'R':
        head, count, query, capacity = (int(next(t)) for _ in range(4))
        physical = [int(x) for x in values(t, capacity)]
        logical = [physical[(head+i)%capacity] for i in range(count)]
        eligible = [i for i,r in enumerate(logical) if r <= query]
        prefix = len(eligible)
        index = (head+prefix-1)%capacity if prefix else -1
        answer = f'R {prefix} {index}'
    elif command == 'F':
        selected_round, query_round, base1, base2, execution, counter = (int(next(t)) for _ in range(6))
        scratch = next(t)
        hs = []
        for _ in range(int(next(t))):
            r = int(next(t)); hs.append((r, values(t, int(next(t)))))
        hm = []
        for _ in range(int(next(t))):
            r = int(next(t)); hm.append((r, parse_rows(t)))
        extra = values(t, int(next(t)))
        initial = next(t)
        limit = min(U64, max(base2+2000, execution+201))
        warning = int(query_round >= limit)
        q1,i1 = history(base1,[r for r,_ in hs],query_round)
        counter = (counter+warning)%(1<<64)
        q2,i2 = history(base2,[r for r,_ in hm],query_round) if i1>=0 else ('-',-1)
        if i1>=0: counter = (counter+warning)%(1<<64)
        if i1<0 or i2<0:
            image = bytearray.fromhex(scratch)
            image[0] = MISSING
            image[8:16] = query_round.to_bytes(8,'little')
            prefix = f'F {q1} {i1} {q2} {i2 if i1>=0 else "-"} {counter} '
            answer = prefix + image.hex()
        else:
            answer = f'F {q1} {i1} {q2} {i2} {counter} ' + schedule(hs[i1][1],extra,hm[i2][1],selected_round,initial)
    else:
        raise ValueError(command)
    if list(t):
        raise ValueError('trailing input')
    return answer


def corpus():
    rng = random.Random(0x4b31e70)
    keys = [bytes([0] * 19 + [i]).hex() for i in range(1, 41)]
    keys += [bytes([128] + [0] * 19).hex(), bytes([255] * 20).hex()]
    initial = bytes(range(72)).hex()
    lines = []
    for base in [0, 1, 199, 200, 1999, 2000, 1 << 32, (1 << 63) - 1, U64-2001, U64-2000, U64-1999, U64-1, U64]:
        rounds = sorted({0, base, max(0, base-1), min(U64,base+1), U64})
        for q in sorted({0, 1, 199, 200, 1999, 2000, base, max(0,base-1), min(U64,base+1999), min(U64,base+2000), min(U64,base+2001), U64}):
            for rs in ([], rounds, [min(U64,base+1)]):
                lines.append(' '.join(map(str,['H',base,q,len(rs),*rs])))
    for _ in range(650):
        b=rng.getrandbits(64); q=rng.getrandbits(64); rs=sorted({rng.getrandbits(64) for _ in range(rng.randrange(9))})
        lines.append(' '.join(map(str,['H',b,q,len(rs),*rs])))
    # Covers every integer conversion/reciprocal limb boundary without allocating
    # a schedule of that length. No claim of native huge-array execution.
    ws=[1,2,3,5,7,10,17,31,127,1000,1001,(1<<32)-1,1<<32,(1<<53)-1,1<<53,(1<<53)+1,(1<<63)-1,1<<63,U64]
    for w in ws:
        for n in [1,2,3,7,21,257,(1<<53)+1,(1<<58)-1]:
            for i in sorted({0,n//2,n-1}):
                for j in sorted({0,w//2,w-1}):
                    lines.append(f'E {i} {n} {w} {j}')
    for _ in range(800):
        n=rng.randrange(1,1<<58);i=rng.randrange(n);w=rng.randrange(1,1<<64);j=rng.randrange(w)
        lines.append(f'E {i} {n} {w} {j}')
    floatbits=[0,1,0x8000000000000000,0x8000000000000001,0x3ff0000000000000,0x7ff0000000000000,0xfff0000000000000,0x7ff8000000000000,0xfff8000000000001,U64]
    for _ in range(120):
        rows=[(rng.choice(floatbits),rng.randrange(2),rng.choice(keys)) for _ in range(rng.randrange(2,25))]
        lines.append('Q '+str(len(rows))+' '+' '.join(f'{b:016x} {t} {k}' for b,t,k in rows))
    def prefix(blocked,extra,rows):
        return ' '.join([str(len(blocked)),*blocked,str(len(extra)),*extra,str(len(rows)),*[s for k,w in rows for s in(k,str(w))]])
    # Below/at/above 1000, full 20-byte lexicographic ties, 1/2/3 replacement
    # wrap, zero quotas, empty sets, subset overlaps, and sum overflow.
    for n in [0,1,2,3,4,7,20,21,22,40]:
        for w in [0,1,2,3,7]:
            rows=[(k,w) for k in keys[:n]]
            for step in [1,2,3,43]:
                extra=keys[:n:step];blocked=keys[:n:7] if step==3 else []
                pre=prefix(blocked,extra,rows)
                lines += ['P '+pre,'S '+pre+' '+str(rng.getrandbits(64))+' '+initial]
    for weights in [[999],[1000],[1001],[1002],[500,501],[999,2],[2001,1],[U64],[U64,1],[U64//3+1,0],[(1<<63),1]]:
        rows=list(zip(keys,weights))
        for extra in [[],keys[:len(rows)],keys[:len(rows)+1]]:
            pre=prefix([],extra,rows);lines.append('P '+pre)
            if sum(weights)<3000:
                lines.append('S '+pre+' 18446744073709551615 '+initial)
    for _ in range(350):
        n=rng.randrange(9); rows=sorted((k,rng.randrange(15)) for k in rng.sample(keys,n))
        blocked=sorted(rng.sample(keys,rng.randrange(6)));extra=sorted(rng.sample(keys,rng.randrange(12)))
        pre=prefix(blocked,extra,rows);lines += ['P '+pre,'S '+pre+' '+str(rng.getrandbits(64))+' '+initial]
    # Explicit overlap/threshold witnesses that were a historical post-source
    # supplement are part of this new node115 pre-adaptation corpus.
    for r in (1,2,3):
        for a in (1,1000,2001):
            for b in (1001,2000,3333):
                lines.append('P '+prefix(keys[:r],keys[:r+1],[(keys[0],U64),(keys[r],a),(keys[r+1],b)]))
    for stake_base in (0,1,U64-2001,U64-2000,U64-1999,U64):
        for execution in (0,199,200,1999,U64-202,U64-201,U64-200,U64):
            limit=min(U64,max(stake_base+2000,execution+201))
            for query in sorted({0,max(0,limit-1),limit,min(U64,limit+1),U64}):
                for counter in (0,U64):
                    base=rng.choice([stake_base,0,U64-1000])
                    rs=sorted({0,base,U64})
                    lines.append(' '.join(map(str,['G',stake_base,execution,base,query,counter,len(rs),*rs])))
    for capacity in (0,1,2,3,4,7,8,16,21,64,65):
        for head in range(max(1,capacity)):
            for count in sorted({0,capacity//2,capacity}):
                logical=list(range(3,3+count*11,11))
                physical=[U64]*capacity
                for i,r in enumerate(logical):physical[(head+i)%capacity]=r
                for query in sorted({0,2,3,4,14,max(logical,default=0),max(logical,default=0)+1,U64}):
                    lines.append(' '.join(map(str,['R',head,count,query,capacity,*physical])))
    for _ in range(260):
        selected=rng.getrandbits(64)
        query=rng.choice([0,1999,2000,2001,U64,rng.getrandbits(64)])
        base1=rng.choice([0,1,U64-1000]);base2=rng.choice([0,199,U64])
        execution=rng.choice([0,199,U64-201,U64]);counter=rng.choice([0,U64-1,U64])
        hs=[(r,sorted(rng.sample(keys,rng.randrange(4)))) for r in sorted(rng.sample([0,1,100,1800,2000,U64],rng.randrange(7)))]
        hm=[(r,sorted((k,rng.randrange(7)) for k in rng.sample(keys,rng.randrange(5)))) for r in sorted(rng.sample([0,1,100,1800,2000,U64],rng.randrange(7)))]
        extra=sorted(rng.sample(keys,5))
        scratch=rng.randbytes(72).hex()
        fields=['F',str(selected),str(query),str(base1),str(base2),str(execution),str(counter),scratch,str(len(hs))]
        for r,ks in hs:fields += [str(r),str(len(ks)),*ks]
        fields += [str(len(hm))]
        for r,rows in hm:fields += [str(r),str(len(rows)),*[s for k,w in rows for s in(k,str(w))]]
        lines.append(' '.join(fields+[str(len(extra)),*extra,initial]))
    return lines


def freeze():
    if (HERE/'rust/lib.rs').exists() or (HERE/'freeze.json').exists():
        raise SystemExit('refuse to overwrite pre-Rust freeze')
    inputs=corpus();expected=[evaluate(x) for x in inputs]
    if any(len(x.split()) < 2 for x in expected): raise ValueError('empty answer')
    record={'schema':1,'stage':'before first node115 Rust adaptation; historical node94 source existed and was inspected','oracle_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'cases':len(inputs),'counts':{c:sum(x.startswith(c+' ') for x in inputs) for c in 'HEQPSFGR'},'files':{}}
    for name,rows in [('inputs',inputs),('expected',expected)]:
        raw=('\n'.join(rows)+'\n').encode();compressed=gzip.compress(raw,mtime=0)
        (HERE/f'{name}.txt.gz').write_bytes(compressed)
        record['files'][name]={'raw_sha256':hashlib.sha256(raw).hexdigest(),'raw_bytes':len(raw),'gzip_sha256':hashlib.sha256(compressed).hexdigest()}
    (HERE/'freeze.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps(record,indent=2))


if __name__=='__main__':
    freeze()
