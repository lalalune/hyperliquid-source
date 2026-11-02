#!/usr/bin/env python3
"""Independent flat-relation/history oracle, integer binary64 rounding and calendar.

No captured instruction evaluation, target execution, Rust, or expected-value
input to a client. The finite examples supplement the manual universal proof.
"""
from __future__ import annotations
import bisect
import gzip
import hashlib
import json
import struct

MIN_YEAR, MAX_YEAR = -262143, 262142
DAY = 86_400_000_000_000
LIMIT = (1 << 63) - 1


def need(ok, message):
    if not ok:
        raise ValueError(message)


def leap(y):
    return y % 4 == 0 and (y % 100 != 0 or y % 400 == 0)


# Calendar oracle uses a finite partition of a 400-year cycle. It does not
# read captured tables or implement the binary's reciprocal/year approximation.
PREFIX = [0]
for _y in range(400):
    PREFIX.append(PREFIX[-1] + 365 + leap(_y))
need(PREFIX[-1] == 146097, 'calendar cycle')


def year_start(y):
    q, r = divmod(y, 400)
    return q * PREFIX[-1] + PREFIX[r]


def flag(y):
    return (year_start(y) + 3) % 7 + 1 + (0 if leap(y) else 8)


def timestamp(y=2024, ordinal=1, second=0, nano=0):
    return [(y << 13) | (ordinal << 4) | flag(y), second, nano]


def valid_time(t):
    date, second, nano = t
    y, ordinal = date >> 13, (date >> 4) & 511
    return (-(1 << 31) <= date < (1 << 31) and MIN_YEAR <= y <= MAX_YEAR
            and 1 <= ordinal <= 365 + leap(y) and date & 15 == flag(y)
            and 0 <= second < 86400 and 0 <= nano < 1_000_000_000)


def total_time(t):
    need(valid_time(t), 'canonical timestamp')
    d, s, n = t
    return (year_start(d >> 13) + ((d >> 4) & 511) - 1) * DAY + s * 1_000_000_000 + n


def from_total(n):
    day, rem = divmod(n, DAY)
    cycle, within = divmod(day, PREFIX[-1])
    yr = bisect.bisect_right(PREFIX, within) - 1
    y, ordinal = cycle * 400 + yr, within - PREFIX[yr] + 1
    if not MIN_YEAR <= y <= MAX_YEAR:
        return None
    second, nano = divmod(rem, 1_000_000_000)
    return timestamp(y, ordinal, second, nano)


def delay_ns(bits):
    """Exact integer computation of RN-even(binary64(bits)*1e9), then conversion.

    Finite-class product rounding is performed once at a 53-significand-bit
    quantum (or the minimum subnormal quantum). Nonfinite product -> zero;
    otherwise truncate magnitude and saturate to signed i64.
    """
    need(0 <= bits < 1 << 64, 'delay bits')
    sign, exponent, fraction = bits >> 63, (bits >> 52) & 2047, bits & ((1 << 52) - 1)
    if exponent == 2047:
        return 0
    significand = fraction if exponent == 0 else (1 << 52) + fraction
    if not significand:
        return 0
    power = -1074 if exponent == 0 else exponent - 1075
    product = significand * 1_000_000_000
    shift = max(product.bit_length() - 53, -1074 - power, 0)
    if shift:
        q, r = divmod(product, 1 << shift)
        half = 1 << (shift - 1)
        product = q + (r > half or (r == half and q & 1))
        power += shift
    if product.bit_length() - 1 + power > 1023:
        return 0
    magnitude = product << power if power >= 0 else product >> -power
    return -min(magnitude, 1 << 63) if sign else min(magnitude, LIMIT)


def fbits(value):
    return struct.unpack('<Q', struct.pack('<d', value))[0]


def observe(initial, steps):
    """Flat list with linear exact-key lookup; no source BTreeMap implementation."""
    rows = json.loads(json.dumps(initial))
    seen = set()
    for row in rows:
        key = (row['round'], row['hash'])
        need(key not in seen and valid_time(row['stamp']), 'initial row')
        need(row['sent'] in (False, True) and row['reasons'] == sorted(set(row['reasons'])), 'row fields')
        seen.add(key)
    outputs = []
    for step in steps:
        key = (step['round'], step['hash'])
        if not valid_time(step['time']):
            outputs.append({'status': 'invalid_time', 'snapshot': sorted(rows, key=lambda r:(r['round'], r['hash']))})
            outputs[-1] = json.loads(json.dumps(outputs[-1]))
            continue
        row = next((r for r in rows if (r['round'], r['hash']) == key), None)
        registered = row is None
        if registered:
            row = dict(round=step['round'], hash=step['hash'], stamp=step['time'][:], reasons=[], sent=False)
            rows.append(row)
        row['reasons'] = sorted(set(row['reasons']) | {step['reason']})
        nanos = 1_000_000_000 if step['delay'] is None else delay_ns(step['delay'])
        deadline = from_total(total_time(row['stamp']) + nanos)
        if deadline is None:
            # New safe refusal policy: the registration and reason remain;
            # native correspondence excludes this panic-boundary case.
            status = 'deadline_range'
        elif total_time(step['time']) < total_time(deadline) or row['sent']:
            status = 'held'
        else:
            row['sent'] = True
            status = 'request'
        outputs.append(json.loads(json.dumps(dict(status=status, registered=registered,
            deadline=deadline, request=list(key) if status=='request' else None,
            snapshot=sorted(rows, key=lambda r:(r['round'], r['hash']))))))
    return outputs


def h(n):
    return hashlib.sha256(('throttle-key-'+str(n)).encode()).hexdigest()


def step(time=None, reason=0, delay=None, round=5, key=0):
    return dict(round=round, hash=h(key), time=timestamp() if time is None else time,
                reason=reason, delay=delay)


def cases():
    c=[]
    def add(name, steps, initial=None, policy=False):
        c.append(dict(name=name, initial=initial or [], steps=steps,
                      domain='new_safe_refusal' if policy else 'native_corresponding_under_premises'))
    add('default-register-wait-equal-once-reasons', [step(),step(timestamp(second=0,nano=999999999),1),
        step(timestamp(second=1),2),step(timestamp(second=2),255),step(timestamp(second=3),2)])
    add('vote-explicit-015-boundary', [step(delay=0x3fc3333333333333),step(timestamp(nano=149999999),3,delay=0x3fc3333333333333),step(timestamp(nano=150000000),4,delay=0x3fc3333333333333),step(timestamp(second=1),255,delay=0x3fc3333333333333)])
    add('explicit-zero-first-call-and-suppressed-reason', [step(delay=0),step(reason=9,delay=0)])
    add('immutable-stamp-after-backwards-time', [step(timestamp(second=10)),step(timestamp(second=9),1),step(timestamp(second=11),2)])
    add('same-hash-different-round-and-same-round-different-hash', [step(),step(round=6),step(key=1),step(timestamp(second=1)),step(timestamp(second=1),round=6),step(timestamp(second=1),key=1)])
    add('all-reasons-through-held-and-sent', [step(reason=i,delay=fbits(1.0) if i<128 else 0) for i in range(256)]+[step(reason=i) for i in range(255,-1,-1)])
    for count in (0,1,4,5,6,10,11,12,21,65,131):
        add('ordered-history-'+str(count),[step(reason=i%256,round=(i*19)%17,key=i,delay=0) for i in range(count)]+[step(reason=255,key=i,round=(i*19)%17) for i in reversed(range(count))])
    delays={0,1,(1<<52)-1,1<<52, (1<<64)-1,0x7ff0000000000000,0xfff0000000000000,
            0x7ff8000000000000,0x7ff0000000000001,0xfff8123456789abc}
    for exponent in (0,1,2,3,400,500,900,950,960,970,980,990,1000,1010,1020,1022,1023,1024,1030,1040,1050,1060,1070,1080,1090,1100,1500,1990,2045,2046,2047):
        for fraction in (0,1,(1<<51)-1,1<<51,(1<<52)-2,(1<<52)-1):
            for sign in (0,1):delays.add((sign<<63)|(exponent<<52)|fraction)
    for value in (1e-9,0.5e-9,1.5e-9,1.0,-1.0,86400.0,-86400.0,9223372036.854776,-9223372036.854776,1e300,-1e300):
        v=fbits(value)
        for delta in (-2,-1,0,1,2):delays.add((v+delta)&((1<<64)-1))
    for i,b in enumerate(sorted(delays)):
        ns=delay_ns(b);base=timestamp(2000,60,43199,999999999);deadline=from_total(total_time(base)+ns)
        add('delay-class-'+str(i),[step(base,delay=b),step(deadline,1,delay=b),step(from_total(total_time(deadline)-1),2,delay=b),step(from_total(total_time(deadline)+1),3,delay=b)])
    for y in (MIN_YEAR,-200001,-801,-800,-401,-400,-399,-101,-100,-4,-1,0,1,4,99,100,399,400,1900,1999,2000,2001,2024,2100,MAX_YEAR):
        for ordinal in (1,59,60,365+leap(y)):
            for ns in (-DAY-1,-1,0,1,DAY+1):
                base=timestamp(y,ordinal,86399,999999999);bits=fbits(ns/1e9);actual=delay_ns(bits)
                destination=from_total(total_time(base)+actual)
                policy=destination is None
                add('calendar-'+str((y,ordinal,ns)),[step(base,delay=bits),step(base,reason=255,delay=bits)],policy=policy)
    for i,bad in enumerate(([0,0,0],timestamp(MIN_YEAR-1),timestamp(MAX_YEAR+1),timestamp(2024,0),timestamp(2023,366),timestamp(second=86400),timestamp(nano=1000000000),[timestamp()[0]^1,0,0])):
        add('refuse-invalid-time-'+str(i),[step(),step(bad,reason=255),step(timestamp(second=1),reason=1)],policy=True)
    for y,delta in ((MIN_YEAR,-1.0),(MAX_YEAR,1.0)):
        base=timestamp(y,1 if delta<0 else 365+leap(y),0 if delta<0 else 86399,0 if delta<0 else 999999999)
        for sent in (False,True):
            initial=[dict(round=5,hash=h(0),stamp=base,reasons=[0],sent=sent)]
            add('deadline-refusal-still-adds-reason-'+str((y,sent)),[step(base,reason=254,delay=fbits(delta)),step(base,reason=255,delay=0)],initial,True)
    return c


def input_frame(case):
    out=bytearray(b'TH01')
    def integer(v,n,signed=False):out.extend(int(v).to_bytes(n,'little',signed=signed))
    def time(t):
        integer(t[0],4,True);integer(t[1],4);integer(t[2],4)
    integer(len(case['initial']),4)
    for row in case['initial']:
        integer(row['round'],8);out.extend(bytes.fromhex(row['hash']));time(row['stamp']);integer(row['sent'],1)
        integer(len(row['reasons']),2);out.extend(row['reasons'])
    integer(len(case['steps']),4)
    for s in case['steps']:
        integer(s['round'],8);out.extend(bytes.fromhex(s['hash']));time(s['time']);integer(s['reason'],1)
        integer(s['delay'] is not None,1)
        if s['delay'] is not None:integer(s['delay'],8)
    return bytes(out)


def generate():
    cs=cases();metadata=[];inputs=[];expected=[]
    for i,c in enumerate(cs):
        ident=f'C{i:06d}'
        metadata.append(json.dumps(dict(id=ident,**c),separators=(',',':')))
        inputs.append(ident+'\t'+input_frame(c).hex())
        expected.append(ident+'\t'+json.dumps(observe(c['initial'],c['steps']),separators=(',',':'),sort_keys=True))
    files={'cases.jsonl':('\n'.join(metadata)+'\n').encode(),'inputs.tsv':('\n'.join(inputs)+'\n').encode(),'expected.tsv':('\n'.join(expected)+'\n').encode()}
    return {name+'.gz':gzip.compress(raw,mtime=0) for name,raw in files.items()}


if __name__=='__main__':
    print(json.dumps(dict(cases=len(cases()),steps=sum(len(x['steps']) for x in cases()),
                         generated_hashes={k:hashlib.sha256(v).hexdigest() for k,v in generate().items()})))
