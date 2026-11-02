#!/usr/bin/env python3
"""Pre-code grammar fixtures; semantic labels never enter the future client.

The independent oracle is mathematical Python over a flat relation. This file
only chooses finite inputs. Neither file evaluates native code or claims that
sampling proves the full contract. All serialization here is fixed transport
or explicitly selected wire bytes, not a copied reference implementation.
"""
from __future__ import annotations
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import random
import oracle

HERE = Path(__file__).resolve().parent
MAX = (1 << 64) - 1


def var(value, width=None):
    if width is None:
        width = 0 if value <= 250 else 2 if value <= 65535 else 4 if value <= 0xffffffff else 8
    if width == 0:
        if not 0 <= value <= 250:
            raise ValueError('inline range')
        return bytes([value])
    return bytes([{2: 251, 4: 252, 8: 253}[width]]) + value.to_bytes(width, 'little')


def signature(seed=0, recovery=0, limb_bytes=None):
    if limb_bytes is None:
        values = [0, 250, 251, 65535, 65536, 0xffffffff, 1 << 32, MAX]
        limb_bytes = [var(values[(i + seed) % len(values)]) for i in range(8)]
    return b''.join(limb_bytes) + bytes([recovery])


def key(n):
    return n.to_bytes(20, 'big')


def rows(entries):
    return var(len(entries)) + b''.join(k + v for k, v in entries)


def map_greeting(entries=(), second=None, vector=b'', scalar=0):
    return (b'\0' + var(len(vector)) + vector + var(scalar) + bytes([second is not None])
            + bytes(range(32)) + rows(entries) + (rows(second) if second is not None else b''))


def record(a=0, b=0, seed=0):
    return var(a) + var(b) + bytes((i * 37 + seed) % 256 for i in range(2048))


def records_greeting(records=None):
    if records is None:
        records = [record(0, 250, 1), record(251, 65536, 2), record(MAX, 1 << 32, 3)]
    return b'\0\0\0\2' + b''.join(records)


def inputs():
    cases = []
    seen = set()

    def add(name, data, *, enabled=False, limit=0, charged=0, cursor=0, op=0, family=None):
        case = dict(data=bytes(data), enabled=enabled, limit=limit, charged=charged, cursor=cursor, op=op)
        frame = oracle.encode_input(case)
        if frame not in seen:
            seen.add(frame)
            case.update(name=name, family=family or name.split('-')[0])
            cases.append(case)

    base = [bytes([t]) for t in range(2, 6)]
    base += [b'\1' + b''.join(var(x) for x in (MAX, 251, 1 << 32)),
             map_greeting(), map_greeting([(key(3), signature(1, 255))], []),
             map_greeting([(key(2), signature(2, 7)), (key(1), signature(3, 8)),
                           (key(2), signature(4, 9))], [(key(0), signature(5, 10))], b'abc', MAX),
             records_greeting()]
    for i, data in enumerate(base):
        add(f'base-{i}', data)
        add(f'base-enabled-{i}', data, enabled=True, limit=MAX)
        add(f'base-disabled-initial-max-{i}', data, charged=MAX)
        add(f'base-caller-{i}', data, op=1, limit=MAX)
        add(f'base-caller-trailing-{i}', data+b'not-consumed', op=1, limit=MAX)
        add(f'base-cursor-prefix-{i}', b'ignored-prefix'+data+b'not-consumed', cursor=14)

    # Complete marker byte alphabet and both sides of every wrapper threshold.
    for role, prefix in [('outer', b''), ('nested', b'\0\0\0'), ('u64', b'\1')]:
        for marker in range(256):
            for n in range(11):
                tail = (bytes([marker]) + bytes((i*53+17) % 256 for i in range(9)))[:n]
                add(f'marker-{role}-{marker}-{n}', prefix+tail, family='marker')

    # Every 2048-byte field shortage, independently in all three records.
    for index in range(3):
        prefix = b'\0\0\0\2' + b''.join(record(0, 0, j) for j in range(index)) + b'\0\0'
        raw = bytes((i*19+index) % 256 for i in range(2048))
        for n in range(2049):
            add(f'fixed-record-{index}-{n}', prefix+raw[:n], family='fixed')
    for n in range(33):
        add(f'fixed-hash-{n}', b'\0\0\0\0'+bytes(range(n)), family='fixed')
    for n in range(21):
        add(f'fixed-key-{n}', b'\0\0\0\0'+bytes(32)+b'\1'+bytes(range(n)), family='fixed')

    # Slow/fast usize marker category is exercised at each record scalar slot.
    for index in range(3):
        for scalar in range(2):
            prefix = b'\0\0\0\2' + b''.join(record() for _ in range(index)) + b'\0'*scalar
            for marker in range(251, 256):
                for n in range(11):
                    add(f'usize-{index}-{scalar}-{marker}-{n}',
                        prefix+(bytes([marker])+bytes(range(9)))[:n])

    # All active signature bytes; three independent map-reader positions.
    map_prefixes = [b'\0\0\0\0'+bytes(32), b'\0\0\0\1'+bytes(32),
                    b'\0\0\0\1'+bytes(32)+b'\0']
    for position, prefix in enumerate(map_prefixes):
        for recovery in range(256):
            add(f'recovery-{position}-{recovery}', prefix+b'\1'+key(0)+signature(0,recovery)+b'\0')
        for limb in range(8):
            for marker in range(251,256):
                for n in range(11):
                    add(f'limb-{position}-{limb}-{marker}-{n}',
                        prefix+b'\1'+key(0)+b'\0'*limb+(bytes([marker])+bytes(range(9)))[:n])
        for n in [0, 1, 2, 250, 251, MAX//96, MAX//96+1, MAX]:
            for enabled in (False, True):
                add(f'map-count-{position}-{n}-{enabled}', prefix+var(n), enabled=enabled, limit=MAX)

    # Nonminimal encodings remain accepted; neither tag nor integer minimality
    # is a policy of the native operation.
    for width in (2,4):
        for tag in range(6):
            suffix = b'\0\0\0' if tag == 1 else b'\0\0\0'+bytes(32)+b'\0' if tag == 0 else b''
            add(f'nonminimal-outer-{tag}-{width}', var(tag,width)+suffix)
    for width in (2,4,8):
        add(f'nonminimal-u64-{width}', b'\1'+var(0,width)+var(250,width)+var(1,width))
        add(f'nonminimal-length-{width}', b'\0'+var(0,width)+var(0,width)+b'\0'+bytes(32)+var(0,width))
    for n in [0,1,250,251,65535,65536,0xffffffff,1<<32,(1<<63)-1,1<<63,MAX]:
        for enabled in (False,True):
            add(f'vector-length-{n}-{enabled}', b'\0'+var(n)+b'abc', enabled=enabled, limit=MAX)

    # Every full-node insertion gap and multi-level cascades in both directions.
    for gap in range(12):
        es = [(key(2*i+2), signature(i,i)) for i in range(11)]
        es.append((key(2*gap+1),signature(7,255)))
        add(f'split-gap-{gap}', map_greeting(es))
    rng = random.Random(0x944674820)
    for count in [10,11,12,23,60,120,240,500]:
        for order in ['ascending','descending','shuffled']:
            order_keys=list(range(count))
            if order=='descending': order_keys.reverse()
            if order=='shuffled': rng.shuffle(order_keys)
            es=[(key(i), signature(i,i%256)) for i in order_keys]
            add(f'tree-{count}-{order}',map_greeting(es))
            # Replacements preserve length and replace all 65 active bytes.
            es += [(key(i), signature(i+3,(i+1)%256)) for i in order_keys[::3]]
            add(f'tree-duplicates-{count}-{order}',map_greeting(es,es[::-1]))
            add(f'tree-cleanup-error-{count}-{order}',map_greeting(es)[:-1])
    identical=[(key(0),signature(i,i)) for i in range(32)]
    add('duplicate-one-key-32',map_greeting(identical,identical[::-1]))
    add('duplicate-leading-unsigned',map_greeting([(bytes([k])+bytes(19),signature(k,k)) for k in [255,0,128,127,1,254]]))

    # Successful-prefix and reservation failures: choose limits from the
    # independent event trace, then keep the full frame, including retained
    # charged state, rather than only checking the error discriminator.
    charge_seeds=base+[map_greeting([(key(i),signature(i,i)) for i in range(12)],[]),
                       b'\1\xfd', b'\0\0\0\0'+bytes(32)+b'\1'+key(0)+b'\0']
    for i,data in enumerate(charge_seeds):
        _,state,_=oracle.expected(dict(data=data,enabled=True,limit=MAX))
        limits={0,1,3,4,7,8,19,20,31,32,63,64,84,85,95,96,MAX}
        for e in state.events:
            if e[0]=='charge' and e[3] <= MAX:
                limits.update([e[3],max(0,e[3]-1),min(MAX,e[3]+1)])
        for limit in sorted(limits):
            add(f'charge-limit-{i}-{limit}',data,enabled=True,limit=limit,family='charge')
            add(f'caller-limit-{i}-{limit}',data,op=1,limit=limit,family='caller')
        for charged in [0,1,3,4,MAX-97,MAX-96,MAX-33,MAX-32,MAX-9,MAX-8,MAX-5,MAX-4,MAX-3,MAX]:
            for limit in [0,charged,MAX]:
                add(f'charge-initial-{i}-{charged}-{limit}',data,enabled=True,charged=charged,limit=limit,family='charge')

    # Arbitrary byte prefixes challenge the grammar without target execution.
    for i in range(512):
        n = rng.randrange(0,257)
        data=bytes(rng.randrange(256) for _ in range(n))
        add(f'random-{i}',data,enabled=bool(i%2),limit=rng.randrange(4096),charged=rng.randrange(16))
    return cases


def generate():
    vectors=[]; expected=[]; metadata=[]
    families={}; errors={}; successes={}; callers=0
    cases=inputs()
    for i,case in enumerate(cases):
        name=f'C{i:06d}'
        inp=oracle.encode_input(case)
        out,state,value=oracle.expected(case)
        vectors.append(f'{name}\t{inp.hex()}\n')
        expected.append(f'{name}\t{out.hex()}\n')
        meta=dict(id=name,name=case['name'],family=case['family'],domain='conditional-native',
                  operation='caller-edx0' if case['op'] else 'supplied-reader',
                  input_sha256=hashlib.sha256(inp).hexdigest(), output_sha256=hashlib.sha256(out).hexdigest(),
                  wire_length=len(case['data']), result_tag=value[0],
                  final_cursor=state.cursor,remaining=state.remaining,charged=state.charged)
        if value[0]==8:
            errors[str(value[1][0])]=errors.get(str(value[1][0]),0)+1
            meta['error']=list(value[1])
        else:successes[str(value[0])]=successes.get(str(value[0]),0)+1
        families[case['family']]=families.get(case['family'],0)+1
        callers+=bool(case['op'])
        metadata.append(json.dumps(meta,sort_keys=True,separators=(',',':'))+'\n')
    files={name:gzip.compress(''.join(lines).encode(),mtime=0) for name,lines in
           [('vectors.tsv.gz',vectors),('expected.tsv.gz',expected),('cases.jsonl.gz',metadata)]}
    report=dict(schema=1,case_count=len(cases),conditional_native_cases=len(cases),safe_policy_cases=0,
                supplied_reader_cases=len(cases)-callers,selected_caller_cases=callers,
                families=families,success_tags=successes,error_kinds=errors,
                disclaimer='Finite fixtures do not prove full native domain; manual proof supplies the universal relation.',
                files={name:dict(sha256=hashlib.sha256(raw).hexdigest(),bytes=len(raw)) for name,raw in files.items()})
    files['corpus.json']=(json.dumps(report,sort_keys=True,indent=2)+'\n').encode()
    return files


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);args=p.parse_args()
    args.out.mkdir(parents=True,exist_ok=False)
    for name,data in generate().items():(args.out/name).write_bytes(data)
