#!/usr/bin/env python3
"""Independent logical byte encoder + PyCryptodome Keccak; never runs the target.

Print the checked fixture JSON, or use --write to regenerate fixture JSON and
the dependency-free Rust integration test. Inputs are normalized logical data,
not captured native observations. Requires pycryptodome 4.5.0.
"""
import argparse
import json
from pathlib import Path
from Crypto.Hash import keccak

DOMAIN = b'Hyperliquid Consensus Payload'


def compact(n):
    assert 0 <= n < 2**64
    if n <= 250:
        return bytes([n])
    for width, marker in [(2, 251), (4, 252), (8, 253)]:
        if n < 1 << (8 * width):
            return bytes([marker]) + n.to_bytes(width, 'little')
    raise AssertionError(n)


def signature(raw):
    raw = bytes.fromhex(raw)
    assert len(raw) == 65
    return b''.join(compact(int.from_bytes(raw[k:k+8], 'little'))
                    for k in range(0, 64, 8)) + raw[64:]


def certificate(c):
    rows = c['rows']  # fixture keys are strictly ascending, matching tree order
    assert [r[0] for r in rows] == sorted(set(r[0] for r in rows))
    return (b''.join(map(compact, c['fields'])) + bytes.fromhex(c['hash']) +
            compact(len(rows)) + b''.join(bytes.fromhex(k) + signature(s) for k, s in rows))


def encode(b):
    seconds = b['seconds']
    zz = 2 * seconds if seconds >= 0 else -2 * seconds - 1
    out = (b'\0' + bytes.fromhex(b['address']) + compact(len(b['hashes'])) +
           b''.join(bytes.fromhex(h) for h in b['hashes']) + compact(zz) + compact(b['nanos']))
    p = b['parent']
    if p['kind'] == 'simple':
        return out + compact(0) + certificate(p['primary'])
    return (out + compact(1) + compact(p['round']) + certificate(p['primary']) +
            compact(len(p['rows'])) + b''.join(bytes.fromhex(k) + compact(v) + signature(s)
                                              for k, v, s in p['rows']) +
            (b'\0' if p['optional'] is None else b'\1' + certificate(p['optional'])))


def digest(raw):
    return keccak.new(digest_bits=256, data=raw).hexdigest()


def inputs():
    bounds = [0, 1, 250, 251, 65535, 65536, 2**32-1, 2**32, 2**64-1]
    for i in range(18):
        def cert(j):
            sig = b''.join(bounds[(j+k) % len(bounds)].to_bytes(8, 'little') for k in range(8)) + bytes([j % 256])
            return dict(fields=[bounds[(j+k) % len(bounds)] for k in range(5)],
                        hash=bytes([j % 256]*32).hex(),
                        rows=[(bytes([k+1]*20).hex(), sig.hex()) for k in range(j % 3)])
        primary = cert(i)
        parent = dict(kind='simple', primary=primary)
        if i % 3:
            parent = dict(kind='composite', primary=primary, round=bounds[i % len(bounds)],
                          rows=[(bytes([9-k]*20).hex(), bounds[(i+k) % len(bounds)],
                                 (bytes([k]*64)+bytes([255-k])).hex()) for k in range(i % 4)],
                          optional=cert(i+1) if i % 3 == 2 else None)
        yield dict(address=bytes([i]*20).hex(), hashes=[bytes([i+k]*32).hex() for k in range(i % 3)],
                   seconds=[0, -1, 125, -126, 32768, -32769, 2**31, -2**31,
                            2**63-1, -2**63][i % 10],
                   nanos=[0, 250, 251, 65535, 65536, 999999999, 2**32-1][i % 7], parent=parent)


def rust_cert(c):
    fields = ','.join(str(v) for v in c['fields'])
    rows = ','.join('SigRow{key:fixed("%s"),sig:fixed("%s")}' % (k, s) for k, s in c['rows'])
    return 'cert([%s],"%s",vec![%s])' % (fields, c['hash'], rows)


def rust_block(b):
    p = b['parent']
    if p['kind'] == 'simple':
        parent = 'Parent::Simple(%s)' % rust_cert(p['primary'])
    else:
        rows = ','.join('TimeoutRow{key:fixed("%s"),value:%d,signature:fixed("%s")}' % r for r in p['rows'])
        opt = 'None' if p['optional'] is None else 'Some(%s)' % rust_cert(p['optional'])
        parent = 'Parent::Composite{primary:%s,round:%d,timeout_rows:vec![%s],optional:%s}' % (rust_cert(p['primary']),p['round'],rows,opt)
    return ('Block{address:fixed("%s"),hashes:vec![%s],timestamp:Timestamp{seconds:%d,nanos:%d},parent:%s}' %
            (b['address'],','.join('fixed("%s")' % h for h in b['hashes']),b['seconds'],b['nanos'],parent))


def main(write):
    assert digest(b'') == 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'
    assert digest(b'abc') == '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45'
    fixtures = [dict(input=b, encoded=encode(b).hex(), digest=digest(DOMAIN+encode(b))) for b in inputs()]
    # Plausible wrong preimages are independently rejected for every fixture.
    for f in fixtures:
        raw = bytes.fromhex(f['encoded'])
        assert digest(raw) != f['digest']
        assert digest(DOMAIN+b'\1'+raw[1:]) != f['digest']
    here = Path(__file__).parent
    rendered = json.dumps(fixtures,indent=2)+'\n'
    if not write:
        assert here.joinpath('fixtures.json').read_text() == rendered
        print(f'PASS: {len(fixtures)} independent byte/hash fixtures; 2 Keccak known vectors; 36 wrong-preimage checks')
        return
    here.joinpath('fixtures.json').write_text(rendered)
    test = '''// Generated by fixture_oracle.py; format with cargo fmt after regeneration.
use node115_certificate_caller::{Block,Parent,Timestamp,TimeoutRow,serialize_variant_zero,block_digest};
use node115_nested_certificate_decision::Certificate;
use node115_nested_certificate_decision::sigmap::{SigMap,SigRow};
fn unhex(s:&str)->Vec<u8>{s.as_bytes().chunks_exact(2).map(|p|u8::from_str_radix(std::str::from_utf8(p).unwrap(),16).unwrap()).collect()}
fn fixed<const N:usize>(s:&str)->[u8;N]{unhex(s).try_into().unwrap()}
fn cert(f:[u64;5],h:&str,rows:Vec<SigRow>)->Certificate{Certificate{pair:[f[0],f[1]],f30:f[2],f38:f[3],f40:f[4],hash:fixed(h),sigs:SigMap::tree(rows)}}
#[test]
fn independent_python_bytes_and_keccak(){
'''
    for i,f in enumerate(fixtures):
        test += '{let b=%s; assert_eq!(serialize_variant_zero(&b),unhex("%s"),"bytes fixture %d");assert_eq!(block_digest(&b),fixed("%s"),"hash fixture %d");}\n' % (rust_block(f['input']),f['encoded'],i,f['digest'],i)
    test += '}\n'
    here.parents[2].joinpath('src/node115-certificate-caller/tests/independent.rs').write_text(test)
    print('Wrote',len(fixtures),'fixtures')


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write',action='store_true')
    main(parser.parse_args().write)
