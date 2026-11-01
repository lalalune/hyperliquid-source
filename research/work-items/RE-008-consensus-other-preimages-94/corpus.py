#!/usr/bin/env python3
"""Independent value-level expectations, authored/frozen before Rust; no instruction evaluator."""
from __future__ import annotations
import argparse
import ast
import copy
import gzip
import hashlib
import itertools
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
PREFIX = b'Hyperliquid Consensus Payload'
MAX64 = (1 << 64) - 1
U64 = [0, 1, 249, 250, 251, 252, 65534, 65535, 65536, 65537,
       (1 << 32) - 1, 1 << 32, (1 << 32) + 1, MAX64]
U32 = [x for x in U64 if x < (1 << 32)]


def need(value, message):
    if not value:
        raise ValueError(message)


def keccak_provider():
    """Extract ONLY the existing MIT arithmetic helper, never its target evaluator."""
    path = ROOT / 'tools/action_signable.py'
    expected = json.loads((HERE / 'dependencies.json').read_text())[str(path.relative_to(ROOT))]
    text = path.read_bytes()
    need(hashlib.sha256(text).hexdigest() == expected, 'Keccak provider dependency changed')
    tree = ast.parse(text)
    fns = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'keccak256']
    constants = [n.value for n in tree.body if isinstance(n, ast.Assign)
                 and any(isinstance(t, ast.Name) and t.id == 'KECCAK_RC' for t in n.targets)]
    need(len(fns) == len(constants) == 1, 'ambiguous pure Keccak helper')
    space = {'MASK': MAX64, 'KECCAK_RATE': 136, 'KECCAK_DELIM': 1,
             'KECCAK_RC': ast.literal_eval(constants[0]),
             '__builtins__': {'range': range, 'len': len, 'int': int, 'bytes': bytes, 'bytearray': bytearray}}
    module = ast.fix_missing_locations(ast.Module(body=fns, type_ignores=[]))
    exec(compile(module, 'credited-pure-keccak-helper', 'exec'), space)
    result = space['keccak256']
    need(result(b'').hex() == 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470',
         'Keccak empty known answer')
    return result


def v(value):
    need(isinstance(value, int) and 0 <= value <= MAX64, 'u64 domain')
    if value < 251:
        return bytes([value])
    width = 2 if value <= 65535 else 4 if value <= 4294967295 else 8
    return bytes([{2: 251, 4: 252, 8: 253}[width]]) + value.to_bytes(width, 'little')


def vl(value):
    """Separate size equation using bit length; no call to the byte encoder."""
    return 1 if value <= 250 else 1 + (2 if value.bit_length() <= 16 else 4 if value.bit_length() <= 32 else 8)


def fixed(text, size):
    data = bytes.fromhex(text)
    need(len(data) == size, 'fixed width')
    return data


def rows_bytes(rows, values):
    return v(len(rows)) + b''.join(fixed(x[0], 20) + (v(x[1]) if values else b'') for x in rows)


def opt_bytes(value, encode):
    return b'\0' if value is None else b'\1' + encode(value)


def snapshot_bytes(s):
    return (opt_bytes(s['stakes'], lambda x: rows_bytes(x, True))
            + opt_bytes(s['jailed'], lambda x: rows_bytes(x, False)) + v(s['evm'])
            + opt_bytes(s['triple'], lambda x: b''.join(v(q['first']) + v(q['second']) + fixed(q['hash'], 32) for q in x)))


def expected(c):
    if c['variant'] == 2:
        out = PREFIX + b'\2' + fixed(c['signer'], 20)
        out += b''.join(v(c[k]) for k in ('round', 'version', 'start', 'qc_round')) + fixed(c['hash'], 32)
        out += v(len(c['votes']))
        for row in c['votes']:
            raw = fixed(row['signature'], 72)
            out += fixed(row['signer'], 20)
            out += b''.join(v(int.from_bytes(raw[i:i + 8], 'little')) for i in range(0, 64, 8)) + raw[64:65]
        return out
    if c['variant'] == 3:
        need(c['random'] < 1 << 32, 'u32 random')
        return (PREFIX + b'\3' + fixed(c['signer'], 20) + v(c['round'])
                + opt_bytes(c['snapshot'], snapshot_bytes)
                + opt_bytes(c['peers'], lambda x: rows_bytes(x, True)) + v(c['random']))
    need(c['variant'] == 4 and c['random'] < 1 << 32, 'variant/u32 random')
    return PREFIX + b'\4' + fixed(c['signer'], 20) + v(c['random']) + v(c['round'])


def size(c):
    def map_size(xs, values):
        return vl(len(xs)) + sum(20 + (vl(x[1]) if values else 0) for x in xs)
    def option_size(x, calc):
        return 1 + (0 if x is None else calc(x))
    def snapshot_size(s):
        return (option_size(s['stakes'], lambda xs: map_size(xs, True))
                + option_size(s['jailed'], lambda xs: map_size(xs, False)) + vl(s['evm'])
                + option_size(s['triple'], lambda xs: sum(32 + vl(x['first']) + vl(x['second']) for x in xs)))
    if c['variant'] == 2:
        return (82 + sum(vl(c[k]) for k in ('round', 'version', 'start', 'qc_round')) + vl(len(c['votes']))
                + sum(21 + sum(vl(int.from_bytes(bytes.fromhex(row['signature'])[i:i + 8], 'little'))
                               for i in range(0, 64, 8)) for row in c['votes']))
    if c['variant'] == 3:
        return (50 + vl(c['round']) + option_size(c['snapshot'], snapshot_size)
                + option_size(c['peers'], lambda xs: map_size(xs, True)) + vl(c['random']))
    return 50 + vl(c['random']) + vl(c['round'])


def input_frame(c):
    """Own test protocol, NOT a native or network encoding. Contains input only."""
    out = bytearray([c['variant']]) + fixed(c['signer'], 20)
    def word(x):
        out.extend(struct.pack('<Q', x))
    def count(n):
        out.extend(struct.pack('<I', n))
    def rows(xs, values):
        out.append(xs is not None)
        if xs is not None:
            count(len(xs))
            for row in xs:
                out.extend(fixed(row[0], 20))
                if values:
                    word(row[1])
    if c['variant'] == 2:
        for k in ('round', 'version', 'start', 'qc_round'):
            word(c[k])
        out.extend(fixed(c['hash'], 32)); count(len(c['votes']))
        for row in c['votes']:
            out.extend(fixed(row['signer'], 20)); out.extend(fixed(row['signature'], 72))
    elif c['variant'] == 3:
        word(c['round']); count(c['random']); s = c['snapshot']; out.append(s is not None)
        if s is not None:
            rows(s['stakes'], True); rows(s['jailed'], False); word(s['evm'])
            out.append(s['triple'] is not None)
            if s['triple'] is not None:
                need(len(s['triple']) == 3, 'three summaries')
                for row in s['triple']:
                    out.extend(fixed(row['hash'], 32)); word(row['first']); word(row['second'])
        rows(c['peers'], True)
    else:
        count(c['random']); word(c['round'])
    return bytes(out)


def addr(i):
    return i.to_bytes(20, 'big').hex()


def signature(limbs, last=0, padding=0):
    need(len(limbs) == 8, 'eight signature limbs')
    return (b''.join(x.to_bytes(8, 'little') for x in limbs) + bytes([last]) + bytes([padding]) * 7).hex()


def timeout(n=1):
    return dict(variant=2, signer=addr(0x123456), round=0, version=0, start=0, qc_round=0,
                hash=bytes(range(32)).hex(), votes=[dict(signer=addr(i + 1), signature=signature([0] * 8)) for i in range(n)])


def heartbeat():
    return dict(variant=3, signer=addr(0xabcdef), round=0, random=0, snapshot=None, peers=None)


def snapshot():
    return dict(stakes=None, jailed=None, evm=0, triple=None)


def triples():
    return [dict(hash=bytes([i + 1]) * 32, first=251 + i, second=(1 << 32) + i) for i in range(3)]


def cases():
    result = []
    def add(name, c):
        c = copy.deepcopy(c); c['name'] = name
        if c['snapshot']['triple'] if c.get('snapshot') is not None else False:
            for x in c['snapshot']['triple']:
                if isinstance(x['hash'], bytes):
                    x['hash'] = x['hash'].hex()
        need(len(expected(c)) == size(c), 'independent size mismatch: ' + name)
        result.append(c)
    for n in (0, 1, 2, 3, 10, 250, 251):
        add(f'timeout-count-{n}', timeout(n))
    for field in ('round', 'version', 'start', 'qc_round'):
        for x in U64:
            c = timeout(); c[field] = x; add(f'timeout-{field}-{x}', c)
    for j in range(8):
        for x in U64:
            c = timeout(); limbs = [0] * 8; limbs[j] = x; c['votes'][0]['signature'] = signature(limbs, 27)
            add(f'signature-limb-{j}-{x}', c)
    for rec in (0, 1, 2, 27, 28, 127, 128, 255):
        c = timeout(2)
        for i, row in enumerate(c['votes']):
            row['signature'] = signature([U64[(j + i + 2) % len(U64)] for j in range(8)], rec, 165)
        add(f'signature-mixed-final-{rec}', c)
    for padding in (0, 1, 90, 165, 255):
        c = timeout(); c['votes'][0]['signature'] = signature([MAX64] * 8, 255, padding)
        add(f'ignored-signature-padding-{padding}', c)
    for n in (2, 3, 11):
        c = timeout(n)
        for i, row in enumerate(c['votes']):
            row['signature'] = signature([i * 65536 + j for j in range(8)], i % 256)
        add(f'vote-order-{n}-forward', c); c['votes'].reverse(); add(f'vote-order-{n}-reverse', c)
    c = timeout(2); c['votes'][1] = copy.deepcopy(c['votes'][0]); add('duplicate-vote-retained', c)
    for fill in (0, 255):
        c = timeout(); c['signer'] = (bytes([fill]) * 20).hex(); c['hash'] = (bytes([fill]) * 32).hex()
        c['votes'][0]['signer'] = (bytes([255 - fill]) * 20).hex(); add(f'timeout-fixed-bytes-{fill}', c)
    for r in U64:
        for rnd in U32:
            add(f'ack-{r}-{rnd}', dict(variant=4, signer=addr(255), round=r, random=rnd))
    for field, values in [('round', U64), ('random', U32)]:
        for x in values:
            c = heartbeat(); c[field] = x; add(f'heartbeat-{field}-{x}', c)
    for flags in itertools.product((False, True), repeat=4):
        c = heartbeat(); s = snapshot(); c['snapshot'] = s
        s['stakes'] = [[addr(2), 251], [addr(1), MAX64]] if flags[0] else None
        s['jailed'] = [[addr(7)], [addr(3)]] if flags[1] else None
        s['triple'] = triples() if flags[2] else None
        c['peers'] = [[addr(8), 65536], [addr(4), 0]] if flags[3] else None
        s['evm'] = 123; add('heartbeat-option-' + ''.join(str(int(x)) for x in flags), c)
    for kind in ('stakes', 'jailed', 'peers'):
        for n in (0, 1, 2, 11, 12, 250, 251):
            c = heartbeat(); c['snapshot'] = snapshot()
            xs = [[addr(i + 1), U64[i % len(U64)]] if kind != 'jailed' else [addr(i + 1)] for i in range(n)]
            if kind == 'peers': c[kind] = xs
            else: c['snapshot'][kind] = xs
            add(f'heartbeat-{kind}-count-{n}', c)
            if n in (2, 12):
                xs.reverse(); add(f'heartbeat-{kind}-reversed-{n}', c)
    for i in range(3):
        for field in ('first', 'second'):
            for x in U64:
                c = heartbeat(); c['snapshot'] = snapshot(); c['snapshot']['triple'] = triples()
                c['snapshot']['triple'][i][field] = x
                add(f'triple-{i}-{field}-{x}', c)
    for x in U64:
        c = heartbeat(); c['snapshot'] = snapshot(); c['snapshot']['evm'] = x; add(f'heartbeat-evm-{x}', c)
    for flags in itertools.product((False, True), repeat=3):
        c = heartbeat(); c['snapshot'] = snapshot()
        c['snapshot']['stakes'] = [] if flags[0] else None
        c['snapshot']['jailed'] = [] if flags[1] else None
        c['peers'] = [] if flags[2] else None
        add('empty-vs-absent-' + ''.join(str(int(x)) for x in flags), c)
    # Exact rate boundaries by arithmetic width search, never native execution.
    def widths(caps, delta):
        choices = {0: []}
        for cap in caps:
            choices = {total + add: xs + [add] for total, xs in choices.items()
                       for add in (0, 2, 4, 8) if add <= cap and total + add <= delta}
        return choices.get(delta)
    width_value = {0: 0, 2: 251, 4: 65536, 8: 1 << 32}
    for target in (135, 136, 137, 271, 272, 273, 407, 408, 409):
        found = None
        for n in range(12):
            c = timeout(n); delta = target - size(c)
            if delta < 0: continue
            inc = widths([8] * (4 + 8*n), delta)
            if inc is None: continue
            values = [width_value[x] for x in inc]
            for j, k in enumerate(('round', 'version', 'start', 'qc_round')): c[k] = values[j]
            for j, row in enumerate(c['votes']): row['signature'] = signature(values[4+8*j:12+8*j], 255, 85)
            found = c; break
        if found is None:
            for n in range(20):
                c = heartbeat(); c['snapshot'] = snapshot()
                c['snapshot']['stakes'] = [[addr(i+1), 0] for i in range(n)]
                delta = target - size(c)
                if delta < 0: continue
                inc = widths([8, 4, 8] + [8] * n, delta)
                if inc is None: continue
                values = [width_value[x] for x in inc]
                c['round'], c['random'], c['snapshot']['evm'] = values[:3]
                for row, value in zip(c['snapshot']['stakes'], values[3:]): row[1] = value
                found = c; break
        need(found is not None and size(found) == target, f'unachieved rate boundary {target}')
        add(f'rate-boundary-{target}', found)
    need(len({c['name'] for c in result}) == len(result), 'duplicate case name')
    return result


def generate():
    digest = keccak_provider(); all_cases = cases()
    body = ''.join(json.dumps(c, separators=(',', ':')) + '\n' for c in all_cases).encode()
    vectors = b''.join((c['name'] + '\t' + input_frame(c).hex() + '\t' + expected(c).hex()
                       + '\t' + digest(expected(c)).hex() + '\n').encode() for c in all_cases)
    # Ensure the deliberately different padding values yield identical active preimages.
    ignored = [expected(c) for c in all_cases if c['name'].startswith('ignored-signature-padding-')]
    need(len(set(ignored)) == 1, 'padding invariance')
    metrics = {'cases': len(all_cases), 'variants': {str(i): sum(c['variant'] == i for c in all_cases) for i in (2,3,4)},
               'preimage_min': min(size(c) for c in all_cases), 'preimage_max': max(size(c) for c in all_cases),
               'rate_boundaries': [size(c) for c in all_cases if c['name'].startswith('rate-boundary-')],
               'expected_hash_scope': 'Independent standard Keccak values; native identity conditional on credited structural evidence.',
               'cases_sha256': hashlib.sha256(body).hexdigest(), 'vectors_sha256': hashlib.sha256(vectors).hexdigest()}
    return {'cases.jsonl.gz': gzip.compress(body, mtime=0), 'vectors.tsv.gz': gzip.compress(vectors, mtime=0),
            'corpus.json': (json.dumps(metrics, indent=2) + '\n').encode()}


def main():
    ap = argparse.ArgumentParser(); ap.add_argument('--out', type=Path, required=True); args = ap.parse_args()
    need(not args.out.exists(), 'output must be new'); args.out.mkdir(parents=True)
    for name, data in generate().items(): (args.out / name).write_bytes(data)
    print((args.out / 'corpus.json').read_text(), end='')


if __name__ == '__main__': main()
