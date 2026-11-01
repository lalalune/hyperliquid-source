#!/usr/bin/env python3
"""Pre-Rust declarative byte-language oracle; never executes target instructions.

Find a maximal prefix separately for each admitted quote language, then choose
length/priority. This is intentionally different from one-pass mask scanning.
No Rust source, result stream, shell, interpreter, or target binary is executed.
"""
import argparse
import gzip
import hashlib
import itertools
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
PACKET = HERE.parent
ROOT = HERE.parents[3]
TARGET = ROOT / 'artifacts/visor/captured/hl-visor'
TARGET_SHA = '89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31'
ORIGINAL_MANIFEST_SHA = 'adf49dc32ce25c5ca1e644c6e6822b7e98c628cee9576416c779e3f3860a00b3'
ORIGINAL_FREEZE_SHA = 'da391eee20b3e7dc9b35046abac827caa59e1d7492a4ff21df505de795ab8ea4'
LIMIT = (1 << 61) - 2

def need(value, why):
    if not value:
        raise ValueError(why)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def image_bytes(data, va, length):
    need(data[:6] == b'\x7fELF\x02\x01', 'ELF64 little endian')
    first = struct.unpack_from('<Q', data, 32)[0]
    size, count = struct.unpack_from('<HH', data, 54)
    need(size == 56 and first + count * size <= len(data), 'program headers')
    hits = []
    for i in range(count):
        typ, _, off, start, _, n, _, _ = struct.unpack_from('<IIQQQQQQ', data, first + size * i)
        if typ == 1 and start <= va and va + length <= start + n:
            need(off + n <= len(data), 'file-backed load bounds')
            hits.append(off + va - start)
    need(len(hits) == 1, 'unique PT_LOAD coordinate')
    return data[hits[0]:hits[0] + length]

def parameters():
    data = TARGET.read_bytes()
    need(len(data) == 8305392 and sha(data) == TARGET_SHA, 'target identity')
    need(sha((PACKET / 'MANIFEST.json').read_bytes()) == ORIGINAL_MANIFEST_SHA, 'original static manifest')
    need(sha((PACKET / 'AUTHOR-FREEZE.json').read_bytes()) == ORIGINAL_FREEZE_SHA, 'original static freeze')
    manifest = json.loads((PACKET / 'MANIFEST.json').read_text())
    for path, entry in manifest['files'].items():
        need(sha((PACKET / path).read_bytes()) == entry['sha256'], 'original file:' + path)
    fields = {'raw_low': (0x6517c1, 0x07ffe80000000000),
              'raw_high': (0x6517b4, 0x07fffffea7ffffff),
              'not_double': (0x6517ea, 0x8000000000000009),
              'not_single': (0x6517fa, 0x0800000000000040),
              'escape': (0x6519cb, 0x4400000000000005)}
    constants = {}
    for key, (va, expected) in fields.items():
        value = int.from_bytes(image_bytes(data, va, 8), 'little')
        need(value == expected, 'native constant:' + key)
        constants[key] = value
    raw = frozenset(i for i in range(128)
                    if ((constants['raw_low'] if i < 64 else constants['raw_high']) >> (i % 64)) & 1)
    single_excluded = frozenset({33 + i for i in range(64) if constants['not_single'] >> i & 1} | {94})
    double_excluded = frozenset({33 + i for i in range(64) if constants['not_double'] >> i & 1} | {94})
    escape = frozenset(34 + i for i in range(63) if constants['escape'] >> i & 1)
    table = image_bytes(data, 0x87579, 256)
    whites = frozenset({*range(9, 14), 32, 0x1680, 0x3000}
                      | {i for i in range(128, 256) if table[i] & 1}
                      | {0x2000 + i for i in range(256) if table[i] & 2})
    need(len(whites) == 25, 'whitespace set size')
    need(image_bytes(data, 0x795ec, 2) == b'mv' and image_bytes(data, 0x769e6, 1) == b' ', 'join literals')
    return {'raw': raw, 'single_excluded': single_excluded,
            'double_excluded': double_excluded, 'escape': escape,
            'white': whites, 'table_sha256': sha(table),
            'constants': {k: hex(v) for k, v in constants.items()}}

def encoded_word(word, p):
    need(0 not in word and len(word) > 0, 'nonempty NUL-free word domain')
    pieces = []
    while word:
        choices = []
        if word[0] == 94:
            length = 1
            while length < len(word) and word[length] not in p['single_excluded']:
                length += 1
            choices.append((length, 1))
        else:
            for mode in (0, 1, 2):
                length = 0
                while length < len(word):
                    b = word[length]
                    admitted = (b in p['raw'] if mode == 0 else
                                b not in p['single_excluded'] if mode == 1 else
                                b not in p['double_excluded'])
                    if not admitted:
                        break
                    length += 1
                choices.append((length, mode))
        length, mode = min(choices, key=lambda pair: (-pair[0], pair[1]))
        need(length > 0, 'maximal language prefix must advance')
        chunk, word = word[:length], word[length:]
        if mode == 0:
            pieces.append(chunk)
        elif mode == 1:
            pieces.append(b"'" + chunk + b"'")
        else:
            pieces.append(b'"' + b''.join((b'\\' if b in p['escape'] else b'') + bytes([b]) for b in chunk) + b'"')
    return b''.join(pieces)

def expected(source, destination, p):
    # Decode strictly only to define canonical scalar membership; no host
    # whitespace API or shell parser supplies the classification/output.
    words = [source.decode('utf-8'), destination.decode('utf-8')]
    need(len(source) + len(destination) <= LIMIT, 'finite fixture length domain')
    if b'\0' in source or b'\0' in destination:
        return ('nul', None)
    kept = [b'mv']
    for word in words:
        if any(ord(cp) not in p['white'] for cp in word):
            kept.append(encoded_word(word.encode('utf-8'), p))
    return ('ok', b' '.join(kept))

def handwritten(p):
    witnesses = [
        (b'', b'', b'mv'), (b' ', b'\t', b'mv'),
        (b'a', b'b', b'mv a b'), (b' a ', b'b', b"mv ' a ' b"),
        (b'', b'b', b'mv b'), (b'a', b'', b'mv a'),
        (b'^', b'b', b"mv '^' b"), (b'^^', b'b', b"mv '^''^' b"),
        (b'a^b', b'', b"mv a'^b'"), (b"'", b'', b'mv "\'"'),
        (b'\\', b'', b'mv "\\\\"'), (b"$'", b'', b'mv \'$\'"\'"'),
        (b"'$", b'', b'mv "\'"\'$\''), (b'2>&1', b'', b"mv '2>&1'"),
        ('é'.encode(), '中'.encode(), "mv 'é' '中'".encode()),
        ('\u2000'.encode(), b'z', b'mv z'),
        ('\u200b'.encode(), b'z', "mv '\u200b' z".encode()),
        ('\u0085x\u0085'.encode(), b'', "mv '\u0085x\u0085'".encode())]
    for src, dst, wanted in witnesses:
        need(expected(src, dst, p) == ('ok', wanted), 'handwritten byte witness:' + src.hex())
    for src, dst in [(b'\0', b''), (b' \0 ', b'a'), (b'a', b'\0'), (b'', b'\0\t')]:
        need(expected(src, dst, p) == ('nul', None), 'handwritten NUL witness')
    return 22

def cases(p):
    result = {}
    def add(category, src, dst):
        src.decode('utf-8'); dst.decode('utf-8')
        result.setdefault((src, dst), set()).add(category)
    add('empty', b'', b'')
    for a in range(128):
        add('ASCII-one-source', bytes([a]), b'')
        add('ASCII-one-destination', b'', bytes([a]))
        for b in range(128):
            add('ASCII-two-in-one', bytes([a, b]), b'')
            add('ASCII-two-operands', bytes([a]), bytes([b]))
    scalars = {0x7f, 0x80, 0x7ff, 0x800, 0xd7ff, 0xe000, 0xffff, 0x10000, 0x10ffff}
    for cp in p['white']:
        scalars.update((cp - 1, cp, cp + 1))
    for cp in sorted(scalars):
        raw = chr(cp).encode('utf-8')
        add('Unicode-member-neighbor', raw, b'z')
        add('Unicode-member-neighbor-reverse', b'z', raw)
        add('Unicode-padded-original', b' ' + raw + b'\t', b'z')
        add('Unicode-NUL-after', raw + b'\0', b'z')
        add('Unicode-NUL-before-destination', b'z', b'\0' + raw)
    white_word = ''.join(chr(cp) for cp in sorted(p['white'])).encode('utf-8')
    add('all25-white', white_word, white_word)
    add('all25-padded-nonblank', white_word + b'x' + white_word, b'y')
    basis = [b'a', b' ', b"'", b'"', b'\\', b'^', b'$', b'!', b'`', 'é'.encode()]
    for length in range(1, 5):
        for parts in itertools.product(basis, repeat=length):
            add('quote-language-conflicts', b''.join(parts), b'dst')
    for raw in [b'2>&1', b' a ', b'^a', b"'$", b"$'", b'--help', b'a\nb']:
        add('ordering-and-quiet-substring', raw, b'second')
        add('ordering-and-quiet-substring', b'first', raw)
        add('ordering-and-quiet-substring', raw, raw)
    for size in [7, 8, 9, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257, 1023, 1024, 1025, 4095, 4096, 4097]:
        for pattern in [b'a', b' ', b'^', b"'$\\", b'a^!\\', 'é'.encode()]:
            # Repeat whole valid pattern, then add ASCII padding to exact size.
            raw = pattern * (size // len(pattern)) + b'x' * (size % len(pattern))
            add('long-language-and-length', raw, b'd')
            add('long-language-and-length', b's', raw)
        add('long-NUL', b'a' * (size - 1) + b'\0', b'd')
    for index, ((src, dst), groups) in enumerate(sorted(result.items())):
        yield f'c{index:05d}', src, dst, sorted(groups)

def write_new(out):
    need(not out.exists(), 'existing corpus output refused')
    p = parameters()
    witness_count = handwritten(p)
    inputs, expects, categories = [], [], {}
    status_counts = {'ok': 0, 'nul': 0}
    max_source = max_output = 0
    for name, src, dst, groups in cases(p):
        status, payload = expected(src, dst, p)
        inputs.append(name + '\t' + src.hex() + '\t' + dst.hex())
        expects.append(name + '\t' + status + ('\t1\t' + payload.hex() if payload is not None else ''))
        status_counts[status] += 1
        max_source = max(max_source, len(src) + len(dst))
        max_output = max(max_output, len(payload) if payload is not None else 0)
        for group in groups:
            categories[group] = categories.get(group, 0) + 1
    lengths = [0, 1, 2, 3, LIMIT - 2, LIMIT - 1, LIMIT, LIMIT + 1,
               (1 << 61), (1 << 63) - 1, (1 << 63), (1 << 64) - 2, (1 << 64) - 1]
    length_inputs, length_expected = [], []
    pairs = set(itertools.product(lengths, repeat=2))
    for a in range(17):
        for delta in (-1, 0, 1):
            pairs.add((a, LIMIT - a + delta))
    for index, (a, b) in enumerate(sorted(pairs)):
        name = f'l{index:03d}'
        length_inputs.append(f'{name}\t{a}\t{b}')
        length_expected.append(name + ('\tok\t' + str(4 * (a + b) + 4) if a + b <= LIMIT else '\tdomain'))
    streams = {'inputs.tsv': '\n'.join(inputs) + '\n', 'expected.tsv': '\n'.join(expects) + '\n',
               'length-inputs.tsv': '\n'.join(length_inputs) + '\n',
               'length-expected.tsv': '\n'.join(length_expected) + '\n'}
    out.mkdir(parents=True, exist_ok=False)
    hashes = {}
    for name, text in streams.items():
        raw = text.encode('ascii')
        stored = gzip.compress(raw, mtime=0)
        (out / (name + '.gz')).write_bytes(stored)
        hashes[name] = {'raw_sha256': sha(raw), 'raw_bytes': len(raw),
                        'gzip_sha256': sha(stored), 'gzip_bytes': len(stored)}
    record = {'target_sha256': TARGET_SHA, 'original_static_manifest_sha256': ORIGINAL_MANIFEST_SHA,
              'original_static_freeze_sha256': ORIGINAL_FREEZE_SHA,
              'oracle_sha256': sha(Path(__file__).read_bytes()),
              'contract_sha256': sha((HERE / 'CONTRACT.md').read_bytes()),
              'case_count': len(inputs), 'status_counts': status_counts,
              'category_membership_counts': categories, 'length_case_count': len(length_inputs),
              'handwritten_witnesses': witness_count, 'maximum_fixture_input_bytes': max_source,
              'maximum_fixture_output_bytes': max_output, 'native_constants': p['constants'],
              'white_scalars': sorted(p['white']), 'table_sha256': p['table_sha256'],
              'streams': hashes,
              'limits': 'Pre-Rust mathematical byte-language expectations, not target execution/evaluation or externally observed runtime. No allocation-failure expectations, actual shell/preflight/filesystem effects or original ABI.'}
    (out / 'corpus.json').write_text(json.dumps(record, sort_keys=True, separators=(',', ':')) + '\n')
    return record

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    result = write_new(args.out)
    print(json.dumps({'cases': result['case_count'], 'length_cases': result['length_case_count'],
                      'handwritten': result['handwritten_witnesses'], 'status': result['status_counts']}))
