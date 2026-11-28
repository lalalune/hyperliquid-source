"""Replay public Linux process accounting and qualify its inputs against node 115."""
import argparse
import csv
import hashlib
import itertools
import json
import random
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections

NODE = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
CRATE = 'cd727fc423c2060f6c92d9534cef765c65a6ed3f428a03d7def74a8c4348e666'
MAX = (1 << 64) - 1


def check(ok, msg):
    if not ok:
        raise ValueError(msg)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def target():
    image = (ROOT / 'artifacts/node/115/hl-node').read_bytes()
    check(sha(image) == NODE, 'Unrecognized node')
    mapped = [s for s in sections(image) if s['flags'] & 2 and s['type'] != 8]

    def read(va, count):
        sec, = [s for s in mapped if s['address'] <= va and va + count <= s['address'] + s['size']]
        off = sec['offset'] + va - sec['address']
        return image[off:off+count]

    def dest(va, opcode):
        check(read(va, len(opcode)) == opcode, 'Wrong opcode')
        size = len(opcode) + 4
        return va + size + struct.unpack('<i', read(va + len(opcode), 4))[0]

    prior = HERE.parent / 'RE-002-node115-rust-sysinfo-process-references' / 'roots.tsv'
    with prior.open() as f:
        row, = [r for r in csv.DictReader(f, delimiter='\t') if 'compute_cpu_usage' in r['reference_attribution']]
    start, end = int(row['start'], 16), int(row['end'], 16)
    body = read(start, end - start)
    check(sha(body) == row['target_sha256'], 'Registered body mismatch')
    factor = dest(0x5cb6fbf, bytes.fromhex('f30f5905'))
    check(struct.unpack('<f', read(factor, 4))[0] == 100, 'Percent scale changed')
    check(dest(0x5cb6f59, bytes.fromhex('0f84')) == 0x5cb706d, 'First-sample return differs')
    for call in (0x5cd0eff, 0x5cb7039):
        check(dest(call, bytes.fromhex('e8')) == start, 'Unexpected call destination')
    check(read(0x5cb6fe4, 8) == bytes.fromhex('f30f11875c010000'), 'Result store differs')
    return {'root': hex(start), 'size': len(body), 'sha256': sha(body), 'scale_address': hex(factor),
            'scale_bits': read(factor, 4).hex(), 'external_call': '0x5cd0eff', 'recursive_call': '0x5cb7039'}


def bits(value):
    return struct.unpack('<I', struct.pack('<f', value))[0]


def single(value):
    return struct.unpack('<f', struct.pack('<f', value))[0]


def uint_to_single(value):
    # Single rounding from the 64-bit integer, including halfway cases.
    shift = max(value.bit_length() - 24, 0)
    if shift:
        top, rest = divmod(value, 1 << shift)
        half = 1 << (shift - 1)
        value = (top + (rest > half or (rest == half and top % 2))) << shift
    return single(value)


def model(proc, total, cap):
    old_user, old_sys, user, system, _ = proc
    delta = min(MAX, max(0, user - old_user) + max(0, system - old_sys))
    return bits(min(cap, single(single(uint_to_single(delta) / total) * 100.0)))


def fixtures():
    rng = random.Random(115)
    groups = [(0, 0, 5, 9), (10, 7, 4, 20), (10, 7, 22, 3), (7, 4, 3, 2),
              (1, 0, MAX, MAX), (1, 1, 1 + (1 << 24) + 1, 1),
              (1, 0, 1 + (1 << 63) + (1 << 39), 0), (1, 0, 2, 0)]
    def emit(triple, total, ceiling):
        active = True
        raw, expected = [], []
        for i, counters in enumerate(triple):
            proc = (*counters, bits(11.5+i))
            active = active and (proc[0] != 0 or proc[1] != 0)
            expected.append(model(proc, total, ceiling) if active else proc[4])
            raw.extend(proc)
        return [*raw, bits(total), bits(ceiling)], expected
    for triple in itertools.product(groups, repeat=3):
        yield emit(triple, 32.0, 400.0)
    for _ in range(512):
        triple = [tuple(rng.getrandbits(64) for _ in range(4)) for _ in range(3)]
        yield emit(triple, rng.choice((1.0, 8.0, float(1 << 61))), rng.choice((100.0, 400.0, 800.0)))


def replay(path):
    check(sha(path.read_bytes()) == CRATE, 'Unexpected public crate')
    with tarfile.open(path) as tar:
        src = tar.extractfile('sysinfo-0.29.11/src/linux/process.rs').read()
    start = src.index(b'pub(crate) fn compute_cpu_usage(')
    end = src.index(b'\n}\n', start) + 3
    source = src[start:end]
    with tempfile.TemporaryDirectory() as td:
        dst = Path(td)
        shutil.copy(HERE / 'control.rs', dst / 'control.rs')
        (dst / 'public_function.rs').write_bytes(source)
        exe = dst / 'control'
        subprocess.run(['rustup', 'run', '1.95.0', 'rustc', '--edition=2021', '-O', dst/'control.rs',
                        '-o', exe], check=True)
        rows = list(fixtures())
        lines = ''.join(' '.join(map(str, row)) + '\n' for row, _ in rows)
        result = subprocess.check_output([exe], input=lines, text=True)
        parsed = [list(map(int, line.split())) for line in result.splitlines()]
        check(parsed == [exp for _, exp in rows], 'Public source and scalar/reference traversal disagree')
    return {'source_function_sha256': sha(source), 'trees': len(rows), 'process_outputs': len(rows)*3,
            'input_sha256': sha(lines.encode()), 'output_sha256': sha(result.encode())}


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('crate', type=Path)
    ap.add_argument('--print', action='store_true', dest='show')
    opt = ap.parse_args()
    result = {'target_sha256': NODE, 'public_crate_sha256': CRATE, 'linked': target(), 'replay': replay(opt.crate)}
    if opt.show:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        check(result == json.loads((HERE / 'result.json').read_bytes()), 'Measurement differs')
        print('1,024 trees and 3,072 binary32 outputs agree')
