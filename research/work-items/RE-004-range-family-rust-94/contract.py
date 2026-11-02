"""Pre-Rust static contract. No captured machine code is executed."""
import hashlib
import importlib.util
import json
from pathlib import Path
import random
import struct
import sys

ROOT = Path(__file__).resolve().parents[3]
PACKET = Path(__file__).resolve().parent
MASK = (1 << 64) - 1
U32 = (1 << 32) - 1
SHA = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
MODULES = ['foundation_range_test']
SOURCE = ROOT / 'src/node94-range-family'
EXTRA = [(89263648, 89263729, 'f30f1efa488b05059947004839c7730ab9010000004839c672344c8b05df9847004c39c7488b0de59847000f92c24839cf400f93c721fa4c39c6410f92c14839ce400f93c64121f14438ca0f94c189c8c3')]


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load_module(name):
    sys.path.insert(0, str(ROOT / 'tools'))
    spec = importlib.util.spec_from_file_location(name, ROOT / 'tools' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def body_checks(data):
    from elf_index import sections
    secs = sections(data)
    def read(va, length):
        candidates = [s for s in secs if s['type'] != 8 and s['address'] <= va
                      and va + length <= s['address'] + s['size']]
        if len(candidates) != 1:
            raise ValueError('Ambiguous byte window')
        s = candidates[0]
        offset = s['offset'] + va - s['address']
        return data[offset:offset + length]
    windows = []
    for name in MODULES:
        module = load_module(name)
        if read(module.START, module.END - module.START) != module.BODY:
            raise ValueError('Instruction body changed')
        windows.append([module.START, module.END, hashlib.sha256(module.BODY).hexdigest()])
    for start, end, hexbytes in EXTRA:
        raw = bytes.fromhex(hexbytes)
        if len(raw) != end - start or read(start, len(raw)) != raw:
            raise ValueError('Companion instructions changed')
        for offset, next_pc, address in [(7, 11, 0x599a730), (0x1d, 0x21, 0x599a720), (0x27, 0x2b, 0x599a730)]:
            if start + next_pc + struct.unpack_from('<i', raw, offset)[0] != address:
                raise ValueError('Companion global read changed')
        windows.append([start, end, hashlib.sha256(raw).hexdigest()])
    return windows


def admit(binary):
    data = Path(binary).read_bytes()
    if len(data) != 91774280 or hashlib.sha256(data).hexdigest() != SHA:
        raise ValueError('Wrong node94 capture')
    facts = []
    for name in MODULES:
        module = load_module(name)
        facts.append({'checker': name, 'checker_sha256': digest(ROOT / 'tools' / (name + '.py')),
                      'facts': module.inspect(binary)})
    return json.loads(json.dumps({'target_sha256': SHA, 'windows': body_checks(data), 'facts': facts}))


def vector_bytes():
    rows = []
    for index, words in enumerate(corpus()):
        expected = registers(words)
        if expected != closed(words):
            raise ValueError('Independent static expressions disagree: ' + str(index))
        rows.append(str(index) + '\t' + ','.join(map(str, words)) + '\t' + ','.join(map(str, expected)))
    return ('\n'.join(rows) + '\n').encode()


def freeze(binary):
    if (SOURCE / 'lib.rs').exists():
        raise ValueError('The new Rust source must not exist before freezing')
    directory = PACKET / 'preparation'
    directory.mkdir()
    facts = admit(binary)
    vectors = vector_bytes()
    (directory / 'vectors.tsv').write_bytes(vectors)
    record = {'base': '56c0ec672bd8fdcfaa80f2db700a61e6240b3663', 'kind': 'range-family', 'cases': len(corpus()),
              'contract_sha256': digest(__file__), 'vectors_sha256': hashlib.sha256(vectors).hexdigest(),
              'new_rust_exists_at_freeze': False, 'equation_mismatches': 0,
              'full_domain_formal_proof': False, 'admitted': facts}
    (directory / 'ORACLE-FREEZE.json').write_text(json.dumps(record, indent=2) + '\n')
    return record

LO, HI = 0x599a730, 0x599a720

def registers(w):
    mode, a, b, c, d, e = w
    if mode == 0:
        value, lo, hi, rax, rcx = a, b, c, d, e
        rdx = hi
        rax = (rax & (MASK ^ 255)) | int(value >= lo)
        rcx = (rcx & (MASK ^ 255)) | int(value < rdx)
        return [(rax & rcx) & U32, 2, HI, LO]
    left, right, lo_first, hi, lo_second = a, b, c, d, e
    rax = lo_first
    if left < rax:
        rcx = 1
        if right < rax:
            return [rcx, 1, LO]
    r8 = hi
    rcx = lo_second
    dl = int(left < r8) & int(left >= rcx)
    r9b = int(right < r8) & int(right >= rcx)
    rcx = (rcx & (MASK ^ 255)) | int(dl == r9b)
    return [rcx & U32, 3, LO, HI, LO]

def closed(w):
    if w[0] == 0:
        _, value, lo, hi, old_a, old_c = w
        preserved = old_a & old_c & 0xffffff00
        return [preserved | int(lo <= value < hi), 2, HI, LO]
    _, x, y, initial, upper, lower = w
    if max(x, y) < initial:
        return [1, 1, LO]
    same = (lower <= x < upper) == (lower <= y < upper)
    return [(lower & 0xffffff00) + int(same), 3, LO, HI, LO]

def corpus():
    edges = [0, 1, 2, 255, 256, 257, (1 << 32) - 1, 1 << 32, 1 << 63, MASK]
    rows = set()
    for lo in edges:
        for hi in edges:
            for value in edges:
                rows.add((0, value, lo, hi, MASK, 0xdeadbeef00ffff00))
                rows.add((1, value, hi, lo, hi, lo))
    for bit in range(64):
        for second in [0, MASK, 1 << bit]:
            rows.add((0, 1, 0, 2, 1 << bit, second))
    rng = random.Random(2026110204)
    for _ in range(2048):
        row = tuple(rng.getrandbits(64) for _ in range(5))
        rows.add((rng.randrange(2), *row))
    return sorted(rows)

if __name__ == "__main__":
    print(json.dumps(freeze(Path(sys.argv[1])), indent=2))
