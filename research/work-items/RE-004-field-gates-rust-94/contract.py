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
MODULES = ['foundation_dual_zero', 'foundation_field_inequality']
SOURCE = ROOT / 'src/node94-field-gates'
EXTRA = []


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
    record = {'base': '56c0ec672bd8fdcfaa80f2db700a61e6240b3663', 'kind': 'field-gates', 'cases': len(corpus()),
              'contract_sha256': digest(__file__), 'vectors_sha256': hashlib.sha256(vectors).hexdigest(),
              'new_rust_exists_at_freeze': False, 'equation_mismatches': 0,
              'full_domain_formal_proof': False, 'admitted': facts}
    (directory / 'ORACLE-FREEZE.json').write_text(json.dumps(record, indent=2) + '\n')
    return record

def image(w):
    mode, base, pointer, a, b, omit = w
    memory = {}
    def put(address, value):
        for i in range(8):
            memory[(address + i) & MASK] = (value >> (8 * i)) & 255
    if mode == 0:
        put((base + 8) & MASK, pointer)
        put((pointer + 0x928) & MASK, a)
        if not omit:
            put((pointer + 0x948) & MASK, b)
    else:
        put((base + 0x1458) & MASK, a)
        if not omit:
            put((base + 0x1478) & MASK, b)
    return memory

def registers(w):
    memory, reads = image(w), []
    def load(address):
        address &= MASK
        reads.append(address)
        return int.from_bytes(bytes(memory[(address + i) & MASK] for i in range(8)), 'little')
    try:
        if w[0] == 0:
            rdx = load(w[1] + 8)
            rax = 0
            if load(rdx + 0x928) == 0:
                rax = int(load(rdx + 0x948) == 0)
            return [0, rax, rdx, len(reads), *reads]
        rax = load(w[1] + 0x1458)
        other = load(w[1] + 0x1478)
        rax = (rax & (MASK ^ 255)) | int(rax != other)
        return [0, rax, 0, len(reads), *reads]
    except KeyError:
        return [1, 0, 0, len(reads), *reads]

def closed(w):
    memory = image(w)
    addresses = []
    def word(address):
        key = address % (1 << 64)
        addresses.append(key)
        return sum(memory[(key + i) % (1 << 64)] * 256 ** i for i in range(8))
    try:
        if w[0] == 0:
            pointer = word(w[1] + 8)
            first = word(pointer + 2344)
            value = int(first == 0 and word(pointer + 2376) == 0)
            return [0, value, pointer, len(addresses), *addresses]
        first = word(w[1] + 5208)
        second = word(w[1] + 5240)
        return [0, (first // 256) * 256 + int(first != second), 0, len(addresses), *addresses]
    except KeyError:
        return [1, 0, 0, len(addresses), *addresses]

def corpus():
    edges = [0, 1, 255, 256, (1 << 32), 1 << 63, MASK]
    rows = set()
    for mode in [0, 1]:
        for base, pointer in [(0x1000, 0x4000), (0x1000, 0x1000), (MASK - 8, 0x2000)]:
            for a in edges:
                for b in edges:
                    rows.add((mode, base, pointer, a, b, 0))
        for bit in range(64):
            rows.add((mode, 0x1000, 0x4000, 1 << bit, 0, 0))
            rows.add((mode, 0x1000, 0x4000, 0, 1 << bit, 0))
        rows.add((mode, 0x1000, 0x4000, 0, 0, 1))
    for a in [1, 256, MASK]:
        rows.add((0, 0x1000, 0x4000, a, 0, 1))  # no second field may be read
    # Pointer slot aliases the first/second field, including partial byte overlap.
    for shift in range(-7, 8):
        pointer = 0x4000
        rows.add((0, (pointer + 0x928 - 8 + shift) & MASK, pointer, pointer, 0, 0))
        rows.add((0, (pointer + 0x948 - 8 + shift) & MASK, pointer, 0, pointer, 0))
    rng = random.Random(2026110205)
    for _ in range(2048):
        a, b = rng.getrandbits(64), rng.getrandbits(64)
        if rng.randrange(3) == 0: a = 0
        if rng.randrange(3) == 0: b = a
        rows.add((rng.randrange(2), 0x1000, 0x4000, a, b, 0))
    return sorted(rows)

if __name__ == "__main__":
    print(json.dumps(freeze(Path(sys.argv[1])), indent=2))
