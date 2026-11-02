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
MODULES = ['foundation_byte_indexed_load']
SOURCE = ROOT / 'src/node94-byte-index'
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
    record = {'base': '56c0ec672bd8fdcfaa80f2db700a61e6240b3663', 'kind': 'byte-index', 'cases': len(corpus()),
              'contract_sha256': digest(__file__), 'vectors_sha256': hashlib.sha256(vectors).hexdigest(),
              'new_rust_exists_at_freeze': False, 'equation_mismatches': 0,
              'full_domain_formal_proof': False, 'admitted': facts}
    (directory / 'ORACLE-FREEZE.json').write_text(json.dumps(record, indent=2) + '\n')
    return record

def registers(w):
    base, rsi, count, value, present = w
    reads = [(base + 1) & MASK]
    edx = count
    eax = 0
    if edx < (rsi & U32):
        return [0, eax, edx, rsi, len(reads), *reads]
    rsi &= U32
    reads.append((base + (rsi << 3) + 8) & MASK)
    if not present:
        return [1, 0, 0, 0, len(reads), *reads]
    eax = value
    return [0, eax, edx, rsi, len(reads), *reads]

def closed(w):
    base, incoming, count, byte, present = w
    index = incoming % (1 << 32)
    first = (base + 1) % (1 << 64)
    if index > count:
        return [0, 0, count, incoming, 1, first]
    second = (base + 8 * (index + 1)) % (1 << 64)
    return ([0, byte, count, index, 2, first, second] if present
            else [1, 0, 0, 0, 2, first, second])

def corpus():
    rows = set()
    for count in range(256):
        for index in range(257):
            high = [0, 0x12345678, 0x80000000, U32][(count + index) % 4]
            rows.add((0x1000, (high << 32) | index, count, (count * 17 + index * 29) % 256, int(index <= count)))
    for count in [0, 1, 255]:
        for index in {0, count}:
            for byte in range(256):
                rows.add((MASK - 7, (U32 << 32) | index, count, byte, 1))
    for bit in range(32, 64):
        for index in [0, 256, U32]:
            rows.add((0, (1 << bit) | index, 0, 255, int(index == 0)))
    rng = random.Random(2026110203)
    for _ in range(1024):
        rsi = rng.getrandbits(64); count = rng.getrandbits(8)
        rows.add((rng.getrandbits(64), rsi, count, rng.getrandbits(8), int((rsi & U32) <= count)))
    rows.add((0x1000, 0, 0, 1, 0))  # checked-view refusal, not native fault equivalence
    return sorted(rows)

if __name__ == "__main__":
    print(json.dumps(freeze(Path(sys.argv[1])), indent=2))
