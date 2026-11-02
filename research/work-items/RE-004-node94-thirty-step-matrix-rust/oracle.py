"""Pre-Rust matrix-product and batched-accumulator oracle for thirty steps."""
import datetime
import gzip
import hashlib
import json
from pathlib import Path
import random
import struct
import sys

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, __version__ as capstone_version

TARGET = ROOT / 'artifacts/node/94/hl-node'
TARGET_SHA = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
START, END = 0x565f2e0, 0x565f390
SITES = [0x565f2d5]
LOCK_SHA = '2f8651f1335962befc10e3a00cb7f4fc8d710cadfadd5518ee06bfed819baef9'
WORD, BIAS = 2**64, 2**31 - 1


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def mapping(data):
    secs = sections(data)
    for name in ('.text', '.eh_frame', '.rela.dyn'):
        require(sum(s['name'] == name for s in secs) == 1, 'Ambiguous section ' + name)

    def offset(va, size):
        found = [s for s in secs if s['type'] != 8 and s['address'] <= va
                 and va + size <= s['address'] + s['size']]
        require(len(found) == 1, 'VA mapping is not unique')
        return found[0]['offset'] + va - found[0]['address']
    return secs, offset


def structure(data):
    require(digest(PACKET / 'static-lock.json') == LOCK_SHA, 'Static lock changed')
    contract = json.loads((PACKET / 'static-lock.json').read_text())
    secs, offset = mapping(data)
    read = lambda va, size: data[offset(va, size):offset(va, size) + size]
    bodies = []
    for item in contract['bodies']:
        start, end = item['start'], item['end']
        raw = read(start, end - start)
        require(hashlib.sha256(raw).hexdigest() == item['body_sha256'], 'Complete body changed')
        for record in item['frames'].values():
            encoded = bytes.fromhex(record['hex'])
            require(read(record['va'], len(encoded)) == encoded, 'FDE/CIE changed')
        fde, cie = item['frames']['fde'], item['frames']['cie']
        encoded = bytes.fromhex(fde['hex'])
        pc = fde['va'] + 8 + struct.unpack_from('<i', encoded, 8)[0]
        extent = struct.unpack_from('<I', encoded, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE extent changed')
        require(fde['va'] + 4 - struct.unpack_from('<I', encoded, 4)[0] == cie['va'], 'CIE pointer changed')
        decoded = list(Cs(CS_ARCH_X86, CS_MODE_64).disasm(raw, start))
        require(b''.join(i.bytes for i in decoded) == raw, 'Incomplete linear decode')
        rows = [{'va': hex(i.address), 'hex': i.bytes.hex(), 'mnemonic': i.mnemonic,
                 'operands': i.op_str} for i in decoded]
        if start == START:
            require(end == END and not any(i.mnemonic == 'call' for i in decoded),
                    'Leaf closure changed')
            require(decoded[-1].address == END - 2 and decoded[-1].mnemonic == 'repz ret', 'Return closure changed')
            require([(i.address, i.mnemonic, i.op_str) for i in decoded if i.mnemonic.startswith('j')] == [(0x565f370, 'jne', '0x565f301')], 'Loop edge changed')
            require(not any('[' in i.op_str for i in decoded if i.mnemonic != 'lea'), 'Unexpected memory access')
        else:
            sites = {i.address: i for i in decoded}
            for site in item['sites']:
                require(sites[site].mnemonic == 'jmp' and sites[site].op_str == hex(START), 'Caller edge changed')
        bodies.append({**item, 'instructions': rows})
    padding = bytes.fromhex(contract['padding']['hex'])
    require(read(END, len(padding)) == padding, 'Leaf alignment padding changed')
    relocation_count = 0
    for section in secs:
        if section['name'].startswith('.rela.'):
            require(section['size'] % 24 == 0, 'Malformed RELA extent')
            for address, _, addend in struct.iter_unpack('<QQq', read(section['address'], section['size'])):
                require(addend != START, 'Unexpected naming relocation')
                require(not (address < END and address + 8 > START), 'Code relocation appeared')
                relocation_count += 1
    text = next(s for s in secs if s['name'] == '.text')
    code, scans = read(text['address'], text['size']), {}
    for opcode, width in ((b'\xe8', 5), (b'\xe9', 5), (b'\xeb', 2)):
        hits, pos = [], 0
        while (pos := code.find(opcode, pos)) >= 0:
            if pos + width <= len(code):
                displacement = struct.unpack_from('<b' if width == 2 else '<i', code, pos + 1)[0]
                if text['address'] + pos + width + displacement == START:
                    hits.append(text['address'] + pos)
            pos += 1
        scans[opcode.hex()] = hits
    require(scans == {'e8': [], 'e9': [], 'eb': SITES}, 'Incoming pattern scan changed')
    return {'target_sha256': TARGET_SHA, 'bodies': bodies,
            'incoming_candidates': {k: [hex(x) for x in v] for k, v in scans.items()},
            'relocation_records': relocation_count, 'naming_relocations': 0,
            'text_scan_bytes': len(code), 'capstone_version': capstone_version,
            'static_lock_sha256': LOCK_SHA, 'complete_xref_census': False}


def admit():
    raw = TARGET.read_bytes()
    require(len(raw) == 91774280 and hashlib.sha256(raw).hexdigest() == TARGET_SHA, 'Target identity changed')
    return structure(raw)


def encoded(row):
    return (BIAS + row[0]) + 2**32 * (BIAS + row[1])


def relation(a, b, accumulator):
    matrix = [[1, 0], [0, 1]]
    total = accumulator
    coverage = {'even_steps': 0, 'odd_subtract_steps': 0, 'odd_swap_steps': 0,
                'bias_increment_wraps': 0, 'accumulator_wrap': False}
    for step in range(30):
        before = (a, b, total % WORD, tuple(tuple(row) for row in matrix))
        if a % 2 == 0:
            transform = ((1, 0), (0, 2))
            coverage['even_steps'] += 1
        elif a >= b:
            transform = ((1, -1), (0, 2))
            coverage['odd_subtract_steps'] += 1
        else:
            transform = ((-1, 1), (2, 0))
            total += (a & b) // 2
            coverage['odd_swap_steps'] += 1
        state = (a, b)
        a, b = (sum(row[k] * state[k] for k in range(2)) // 2 for row in transform)
        matrix = [[sum(transform[i][k] * matrix[k][j] for k in range(2))
                   for j in range(2)] for i in range(2)]
        require(all(sum(abs(x) for x in row) <= 2**(step + 1) for row in matrix),
                'Matrix coefficient bound failed')
        # Quotient/remainder form, independent of Rust's wrapping-add/shift.
        increment = (b // 4 + int(b % 4 >= 2)) % 2**62
        coverage['bias_increment_wraps'] += int(b >= WORD - 2)
        total += increment
    coverage['accumulator_wrap'] = total >= WORD
    old_a, old_b, old_total, old_matrix = before
    # RAX,RBX,RCX,RDX,RBP,RDI,R8,R9,R10,R11,R12,R13,R14,R15.
    words = (matrix[0][0] % WORD, matrix[0][1] % WORD,
             matrix[1][1] % WORD, matrix[1][0] % WORD, total % WORD, 0,
             a, b, old_a, old_b, encoded(old_matrix[0]), encoded(old_matrix[1]), old_total, BIAS)
    return ','.join(f'{value:016x}' for value in words), coverage


def fixture_bytes():
    cases = {(a, b, 0) for a in range(128) for b in range(128)}
    edges = {0, 1, 2, 3, WORD - 1, WORD - 2}
    for bit in range(64):
        edges.update((2**bit - 1, 2**bit, min(WORD - 1, 2**bit + 1)))
    for a in sorted(edges):
        for b in sorted(edges):
            cases.add((a, b, WORD - 1 if (a ^ b) & 1 else 0))
    for a in range(32):
        for b in range(32):
            for accumulator in (WORD - 1, 2**63, 1):
                cases.add((a, b, accumulator))
    for a in (0, 1, 2, 3, WORD - 3, WORD - 2, WORD - 1):
        for b in (0, 1, 2, 3, WORD - 3, WORD - 2, WORD - 1):
            for bit in range(64):
                cases.add((a, b, 2**bit)); cases.add((a, b, WORD - 1 - 2**bit))
    rng = random.Random(START)
    for _ in range(4096):
        cases.add(tuple(rng.getrandbits(64) for _ in range(3)))
    inputs, expected = [], []
    coverage = {'cases': len(cases), 'random_seed': hex(START), 'steps_per_case': 30,
                'even_steps': 0, 'odd_subtract_steps': 0, 'odd_swap_steps': 0,
                'bias_increment_wraps': 0, 'accumulator_wrap': 0}
    for a, b, accumulator in sorted(cases):
        output, facts = relation(a, b, accumulator)
        inputs.append(f'{a:016x}\t{b:016x}\t{accumulator:016x}')
        expected.append(output)
        for key, value in facts.items():
            coverage[key] += int(value)
    return ('\n'.join(inputs) + '\n').encode(), ('\n'.join(expected) + '\n').encode(), coverage


def freeze():
    require(not (ROOT / 'src/node94-thirty-step-matrix').exists(), 'Rust already exists')
    folder = PACKET / 'frozen'
    require(not (folder / 'ORACLE-FREEZE.json').exists(), 'Freeze already exists')
    facts = admit()
    inputs, output, coverage = fixture_bytes()
    for name, raw in (('inputs.tsv', inputs), ('expected.txt', output)):
        (folder / (name + '.gz')).write_bytes(gzip.compress(raw, mtime=0))
    record = {'frozen_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'source_base_commit': '56c0ec672bd8fdcfaa80f2db700a61e6240b3663',
              'rust_source_present': False, 'oracle_source_sha256': digest(__file__),
              'inputs_sha256': hashlib.sha256(inputs).hexdigest(),
              'expected_sha256': hashlib.sha256(output).hexdigest(), 'coverage': coverage,
              'static_facts': facts}
    (folder / 'ORACLE-FREEZE.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps({'oracle_source_sha256': record['oracle_source_sha256'], 'coverage': coverage}, indent=2))


if __name__ == '__main__':
    freeze()
