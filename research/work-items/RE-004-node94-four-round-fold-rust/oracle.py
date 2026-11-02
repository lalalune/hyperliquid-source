"""Pre-Rust whole-integer oracle for four multiply/carry rounds and low folds."""
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
from fde_extents import eh_frame_records
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, __version__ as capstone_version

TARGET = ROOT / 'artifacts/node/94/hl-node'
TARGET_SHA = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
START, END = 0x565d8a0, 0x565da24
SITES = [0x565d785, 0x565d825]
LOCK_SHA = 'a295f8599882d60c9ee3c8ccdebc685f3ee7415439c96ff33446c9e3ed0828e3'
WORD = 2**64


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
    _, frames = eh_frame_records(data)
    bodies = []
    for item in contract['bodies']:
        start, end = item['start'], item['end']
        overlapping = [f for f in frames if f['start'] < end and start < f['end']]
        require(len(overlapping) == 1 and (overlapping[0]['start'], overlapping[0]['end']) == (start, end), 'Unique complete FDE changed')
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
            require(not any(i.mnemonic.startswith('j') for i in decoded), 'Unexpected branch')
            memory = [(i.mnemonic, i.op_str) for i in decoded if '[' in i.op_str]
            expected = [('mov', 'rax, qword ptr [rsi]'), ('mov', 'r10, qword ptr [rsi + 8]'),
                        ('mov', 'r11, qword ptr [rsi + 0x10]'), ('mov', 'r12, qword ptr [rsi + 0x18]')]
            expected += [('mul', f'qword ptr [rbx{suffix}]') for _ in range(4)
                         for suffix in ('', ' + 8', ' + 0x10', ' + 0x18')]
            require(memory == expected, 'Complete memory-read closure changed')
        else:
            sites = {i.address: i for i in decoded}
            for site in item['sites']:
                require(sites[site].mnemonic == 'call' and sites[site].op_str == hex(START), 'Caller edge changed')
        bodies.append({**item, 'instructions': rows})
    padding = bytes.fromhex(contract['padding']['hex'])
    require(read(END, len(padding)) == padding, 'Leaf alignment padding changed')
    relocation_count = 0
    for section in secs:
        require(section['type'] != 9, 'Unexpected REL table')
        if section['type'] == 4:
            require(section['size'] % 24 == 0, 'Malformed RELA extent')
            for address, info, addend in struct.iter_unpack('<QQq', read(section['address'], section['size'])):
                require((info & 0xffffffff) in (1, 6, 7, 8, 18), 'Unknown relocation width')
                require(addend != START, 'Unexpected naming relocation')
                for body in contract['bodies']:
                    require(not (address < body['end'] and address + 8 > body['start']), 'Body relocation appeared')
                require(not (address < END + len(padding) and address + 8 > END), 'Padding relocation appeared')
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
    require(scans == {'e8': SITES, 'e9': [], 'eb': []}, 'Incoming pattern scan changed')
    return {'target_sha256': TARGET_SHA, 'bodies': bodies,
            'incoming_candidates': {k: [hex(x) for x in v] for k, v in scans.items()},
            'relocation_records': relocation_count, 'naming_relocations': 0,
            'text_scan_bytes': len(code), 'capstone_version': capstone_version,
            'static_lock_sha256': LOCK_SHA, 'complete_xref_census': False}


def admit():
    raw = TARGET.read_bytes()
    require(len(raw) == 91774280 and hashlib.sha256(raw).hexdigest() == TARGET_SHA, 'Target identity changed')
    return structure(raw)



def relation(words):
    # One whole 256-bit sum per round. No per-limb carry chain or register simulation.
    a = sum(words[i] * WORD**i for i in range(4))
    m = sum(words[i + 4] * WORD**i for i in range(4))
    coefficient = words[8]
    quotients, trace = [], []
    for _ in range(4):
        q = (a * coefficient) % WORD
        total = a + q * m
        residue = total % WORD
        local_carry = (a % WORD + q * (m % WORD)) // WORD
        discarded = (residue + local_carry) // WORD
        trace.append((q, residue, local_carry, discarded, a % WORD * coefficient >= WORD))
        a = total // WORD + residue - WORD * discarded
        require(0 <= a < WORD**4, 'Round escaped four-word domain')
        quotients.append(q)
    limbs = [(a // WORD**i) % WORD for i in range(4)]
    # RAX, RDX, R9, R10, R11, R12, R13, R14, R15.
    return (limbs[0], limbs[3], limbs[3], *quotients[1:], *limbs[:3]), trace


def fixture_bytes():
    cases = set()
    def add(a, m, coefficient):
        cases.add(tuple(x % WORD for x in (*a, *m, coefficient)))
    zeros, ones = [0] * 4, [WORD - 1] * 4
    edge = [0, 1, 2, 3, WORD // 2 - 1, WORD // 2, WORD - 2, WORD - 1]
    patterns = [zeros, ones, [1, 0, 0, 0], [0, 0, 0, 1],
                [0xaaaaaaaaaaaaaaaa, 0x5555555555555555] * 2]
    for value in edge:
        patterns.append([value] * 4)
        for lane in range(4):
            a = [0] * 4; a[lane] = value; patterns.append(a)
            a = [WORD - 1] * 4; a[lane] = value; patterns.append(a)
    for a in patterns:
        for m in patterns:
            for coefficient in (0, 1, WORD // 2, WORD - 1):
                add(a, m, coefficient)
    for bit in range(64):
        for delta in (-1, 0, 1):
            v = (2**bit + delta) % WORD
            for lane in range(4):
                a = [0] * 4; a[lane] = v
                m = [WORD - 1] * 4; m[lane] = v
                for coefficient in (v, WORD - 1 - v):
                    add(a, m, coefficient)
                    add(m, a, coefficient)
    # Exact low fold overflow: first-round low 2 plus carry WORD-2 wraps to zero.
    add([1, 0, 0, 0], [WORD - 1, 0, 0, 0], WORD - 1)
    rng = random.Random(START)
    for _ in range(4096):
        add([rng.getrandbits(64) for _ in range(4)],
            [rng.getrandbits(64) for _ in range(4)], rng.getrandbits(64))
    inputs, expected = [], []
    coverage = {'cases': len(cases), 'random_seed': hex(START),
                'zero_q_by_round': [0] * 4, 'nonzero_residue_by_round': [0] * 4,
                'discarded_fold_carry_by_round': [0] * 4, 'q_product_wrap_by_round': [0] * 4,
                'equal_input_operand': 0, 'zero_coefficient': 0, 'high_bit_coefficient': 0}
    for words in sorted(cases):
        output, trace = relation(words)
        inputs.append('\t'.join(f'{x:016x}' for x in words))
        expected.append(','.join(f'{x:016x}' for x in output))
        coverage['equal_input_operand'] += words[:4] == words[4:8]
        coverage['zero_coefficient'] += words[8] == 0
        coverage['high_bit_coefficient'] += words[8] >= WORD // 2
        for i, (q, residue, carry, discarded, wrap) in enumerate(trace):
            coverage['zero_q_by_round'][i] += q == 0
            coverage['nonzero_residue_by_round'][i] += residue != 0
            coverage['discarded_fold_carry_by_round'][i] += discarded
            coverage['q_product_wrap_by_round'][i] += wrap
    require(all(coverage['discarded_fold_carry_by_round']), 'Missing fold-carry cases')
    return ('\n'.join(inputs) + '\n').encode(), ('\n'.join(expected) + '\n').encode(), coverage


def freeze():
    require(not (ROOT / 'src/node94-four-round-fold').exists(), 'Rust already exists')
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
