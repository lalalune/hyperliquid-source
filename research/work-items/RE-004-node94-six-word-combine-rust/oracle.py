"""Pre-Rust whole-integer and immutable-overlay oracle for six-word combine."""
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
START, END = 0x565f000, 0x565f20c
SITES = [0x565ef7c, 0x565ef8e]
LOCK_SHA = '69b350bf1c6938639c7ce0f935a6f0ca10bf5ce73e4f4dfeadac50174583105a'
WORD, WIDTH, WIDE = 2**64, 2**384, 2**448


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
            require(end == END and not any(i.mnemonic == 'call' or i.mnemonic.startswith('j') for i in decoded),
                    'Leaf closure changed')
            require(decoded[-1].address == END - 2 and decoded[-1].mnemonic == 'repz ret', 'Return closure changed')
            require(not any('rip' in i.op_str for i in decoded), 'Unexpected global data edge')
        else:
            sites = {i.address: i for i in decoded}
            for site in item['sites']:
                require(sites[site].mnemonic == 'call' and sites[site].op_str == hex(START), 'Caller edge changed')
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
    code, direct, pos = read(text['address'], text['size']), [], 0
    while (pos := code.find(b'\xe8', pos)) >= 0:
        if pos + 5 <= len(code) and text['address'] + pos + 5 + struct.unpack_from('<i', code, pos + 1)[0] == START:
            direct.append(text['address'] + pos)
        pos += 1
    require(direct == SITES, 'Direct caller scan changed')
    return {'target_sha256': TARGET_SHA, 'bodies': bodies, 'direct_e8_sites': [hex(x) for x in direct],
            'relocation_records': relocation_count, 'naming_relocations': 0,
            'text_scan_bytes': len(code), 'capstone_version': capstone_version,
            'static_lock_sha256': LOCK_SHA, 'complete_xref_census': False}


def admit():
    raw = TARGET.read_bytes()
    require(len(raw) == 91774280 and hashlib.sha256(raw).hexdigest() == TARGET_SHA, 'Target identity changed')
    return structure(raw)


def product(value, coefficient):
    """Mathematical signed product plus the target's discarded-zero-carry term."""
    correction = -abs(coefficient) * WIDTH if value == 0 and coefficient < 0 else 0
    return coefficient * value + correction


def relation(image, source, destination, first, second):
    if source + 96 > len(image) or destination + 48 > len(image):
        return 'span:' + image.hex(), {'refusal': True}
    a = int.from_bytes(image[source:source + 48], 'little')
    pa = product(a, first)
    # Immutable byte overlay, independent of a future in-place Rust load/store loop.
    interim = image[:destination] + (pa % WIDTH).to_bytes(48, 'little') + image[destination + 48:]
    b = int.from_bytes(interim[source + 48:source + 96], 'little')
    pb = product(b, second)
    total = (pa + pb) % WIDE
    signed = total if total < WIDE // 2 else total - WIDE
    magnitude = abs(signed // 2**30) % WIDTH
    result = image[:destination] + magnitude.to_bytes(48, 'little') + image[destination + 48:]
    # These two raw register values are the last multiply, before carry addition.
    transformed = (-b) % WIDTH if second < 0 else b
    last_multiply = (transformed // 2**320) * abs(second)
    rax, rdx = last_multiply % WORD, last_multiply // WORD
    rbx = int(signed < 0)
    r14 = WORD - 1 if signed < 0 else 0
    r15 = (pb % WIDE) // WIDTH
    words = [(magnitude // 2**(64 * i)) % WORD for i in range(6)]
    output = 'ok:' + ','.join(f'{x:016x}' for x in (rax, rdx, rbx, r14, r15, *words)) + ':' + result.hex()
    return output, {'refusal': False, 'first_negative_zero': a == 0 and first < 0,
                    'second_negative_zero': b == 0 and second < 0,
                    'second_input_changed': interim[source + 48:source + 96] != image[source + 48:source + 96],
                    'negative_nonmultiple': signed < 0 and signed % 2**30 != 0,
                    'sum_signed_wrap': not (-WIDE // 2 <= pa + pb < WIDE // 2),
                    'negative_sum': signed < 0}


def fixture_bytes():
    cases = set()
    rng = random.Random(START)
    masks = (0, WIDTH - 1, 1, 2**383, (WIDTH - 1) // 3, 2**320 - 1)
    pairs = ((0, 0), (0, WIDTH - 1), (WIDTH - 1, 0), (1, 1),
             (2**383, 2**320 - 1), ((WIDTH - 1) // 3, 2 * ((WIDTH - 1) // 3)))
    coefficients = (-2**63, -2**63 + 1, -2**32, -2**30, -1, 0, 1, 2**30, 2**32, 2**63 - 1)
    selected = ((0, 0), (-1, 1), (1, -1), (-2**63, -2**63),
                (2**63 - 1, 2**63 - 1), (2**30, -2**30), (-2**32, 2**32))

    def include(a, b, first, second, destination, salt=0):
        image = bytes((i * 73 + salt * 29 + 11) % 256 for i in range(208))
        image = image[:64] + a.to_bytes(48, 'little') + b.to_bytes(48, 'little') + image[160:]
        cases.add((64, destination, first, second, image))

    for destination in (0, *range(17, 160), 160):
        for a, b in pairs:
            for first, second in selected:
                include(a, b, first, second, destination)
    for destination in (0, 64, 80, 112, 159):
        for a, b in pairs[:4]:
            for first in coefficients:
                for second in coefficients:
                    include(a, b, first, second, destination)
    for bit in range(384):
        for a, b in ((2**bit, 0), (0, 2**bit)):
            for destination in (0, 113):
                for first, second in ((1, -1), (-1, 1)):
                    include(a, b, first, second, destination, 1)
    for bit in (0, 1, 29, 30, 31, 63, 64, 127, 255, 319, 320, 383):
        for offset in (-1, 0, 1):
            a = (2**bit + offset) % WIDTH
            for b in masks:
                include(a, b, -1, -1, 0, 2)
    for _ in range(2048):
        include(rng.getrandbits(384), rng.getrandbits(384),
                rng.randint(-2**63, 2**63 - 1), rng.randint(-2**63, 2**63 - 1), rng.randrange(161), rng.randrange(256))
    for length in (0, 1, 47, 48, 95, 96, 97, 159, 160, 207, 208):
        for source in (0, 1, 64, WORD - 96, WORD - 1):
            for destination in (0, 1, 64, 160, WORD - 48, WORD - 1):
                image = bytes((i * 37 + 5) % 256 for i in range(length))
                cases.add((source, destination, -2**63, -1, image))
    inputs, outputs = [], []
    coverage = {'cases': len(cases), 'refusal': 0, 'first_negative_zero': 0,
                'second_negative_zero': 0, 'second_input_changed': 0, 'negative_nonmultiple': 0,
                'sum_signed_wrap': 0, 'negative_sum': 0, 'random_seed': hex(START)}
    for source, destination, first, second, image in sorted(cases):
        output, flags = relation(image, source, destination, first, second)
        inputs.append(f'{source}\t{destination}\t{first % WORD:016x}\t{second % WORD:016x}\t{image.hex() or "-"}')
        outputs.append(output)
        for key, value in flags.items():
            coverage[key] += int(value)
    return ('\n'.join(inputs) + '\n').encode(), ('\n'.join(outputs) + '\n').encode(), coverage


def freeze():
    require(not (ROOT / 'src/node94-six-word-combine').exists(), 'Rust already exists')
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
