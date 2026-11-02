"""Pre-Rust finite geometric-sum oracle for the complete mask and store relation."""
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
START, END = 0x5521d10, 0x5521d37
STORE = 0x5788110
SITES = [0x54b9c3f]
LOCK_SHA = '3f78aaf6e1e416bcc77261f41dc05908682cae83f523eb08080296e2a631a997'
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
            require(decoded[-1].address == END - 1 and decoded[-1].mnemonic == 'ret', 'Return closure changed')
            require([(i.address, i.mnemonic, i.op_str) for i in decoded if i.mnemonic.startswith('j')] == [(0x5521d1f, 'je', '0x5521d2f')], 'Sentinel branch changed')
            require([i.address for i in decoded if '[' in i.op_str] == [0x5521d2f], 'Memory closure changed')
            require(0x5521d36 + struct.unpack_from('<i', raw, 34)[0] == STORE, 'RIP store target changed')
        else:
            sites = {i.address: i for i in decoded}
            for site in item['sites']:
                require(sites[site].mnemonic == 'call' and sites[site].op_str == hex(START), 'Caller edge changed')
        bodies.append({**item, 'instructions': rows})
    padding = bytes.fromhex(contract['padding']['hex'])
    require(read(END, len(padding)) == padding, 'Leaf alignment padding changed')
    store = contract['store']
    require(read(STORE, 8).hex() == store['initial_hex'] == 'ff' * 8, 'Initial global bytes changed')
    require(next(s for s in secs if s['address'] <= STORE and STORE + 8 <= s['address'] + s['size']) == store['section'], 'Global mapping changed')
    require(store['section']['name'] == '.data' and store['section']['flags'] & 1, 'Writable global section changed')
    relocation_count = 0
    for section in secs:
        require(section['type'] != 9, 'Unexpected REL table')
        if section['type'] == 4:
            require(section['size'] % 24 == 0, 'Malformed RELA extent')
            for address, info, addend in struct.iter_unpack('<QQq', read(section['address'], section['size'])):
                require((info & 0xffffffff) in (1, 6, 7, 8, 18), 'Unknown relocation width')
                require(addend != START, 'Unexpected naming relocation')
                require(not (address < END + 9 and address + 8 > START), 'Code/padding relocation appeared')
                require(not (address < STORE + 8 and address + 8 > STORE), 'Global writer relocation appeared')
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
            'relocation_records': relocation_count, 'naming_relocations': 0, 'store': store,
            'text_scan_bytes': len(code), 'capstone_version': capstone_version,
            'static_lock_sha256': LOCK_SHA, 'complete_xref_census': False}


def admit():
    raw = TARGET.read_bytes()
    require(len(raw) == 91774280 and hashlib.sha256(raw).hexdigest() == TARGET_SHA, 'Target identity changed')
    return structure(raw)



def relation(value, entry_rcx, bias):
    # A finite geometric sum, not a masked machine shift/subtraction.
    count = 64 if value == WORD - 1 else value % 64
    mask = sum(2**position for position in range(count))
    rcx = entry_rcx if count == 64 else value % 2**32
    destination = (STORE + bias) % WORD
    return mask, rcx, destination, mask


def fixture_bytes():
    cases = set()
    def add(value, rcx, bias, initial):
        cases.add((value % WORD, rcx % WORD, bias % WORD, initial % WORD))
    highs = {0, 1, 2**26 - 1, 2**57, 2**58 - 1}
    for bit in range(58):
        highs.update((2**bit, 2**58 - 1 - 2**bit))
    biases = (0, 1, 2**32, 2**63, WORD - STORE - 1, WORD - STORE, WORD - STORE + 1, WORD - 1)
    for high in sorted(highs):
        for low in range(64):
            value = 64 * high + low
            for i, entry in enumerate((0, WORD - 1)):
                add(value, entry, biases[(high + low + i) % len(biases)], value ^ entry)
    for low in range(256):
        for high in (0, 1, 2**32 - 1, 2**56 - 1):
            for bias in biases:
                add(256 * high + low, 0xdeadbeef12345678, bias, 0xa5a5a5a5a5a5a5a5)
    for bit in range(64):
        for value in (WORD - 1, WORD - 2, 2**bit - 1, 2**bit, min(WORD - 1, 2**bit + 1)):
            for entry in (2**bit, WORD - 1 - 2**bit):
                for bias in biases:
                    add(value, entry, bias, 0)
    rng = random.Random(START)
    for _ in range(2048):add(*(rng.getrandbits(64) for _ in range(4)))
    inputs, expected = [], []
    coverage = {'cases': len(cases), 'sentinel_cases': 0, 'ordinary_shift_counts': [],
                'ordinary_low32_all_ones': 0, 'ordinary_high32_set': 0,
                'destination_wraps': 0, 'sentinel_preserves_nonzero_rcx': 0,
                'slot_already_equal': 0, 'random_seed': hex(START)}
    counts = set()
    for value, entry, bias, initial in sorted(cases):
        output = relation(value, entry, bias)
        inputs.append('\t'.join(f'{x:016x}' for x in (value, entry, bias, initial)))
        expected.append(','.join(f'{x:016x}' for x in output))
        sentinel = value == WORD - 1
        coverage['sentinel_cases'] += sentinel
        coverage['sentinel_preserves_nonzero_rcx'] += sentinel and entry != 0
        coverage['ordinary_low32_all_ones'] += not sentinel and value % 2**32 == 2**32 - 1
        coverage['ordinary_high32_set'] += not sentinel and value >= 2**32
        coverage['destination_wraps'] += STORE + bias >= WORD
        coverage['slot_already_equal'] += output[0] == initial
        if not sentinel:counts.add(value % 64)
    coverage['ordinary_shift_counts'] = sorted(counts)
    return ('\n'.join(inputs) + '\n').encode(), ('\n'.join(expected) + '\n').encode(), coverage


def freeze():
    require(not (ROOT / 'src/node94-mask-builder').exists(), 'Rust already exists')
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
