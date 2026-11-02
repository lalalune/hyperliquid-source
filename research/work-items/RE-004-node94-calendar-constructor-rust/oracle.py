"""Pre-Rust absolute-year binary-search oracle; static target reads only."""
import bisect
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
START, END = 0x151f6f0, 0x151f86a
LOCK_SHA = '3720ba8eb7e624225554e46b84a41f2e3b3595dc9a20cb0dd217d6ac5e734803'
MIN_YEAR, MAX_YEAR = -262143, 262142
YEAR_DAYS = tuple(366 if y % 4 == 0 and (y % 100 != 0 or y % 400 == 0) else 365 for y in range(400))
PREFIX = [0]
for length in YEAR_DAYS:
    PREFIX.append(PREFIX[-1] + length)
LEAPS = bytes(PREFIX[y] - 365 * y for y in range(401))
FLAGS = bytes((0 if YEAR_DAYS[y] == 366 else 8) | (1 + (PREFIX[y] + 3) % 7) for y in range(400))


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
    rels, count = {}, 0
    for section in secs:
        require(section['type'] != 9, 'Unexpected REL table')
        if section['type'] == 4:
            require(section['size'] % 24 == 0, 'Malformed RELA extent')
            for index in range(0, section['size'], 24):
                va = section['address'] + index
                address, info, addend = struct.unpack('<QQq', read(va, 24))
                require((info & 0xffffffff) in (1, 6, 7, 8, 18), 'Unknown relocation width')
                require(address not in rels, 'Duplicate relocation address')
                rels[address] = dict(record_va=va, info=info, addend=addend)
                count += 1
    for writer, value in rels.items():
        for slot, expected in contract['relocations'].items():
            slot = int(slot)
            if writer < slot + 8 and slot < writer + 8:
                require(writer == slot and value == expected, 'Conflicting slot relocation writer')
        for body in contract['bodies']:
            require(not (writer < body['end'] and body['start'] < writer + 8), 'Code relocation writer')
        for item in contract['data']:
            if writer < item['va'] + len(item['hex']) // 2 and item['va'] < writer + 8:
                require(str(writer) in contract['relocations'] and value == contract['relocations'][str(writer)], 'Unbound data relocation writer')
    for address, expected in contract['relocations'].items():
        address = int(address)
        require(rels.get(address) == expected, 'Relocation changed')
        require(read(address, 8) == b'\0' * 8, 'Relocated slot bytes changed')
    naming = [hex(a) for a, r in rels.items() if r['addend'] == START]
    require(naming == contract['naming_slots'], 'Naming relocation set changed')
    for item in contract['data']:
        raw = bytes.fromhex(item['hex'])
        require(read(item['va'], len(raw)) == raw, 'Constant/location bytes changed')
    require(read(0x250354, 401) == LEAPS, 'Gregorian leap-prefix identity changed')
    require(read(0x2504e5, 400) == FLAGS, 'Packed flag identity changed')
    require(not any(0x250354 <= a < 0x250675 for a in rels), 'Table relocation appeared')
    _, frames = eh_frame_records(data)
    bodies = []
    for item in contract['bodies']:
        start, end = item['start'], item['end']
        overlapping = [f for f in frames if f['start'] < end and start < f['end']]
        require(len(overlapping) == 1 and (overlapping[0]['start'], overlapping[0]['end']) == (start, end), 'Unique exact FDE changed')
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
        sites = {i.address: i for i in decoded}
        if start == START:
            require(end == END, 'Callee end changed')
            for i in decoded:
                if i.mnemonic.startswith('j'):
                    require(START <= int(i.op_str, 16) < END, 'Branch escapes selected body')
            calls = {0x151f830: 0x576e150, 0x151f842: 0x576dfc8,
                     0x151f857: 0x576dfc8, 0x151f864: 0x576e118}
            require({i.address for i in decoded if i.mnemonic == 'call'} == set(calls), 'Call set changed')
            for site, slot in calls.items():
                insn = sites[site]
                require(insn.bytes[:2] == b'\xff\x15' and site + 6 + struct.unpack_from('<i', insn.bytes, 2)[0] == slot,
                        'Panic call slot changed')
            for site, target in ((0x151f755, 0x250354), (0x151f7fb, 0x2504e5),
                                 (0x151f829, 0x5672140), (0x151f836, 0x56721a0),
                                 (0x151f848, 0x5672158), (0x151f85d, 0x5672170)):
                insn = sites[site]
                require(insn.mnemonic == 'lea' and site + 7 + struct.unpack_from('<i', insn.bytes, 3)[0] == target,
                        'RIP-relative data edge changed')
        else:
            for site in item['sites']:
                insn = sites[site]
                require(insn.mnemonic == 'call', 'Caller site is not an instruction')
                target = site + len(insn.bytes) + struct.unpack_from('<i', insn.bytes, len(insn.bytes) - 4)[0]
                require(target == (START if insn.bytes[0] == 0xe8 else 0x576e890), 'Caller destination changed')
        bodies.append({**item, 'instructions': rows})
    require(read(END, 6) == b'\xcc' * 6, 'Callee padding changed')
    text = next(s for s in secs if s['name'] == '.text')
    code, candidates = read(text['address'], text['size']), []
    for opcode in (b'\xe8', b'\xe9', b'\xff\x15', b'\xff\x25'):
        pos = 0
        while (pos := code.find(opcode, pos)) >= 0:
            length = len(opcode) + 4
            if pos + length <= len(code):
                target = text['address'] + pos + length + struct.unpack_from('<i', code, pos + len(opcode))[0]
                if target == (START if opcode in (b'\xe8', b'\xe9') else 0x576e890):
                    candidates.append(text['address'] + pos)
            pos += 1
    require([hex(x) for x in sorted(candidates)] == contract['incoming_sites'], 'Incoming pattern scan changed')
    return {'target_sha256': TARGET_SHA, 'bodies': bodies, 'data': contract['data'],
            'relocations': contract['relocations'], 'naming_slots': naming,
            'incoming_pattern_candidates': contract['incoming_sites'], 'complete_xref_census': False,
            'qualified_incoming_sites': [hex(a) for b in bodies[1:] for a in b['sites']],
            'relocation_records': count, 'text_scan_bytes': len(code), 'capstone_version': capstone_version,
            'static_lock_sha256': LOCK_SHA,
            'prior_evidence_sha256': digest(ROOT / 'research/work-items/foundation-millis-94/evidence.json')}


def certificates():
    """Finite arithmetic lemmas over normalized residues; no instruction execution."""
    reciprocal = []
    for divisor, shift, multiplier, bound in ((146097, 47, 0x396b06bd, 2**31),):
        scale = 2**shift
        error = multiplier * divisor - scale
        upper = (bound // divisor) * error + (divisor - 1) * multiplier
        require(0 < error and upper < scale and multiplier % 2 == 1 and bound < scale,
                'Signed reciprocal proof inequality failed')
        reciprocal.append(dict(divisor=divisor, scale=scale, multiplier=multiplier,
                               maximum_magnitude=bound, positive_error=error, residual_upper=upper))
    corrected = 0
    for day in range(146097):
        high = day * 0x6719f361 // 2**32
        estimate = ((day - high) // 2 + high) // 256
        require(estimate == day // 365 and estimate <= 400, '365 quotient identity failed')
        rem = day % 365
        if rem < LEAPS[estimate]:
            require(day >= 365 and estimate >= 1, 'Subtraction panic reachable')
            year = estimate - 1
            require(year < 401 and rem + 365 - LEAPS[year] >= rem, 'Correction panic reachable')
            ordinal = rem + 366 - LEAPS[year]
            corrected += 1
        else:
            require(day <= 0x23a4f and estimate < 400, 'Flag table panic reachable')
            year, ordinal = estimate, rem - LEAPS[estimate] + 1
        actual = bisect.bisect_right(PREFIX, day) - 1
        require(year == actual and ordinal == day - PREFIX[actual] + 1, 'Calendar partition changed')
        require(1 <= ordinal <= YEAR_DAYS[year], 'Ordinal gate would reject')
        require(((ordinal - 367) % 2**32) >= 0xfffffe92, 'Unsigned ordinal gate changed')
        require(((ordinal << 4) | FLAGS[year]) & 0x1ff8 < 0x16e1, 'Final packed gate would reject')
    return {'reciprocal_inequalities': reciprocal, 'normalized_days_exhausted': 146097,
            'year_correction_cases': corrected, 'leap_prefix_bytes': 401, 'flag_bytes': 400}


def admit():
    raw = TARGET.read_bytes()
    require(len(raw) == 91774280 and hashlib.sha256(raw).hexdigest() == TARGET_SHA, 'Target identity changed')
    return structure(raw)



WORD = 2**64
MIN_DAY, MAX_DAY = -95746129, 95745399


def absolute_start(year):
    return 365 * year + (year + 3) // 4 - (year + 99) // 100 + (year + 399) // 400


def relation(raw_day, entry_rax):
    bits = raw_day % 2**32
    day = bits if bits < 2**31 else bits - 2**32
    if not MIN_DAY <= day <= MAX_DAY:
        return (0, entry_rax), None
    absolute = day + 365
    # Whole-year monotone search; no 400-year quotient or correction step.
    left, right = MIN_YEAR, MAX_YEAR + 1
    while left + 1 < right:
        middle = (left + right) // 2
        if absolute_start(middle) <= absolute:
            left = middle
        else:
            right = middle
    year = left
    ordinal = absolute - absolute_start(year) + 1
    leap = absolute_start(year + 1) - absolute_start(year) == 366
    weekday = (absolute_start(year) - 367) % 7 or 7
    flags = weekday + (0 if leap else 8)
    encoded = (year % 2**19) * 8192 + ordinal * 16 + flags
    return (encoded, entry_rax), (year, ordinal)


def fixture_bytes():
    cases = set()
    def add(day, entry=0, high=0):
        cases.add(((day % 2**32) + (high % 2**32) * 2**32, entry % WORD))
    # Every normalized day exactly once, alternating nonnegative and negative cycles.
    for residue in range(146097):
        day = residue - 365 - (146097 if residue % 2 else 0)
        add(day, (residue * 0x9e3779b97f4a7c15) % WORD)
    years = set(range(-401, 402)) | {MIN_YEAR - 1, MIN_YEAR, MIN_YEAR + 1,
            MAX_YEAR - 1, MAX_YEAR, MAX_YEAR + 1, -10000, 10000}
    for year in years:
        first = absolute_start(year) - 365
        length = absolute_start(year + 1) - absolute_start(year)
        for ordinal in (0, 1, 2, 59, 60, 61, length - 1, length, length + 1):
            add(first + ordinal - 1, WORD - 1)
    for center in (-2**31, 2**31 - 366, 2**31 - 365, 2**31 - 1, MIN_DAY, MAX_DAY, -365, 0):
        for delta in range(-8, 9):
            day = max(-2**31, min(2**31 - 1, center + delta))
            for entry in (0, WORD - 1, 2**63, 0x0123456789abcdef):
                for high in (0, 1, 0xffffffff, 0x80000000):add(day, entry, high)
    for bit in range(64):
        for day in (-366, -365, -1, 0, 1, MIN_DAY, MAX_DAY, 2**31 - 1):
            add(day, 2**bit, 0xdeadbeef)
            add(day, WORD - 1 - 2**bit, 0x12345678)
    rng = random.Random(START)
    for _ in range(4096):cases.add((rng.getrandbits(64), rng.getrandbits(64)))
    inputs, outputs = [], []
    coverage = {'cases': len(cases), 'nonzero_results': 0, 'zero_results': 0,
                'initial_add_overflow': 0, 'negative_year_results': 0,
                'upper_input_bits_set': 0, 'preserved_rax_nonzero': 0,
                'normalized_day_classes': 146097, 'random_seed': hex(START)}
    for raw, entry in sorted(cases):
        result, date = relation(raw, entry)
        inputs.append(f'{raw:016x}\t{entry:016x}')
        outputs.append(','.join(f'{v:016x}' for v in result))
        bits = raw % 2**32;day = bits if bits < 2**31 else bits - 2**32
        coverage['nonzero_results'] += result[0] != 0
        coverage['zero_results'] += result[0] == 0
        coverage['initial_add_overflow'] += day > 2**31 - 1 - 365
        coverage['negative_year_results'] += date is not None and date[0] < 0
        coverage['upper_input_bits_set'] += raw >= 2**32
        coverage['preserved_rax_nonzero'] += entry != 0
    return ('\n'.join(inputs) + '\n').encode(), ('\n'.join(outputs) + '\n').encode(), coverage


def freeze():
    require(not (ROOT / 'src/node94-calendar-constructor').exists(), 'Rust already exists')
    folder = PACKET / 'frozen'
    require(not (folder / 'ORACLE-FREEZE.json').exists(), 'Freeze already exists')
    require(absolute_start(MIN_YEAR) - 365 == MIN_DAY and absolute_start(MAX_YEAR + 1) - 366 == MAX_DAY, 'Exact admitted endpoints changed')
    facts, proof = admit(), certificates()
    inputs, output, coverage = fixture_bytes()
    for name, raw in (('inputs.tsv', inputs), ('expected.txt', output)):
        (folder / (name + '.gz')).write_bytes(gzip.compress(raw, mtime=0))
    record = {'frozen_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'source_base_commit': '56c0ec672bd8fdcfaa80f2db700a61e6240b3663',
              'rust_source_present': False, 'oracle_source_sha256': digest(__file__),
              'inputs_sha256': hashlib.sha256(inputs).hexdigest(),
              'expected_sha256': hashlib.sha256(output).hexdigest(), 'coverage': coverage,
              'certificates': proof, 'static_facts': facts}
    (folder / 'ORACLE-FREEZE.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps({'oracle_source_sha256': record['oracle_source_sha256'], 'coverage': coverage, 'certificates': proof}, indent=2))


if __name__ == '__main__':
    freeze()
