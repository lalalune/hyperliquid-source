"""Pre-Rust 400-year calendar partition oracle; static target reads only."""
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
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, __version__ as capstone_version

TARGET = ROOT / 'artifacts/node/94/hl-node'
TARGET_SHA = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
START, END = 0x151f870, 0x151fa9c
LOCK_SHA = '9efbea5a459d97a8e52acf907647046aa592089291989cf6aeec6cd93e710309'
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
        if section['name'].startswith('.rela.'):
            require(section['size'] % 24 == 0, 'Malformed RELA extent')
            for index in range(0, section['size'], 24):
                va = section['address'] + index
                address, info, addend = struct.unpack('<QQq', read(va, 24))
                require(address not in rels, 'Duplicate relocation address')
                rels[address] = dict(record_va=va, info=info, addend=addend)
                count += 1
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
        sites = {i.address: i for i in decoded}
        if start == START:
            require(end == END, 'Callee end changed')
            for i in decoded:
                if i.mnemonic.startswith('j'):
                    require(START <= int(i.op_str, 16) < END, 'Branch escapes selected body')
            calls = {0x151fa55: 0x576e150, 0x151fa62: 0x576e150,
                     0x151fa74: 0x576dfc8, 0x151fa89: 0x576dfc8, 0x151fa96: 0x576e118}
            require({i.address for i in decoded if i.mnemonic == 'call'} == set(calls), 'Call set changed')
            for site, slot in calls.items():
                insn = sites[site]
                require(insn.bytes[:2] == b'\xff\x15' and site + 6 + struct.unpack_from('<i', insn.bytes, 2)[0] == slot,
                        'Panic call slot changed')
            for site, target in ((0x151f8e3, 0x250354), (0x151fa09, 0x2504e5),
                                 (0x151fa4e, 0x5672188), (0x151fa5b, 0x5672140),
                                 (0x151fa68, 0x56721a0), (0x151fa7a, 0x5672158), (0x151fa8f, 0x5672170)):
                insn = sites[site]
                require(insn.mnemonic == 'lea' and site + 7 + struct.unpack_from('<i', insn.bytes, 3)[0] == target,
                        'RIP-relative data edge changed')
        else:
            for site in item['sites']:
                insn = sites[site]
                require(insn.mnemonic == 'call', 'Caller site is not an instruction')
                target = site + len(insn.bytes) + struct.unpack_from('<i', insn.bytes, len(insn.bytes) - 4)[0]
                require(target == (START if insn.bytes[0] == 0xe8 else 0x576e8b0), 'Caller destination changed')
        bodies.append({**item, 'instructions': rows})
    require(read(END, 4) == b'\xcc' * 4, 'Callee padding changed')
    text = next(s for s in secs if s['name'] == '.text')
    code, candidates = read(text['address'], text['size']), []
    for opcode in (b'\xe8', b'\xff\x15', b'\xff\x25'):
        pos = 0
        while (pos := code.find(opcode, pos)) >= 0:
            length = len(opcode) + 4
            if pos + length <= len(code):
                target = text['address'] + pos + length + struct.unpack_from('<i', code, pos + len(opcode))[0]
                if target == (START if opcode == b'\xe8' else 0x576e8b0):
                    candidates.append(text['address'] + pos)
            pos += 1
    require([hex(x) for x in sorted(candidates)] == contract['incoming_sites'], 'Incoming pattern scan changed')
    return {'target_sha256': TARGET_SHA, 'bodies': bodies, 'data': contract['data'],
            'relocations': contract['relocations'], 'naming_slots': naming,
            'incoming_pattern_candidates': contract['incoming_sites'], 'complete_xref_census': False,
            'qualified_incoming_sites': [hex(a) for b in bodies[1:] for a in b['sites']],
            'relocation_records': count, 'text_scan_bytes': len(code), 'capstone_version': capstone_version,
            'static_lock_sha256': LOCK_SHA,
            'prior_evidence_sha256': digest(ROOT / 'research/work-items/foundation-days-to-date-94/evidence.json')}


def certificates():
    """Finite arithmetic lemmas over normalized residues; no instruction execution."""
    reciprocal = []
    for divisor, shift, multiplier, bound in ((400, 39, 0x51eb851f, 262144),
                                               (146097, 47, 0x396b06bd, 2**31)):
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


def pack(year, ordinal, flags=None):
    return ((year % 2**19) << 13) | (ordinal << 4) | (FLAGS[year % 400] if flags is None else flags)


def expected(raw, delta):
    year = raw >> 13
    if year >= 2**18:
        year -= 2**19
    ordinal = (raw >> 4) & 511
    if not (MIN_YEAR <= year <= MAX_YEAR and 1 <= ordinal <= YEAR_DAYS[year % 400]
            and raw & 15 == FLAGS[year % 400]):
        return 'invalid'
    cycle, residue = divmod(year, 400)
    serial = cycle * 146097 + PREFIX[residue] + ordinal - 1 + delta
    out_cycle, day = divmod(serial, 146097)
    out_residue = bisect.bisect_right(PREFIX, day) - 1
    out_year = out_cycle * 400 + out_residue
    value = 0 if not MIN_YEAR <= out_year <= MAX_YEAR else pack(out_year, day - PREFIX[out_residue] + 1)
    return f'ok:{value:08x}'


def fixture_bytes():
    cases = set()
    for day in range(146097):
        cases.add((pack(0, 1), day))
    years = set(range(-401, 402)) | {MIN_YEAR, MIN_YEAR + 1, MAX_YEAR - 1, MAX_YEAR,
                                   -10000, -1900, -1600, 1600, 1900, 2000, 2100, 2400, 10000}
    deltas = (-2**31, -2**31 + 1, -146098, -146097, -146096, -367, -366, -365,
              -2, -1, 0, 1, 2, 365, 366, 367, 146096, 146097, 146098, 2**31 - 2, 2**31 - 1)
    for year in sorted(years):
        for ordinal in {1, 2, 59, 60, 61, YEAR_DAYS[year % 400] - 1, YEAR_DAYS[year % 400]}:
            raw = pack(year, ordinal)
            for delta in deltas:
                cases.add((raw, delta))
            for destination in (MIN_YEAR, MAX_YEAR):
                for end in (1, YEAR_DAYS[destination % 400]):
                    source_cycle, source_residue = divmod(year, 400)
                    out_cycle, out_residue = divmod(destination, 400)
                    distance = ((out_cycle - source_cycle) * 146097 + PREFIX[out_residue]
                                - PREFIX[source_residue] + end - ordinal)
                    for offset in (-1, 0, 1):
                        cases.add((raw, distance + offset))
    for year in (-262144, MIN_YEAR, -400, -100, -1, 0, 1, 100, 400, MAX_YEAR, 262143):
        for ordinal in (0, 1, 2, 365, 366, 367, 511):
            for flag in range(16):
                for delta in (-2**31, -1, 0, 1, 2**31 - 1):
                    cases.add((pack(year, ordinal, flag), delta))
    rng = random.Random(START)
    for _ in range(4096):
        year = rng.randint(MIN_YEAR, MAX_YEAR)
        cases.add((pack(year, rng.randint(1, YEAR_DAYS[year % 400])), rng.randint(-2**31, 2**31 - 1)))
        cases.add((rng.randrange(2**32), rng.randint(-2**31, 2**31 - 1)))
    inputs, outputs = [], []
    coverage = {'cases': len(cases), 'admitted_zero': 0, 'admitted_packed': 0,
                'invalid_representation': 0, 'random_seed': hex(START), 'entire_cycle_destination_days': 146097}
    for raw, delta in sorted(cases):
        result = expected(raw, delta)
        inputs.append(f'{raw:08x}\t{delta}')
        outputs.append(result)
        key = 'invalid_representation' if result == 'invalid' else 'admitted_zero' if result == 'ok:00000000' else 'admitted_packed'
        coverage[key] += 1
    return ('\n'.join(inputs) + '\n').encode(), ('\n'.join(outputs) + '\n').encode(), coverage


def freeze():
    require(not (ROOT / 'src/node94-packed-date-add').exists(), 'Rust already exists')
    folder = PACKET / 'frozen'
    require(not (folder / 'ORACLE-FREEZE.json').exists(), 'Freeze already exists')
    facts = admit()
    proof = certificates()
    inputs, output, coverage = fixture_bytes()
    for name, raw in (('inputs.tsv', inputs), ('expected.txt', output)):
        (folder / (name + '.gz')).write_bytes(gzip.compress(raw, mtime=0))
    record = {'frozen_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'source_base_commit': '56c0ec672bd8fdcfaa80f2db700a61e6240b3663',
              'rust_source_present': False, 'oracle_source_sha256': digest(__file__),
              'inputs_sha256': hashlib.sha256(inputs).hexdigest(),
              'expected_sha256': hashlib.sha256(output).hexdigest(), 'coverage': coverage,
              'static_facts': facts, 'arithmetic_certificates': proof}
    (folder / 'ORACLE-FREEZE.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps({'oracle_source_sha256': record['oracle_source_sha256'], 'coverage': coverage,
                      'arithmetic_certificates': proof}, indent=2))


if __name__ == '__main__':
    freeze()
