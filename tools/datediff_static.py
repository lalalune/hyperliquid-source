#!/usr/bin/env python3
"""Authenticated node94 chrono-style date difference core binding (0x151d1b0).

Binds the difference core behind the shared "Time Sub" helper to the node #94
digest: its FDE-bounded body, the 400-entry Gregorian leap-day table
(validated entry-by-entry against an independent model), the packed-date
decomposition (year << 13 | ordinal << 4), the era constants (400-cycle,
146097 days, 365, 86400, 1e9 with its magic divisor), the year-0 panic routed
to a chrono-0.4.38 source Location, and the three-caller census. Static
byte/record checks only; the captured binary is never executed.
"""
import argparse
import bisect
import hashlib
import json
import struct
from pathlib import Path
from elf_index import sections

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

START, END = 0x151d1b0, 0x151d33f
FDE_VA = 0xcf630c
TABLE_VA = 0x250354
TABLE_LEN = 400
LOC_VA = 0x5672188
CHRONO_PATH = (b'/home/ubuntu/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/'
               b'chrono-0.4.38/src/naive/date/mod.rs')
PANIC_FN = 0x157b520
GOT_PANIC, GOT_SELF = 0x576e150, 0x576eaa0
CALLERS = [0x13cfdc1, 0x1447166, 0x1450a61]

BODY = bytes.fromhex(
    '554156538b0f89c8c1f80d48984c69c01f85eb514c89c248c1ea3f49c1f82741'
    '01d04169d09001000029d04189c141c1f91f4489ca81e29001000001c24469da'
    '6d010000c1e90481e1ff010000488d055031d3fe440fb614024101ca4501da0f'
    '841d0100008b0e89cac1fa0d4c63da4969d31f85eb514889d348c1eb3f48c1fa'
    '2701da69d2900100004489db29d389dac1fa1f81e29001000001da69ea6d0100'
    '00c1e90481e1ff01000001e90fb62c0201cd0f84ca000000448b77048b4f0848'
    '81f900ca9a3b0f93c08b7e048b56084139fe400f92c64020c6400fb6c648f7d8'
    '4881fa00ca9a3bbe01000000480f42f04139fe480f46f04829d148bab394d626'
    'e80b2e114889c848f7ea4889d048c1e83f48c1fa1a4801d04869d000ca9a3b48'
    '29d14889ca48c1fa3f4801f04801d081e200ca9a3b01ca4969cbe17a14ae4889'
    'ce48c1ee3f48c1f92701f14101c84501c1c1eb1f4401cb4863cb4489d64189e8'
    '4869c9b13a02004801f14c29c14869c9805101004c01f14829f94801c85b415e'
    '5dc3488d3d4f4e1504ff15110e2504')

FDE = bytes.fromhex(
    '2c000000f84d01009c6e82008f01000000410e10420e18410e2083048e038602'
    '037a010e18420e10410e08410e200000')

# Immediate constants that must appear in the body (offset, little-endian).
IMMEDIATES = [
    (0x10, '1f85eb51', 'signed div-400 magic (operand A)'),
    (0x25, '90010000', '400 (operand A)'),
    (0x40, '6d010000', '365 (operand A)'),
    (0x49, 'ff010000', '511 mask (operand A)'),
    (0x72, '1f85eb51', 'signed div-400 magic (operand B)'),
    (0x95, '90010000', '400 (operand B)'),
    (0x9d, '6d010000', '365 (operand B)'),
    (0xa6, 'ff010000', '511 mask (operand B)'),
    (0xc2, '00ca9a3b', '1e9 nanos-per-second'),
    (0xfc, 'b394d626e80b2e11', 'signed div-1e9 magic'),
    (0x11b, '00ca9a3b', '1e9 (remainder normalization)'),
    (0x131, '00ca9a3b', '1e9 (imul quotient)'),
    (0x13a, 'e17a14ae', 'negated div-400 magic'),
    (0x163, 'b13a0200', '146097 days per 400-year cycle'),
    (0x170, '80510100', '86400 seconds per day'),
]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def leap_table_model():
    """Cumulative leap days before cycle year i, proleptic Gregorian."""
    table = []
    total = 0
    for year in range(TABLE_LEN):
        table.append(total)
        if year % 4 == 0 and (year % 100 != 0 or year % 400 == 0):
            total += 1
    return table


class Reader:
    def __init__(self, data):
        self.data = data
        self.sections = sections(data)
        self.by_name = {s['name']: s for s in self.sections}

    def read(self, va, size):
        matches = [s for s in self.sections if s['type'] != 8
                   and s['address'] <= va and va + size <= s['address'] + s['size']]
        require(len(matches) == 1, f'Ambiguous or unmapped VA {va:#x}')
        s = matches[0]
        off = s['offset'] + va - s['address']
        return self.data[off:off + size]


def relocations(reader):
    raw = reader.read(reader.by_name['.rela.dyn']['address'],
                      reader.by_name['.rela.dyn']['size'])
    rels = {}
    for off in range(0, len(raw), 24):
        address, info, addend = struct.unpack_from('<QQq', raw, off)
        if info == 8:
            require(address not in rels, 'Duplicate relative relocation')
            rels[address] = addend
    return rels


def analyze(data):
    reader = Reader(data)
    body = reader.read(START, END - START)
    require(body == BODY, 'Difference core body bytes changed')
    require(len(body) == 0x18f, 'FDE extent length changed')

    eh = reader.by_name['.eh_frame']
    require(eh['address'] <= FDE_VA < eh['address'] + eh['size'], 'FDE outside .eh_frame')
    record = reader.read(FDE_VA, len(FDE))
    require(record == FDE, 'Difference core FDE record changed')
    length = struct.unpack_from('<I', record, 0)[0]
    pc = FDE_VA + 8 + struct.unpack_from('<i', record, 8)[0]
    extent = struct.unpack_from('<I', record, 12)[0]
    require(length == len(FDE) - 4, 'FDE length changed')
    require((pc, pc + extent) == (START, END), 'FDE PC range changed')

    for offset, hexstr, label in IMMEDIATES:
        raw = bytes.fromhex(hexstr)
        require(body[offset:offset + len(raw)] == raw, f'Immediate changed: {label}')

    for offset, pattern, rel_pos, insn_len, destination in [
            (0x5f, '0f841d010000', 2, 6, 0x151d332),
            (0xb2, '0f84ca000000', 2, 6, 0x151d332)]:
        raw = bytes.fromhex(pattern)
        require(body[offset:offset + len(raw)] == raw,
                f'Panic branch changed at +{offset:#x}')
        rel = struct.unpack_from('<i', body, offset + rel_pos)[0]
        require(START + offset + insn_len + rel == destination, 'Panic branch destination changed')

    table = reader.read(TABLE_VA, TABLE_LEN)
    require(list(table) == leap_table_model(), 'Leap table no longer matches the Gregorian model')
    off = 0x151d1fd - START
    require(body[off:off + 3] == b'\x48\x8d\x05', 'Leap table lea changed')
    disp = struct.unpack_from('<i', body, off + 3)[0]
    require(0x151d204 + disp == TABLE_VA, 'Leap table address changed')

    rels = relocations(reader)
    require(rels.get(LOC_VA) is not None, 'Panic Location relocation missing')
    loc_path_va = rels[LOC_VA]
    length_, line, column = struct.unpack('<QII', reader.read(LOC_VA + 8, 16))
    require((length_, line, column) == (len(CHRONO_PATH), 2334, 5),
            'Panic Location layout changed')
    require(reader.read(loc_path_va, length_) == CHRONO_PATH, 'chrono path changed')
    require(rels.get(GOT_PANIC) == PANIC_FN, 'Panic callee GOT slot changed')
    require(rels.get(GOT_SELF) == START, 'Self GOT slot changed')

    off = 0x151d332 - START
    require(body[off:off + 3] == b'\x48\x8d\x3d', 'Panic message lea changed')
    disp = struct.unpack_from('<i', body, off + 3)[0]
    require(0x151d339 + disp == LOC_VA, 'Panic Location address changed')

    # Call census over the whole .text.
    text = reader.by_name['.text']
    code = reader.read(text['address'], text['size'])
    pos, indirect, direct = 0, [], []
    while (pos := code.find(b'\xff\x15', pos)) >= 0:
        if pos + 6 <= len(code):
            got = text['address'] + pos + 6 + struct.unpack_from('<i', code, pos + 2)[0]
            if got == GOT_SELF:
                indirect.append(text['address'] + pos)
        pos += 2
    pos = 0
    while (pos := code.find(b'\xe8', pos)) >= 0:
        if pos + 5 <= len(code):
            destination = text['address'] + pos + 5 + struct.unpack_from('<i', code, pos + 1)[0]
            if destination == START:
                direct.append(text['address'] + pos)
        pos += 1
    require(indirect == CALLERS, f'GOT-indirect caller census changed: {[hex(x) for x in indirect]}')
    require(direct == [], 'Unexpected direct references')

    # Day-count identity: within-cycle days = 365*rem + table[rem] + ord0
    # with year = x >>a 13, rem = year mod 400 (euclidean) and the stored
    # ord0 = (x >> 4) & 511 behaving as a zero-based day offset under
    # astronomical year numbering (cycle year 0 = 1 BC, a leap year).
    # Validated as day differences against Python's proleptic Gregorian
    # calendar, an independent oracle, for years >= 1 (AD).
    import datetime
    base = datetime.date(1, 1, 1).toordinal()  # python_day(1, 0) reference
    for year in (1, 2, 3, 4, 5, 100, 399, 400, 401, 1970, 2000, 2026, 2400):
        for ord0 in (0, 59, 99, 199, 364, 365):
            try:
                calendar_day = datetime.date(year, 1, 1).toordinal() + ord0
            except ValueError:
                continue  # ord0 365 needs a leap year; the stored field has no such check
            q, r = divmod(year, 400)
            if r < 0:
                q, r = q - 1, r + 400
            binary_day = 146097 * q + 365 * r + leap_table_model()[r] + ord0
            require(binary_day - (365 + leap_table_model()[1]) == calendar_day - base,
                    f'Day-count identity failed for year {year} ord0 {ord0}')

    return dict(
        target_release='94', target_sha256=SHA256,
        coordinate_system='ELF virtual addresses, no runtime rebase',
        core=dict(start_va=hex(START), end_va_exclusive=hex(END), bytes=len(body),
                  sha256=hashlib.sha256(body).hexdigest(), fde_va=hex(FDE_VA),
                  inferred_label='chrono NaiveDate-style signed difference core'),
        leap_table=dict(va=hex(TABLE_VA), entries=TABLE_LEN,
                        model='cumulative proleptic-Gregorian leap days per 400-year cycle',
                        validated_entries=TABLE_LEN,
                        source='chrono-0.4.38 naive/date/mod.rs table'),
        packed_date=dict(observed='year = dword >>a 13; ordinal = (dword >> 4) & 511',
                         days_formula='146097*floor_div(year,400) + 365*r + table[r] + ordinal, r = year mod 400',
                         invalid_check='sum == 0 (year 0, ordinal 0) branches to panic'),
        panic=dict(location_va=hex(LOC_VA), path='chrono-0.4.38/src/naive/date/mod.rs',
                   line=2334, column=5, callee=hex(PANIC_FN), sites=['0x151d20f', '0x151d262']),
        era_constants=dict(cycle_days=146097, days_per_year=365, secs_per_day=86400,
                           nanos_per_second=1000000000, div400_magic='0x51eb851f',
                           div1e9_magic='0x112e0be826d694b3'),
        result_model='returns (i64 total seconds in rax, i32 nanosecond remainder in edx '
                     'normalized to [0, 1e9)); tail borrow cmovs recorded structurally',
        call_census=dict(got_slot=hex(GOT_SELF), got_indirect=[hex(x) for x in CALLERS],
                         direct_e8=0,
                         known_consumers=['0x1447166 (shared Time Sub helper, separate packet)',
                                          '0x13cfdc1', '0x1450a61']),
        captured_binary_executed=False, progress_gate_requested=False)


def inspect(path):
    data = Path(path).read_bytes()
    require(len(data) == 91774280 and hashlib.sha256(data).hexdigest() == SHA256,
            'Expected exact node #94 size/SHA-256')
    return analyze(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=TARGET)
    parser.add_argument('--check', type=Path, help='Compare with retained JSON; fail on drift')
    parser.add_argument('--output', type=Path, help='Write the record JSON to this path')
    args = parser.parse_args()
    result = inspect(args.binary)
    text = json.dumps(result, indent=2, sort_keys=True) + '\n'
    if args.check is not None:
        expected = args.check.read_text()
        require(text == expected, 'Retained evidence record drifted')
        print('Record matches retained evidence.')
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text)
    else:
        print(text)


if __name__ == '__main__':
    main()
